"""
Mahoraga Python backend entry point.
Spawned as a subprocess by Electron main.js.
Communicates via stdin/stdout JSON lines.
"""

import sys
import os
import threading
import time
import uuid

# Ensure project root is on path when run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from python.core.ipc_server import IPCServer, set_server, emit
from python.core.config import Config
from python.core.logger import get_logger
from python.sensor.process_monitor import ProcessMonitor
from python.sensor.network_sniffer import NetworkSniffer
from python.sensor.file_watcher import FileWatcher
from python.detection.anomaly_detector import AnomalyDetector
from python.detection.behaviour_classifier import BehaviourClassifier
from python.detection.zero_day_heuristics import ZeroDayHeuristics
from python.analysis.attack_classifier import AttackClassifier
from python.analysis.mitre_tagger import MITRETagger
from python.analysis.severity_scorer import SeverityScorer
from python.response.process_killer import ProcessKiller
from python.response.quarantine import Quarantine
from python.response.network_isolator import NetworkIsolator
from python.archive.db import Database
from python.demo.threat_simulator import ThreatSimulator
from python.archive.antibody import AntibodyStore
from python.archive.vector_index import VectorIndex
from python.adaptation.scheduler import AdaptationScheduler
from python.analysis.insight_generator import generate as generate_insights

logger = get_logger('main')


class CommandRouter:
    def __init__(self, app):
        self.app = app

    def route(self, command: str, payload: dict):
        handlers = {
            'START_MONITORING': self.app.start_monitoring,
            'STOP_MONITORING':  self.app.stop_monitoring,
            'GET_ARCHIVE':      self.app.get_archive,
            'QUARANTINE':       self.app.quarantine_file,
            'KILL_PROCESS':     self.app.kill_process,
            'ISOLATE_NETWORK':  self.app.isolate_network,
            'GET_CONFIG':       self.app.get_config,
            'SET_CONFIG':       self.app.set_config,
            'ACTIVATE_LICENSE': self.app.activate_license,
        }
        handler = handlers.get(command)
        if handler:
            threading.Thread(target=handler, args=(payload,), daemon=True).start()
        else:
            logger.warning(f'Unknown command: {command}')


class MahoragaApp:
    def __init__(self):
        self.config = Config.load()
        self.db = Database()
        self.antibody_store = AntibodyStore(self.db)
        self.vector_index = VectorIndex()

        self.process_monitor = ProcessMonitor(self.on_telemetry)
        self.network_sniffer = NetworkSniffer(self.on_telemetry)
        self.file_watcher = FileWatcher(self.on_telemetry)

        self.anomaly_detector = AnomalyDetector()
        self.behaviour_classifier = BehaviourClassifier()
        self.heuristics = ZeroDayHeuristics()

        self.attack_classifier = AttackClassifier()
        self.mitre_tagger = MITRETagger()
        self.severity_scorer = SeverityScorer()

        self.process_killer = ProcessKiller()
        self.quarantine = Quarantine()
        self.network_isolator = NetworkIsolator()

        self.adaptation_scheduler = AdaptationScheduler(
            self.antibody_store, self.anomaly_detector, self.behaviour_classifier
        )
        self.demo_simulator = ThreatSimulator(self.on_telemetry)

        # Pre-fit anomaly detector with synthetic baseline so scores are meaningful
        self._seed_anomaly_model()

    def _seed_anomaly_model(self):
        """Fit isolation forest with synthetic normal baseline so it can score."""
        import numpy as np
        rng = np.random.default_rng(42)
        # 200 samples of "normal" behaviour
        normal = rng.uniform(0, 1, (200, 8))
        normal[:, 0] *= 20    # cpu  0-20%
        normal[:, 1] *= 10    # mem  0-10%
        normal[:, 2] *= 5     # conn 0-5
        normal[:, 3:] = rng.integers(0, 2, (200, 5))
        try:
            self.anomaly_detector.model.fit(normal)
            logger.info('Anomaly model seeded with synthetic baseline')
        except Exception as e:
            logger.warning(f'Anomaly model seed failed: {e}')

    def start_monitoring(self, payload=None):
        self.process_monitor.start()
        self.network_sniffer.start()
        self.file_watcher.start()
        self.adaptation_scheduler.start()
        self.demo_simulator.start()
        threading.Thread(target=self._sensor_watchdog, daemon=True).start()
        emit('MONITORING_STARTED', {'status': 'active', 'demo': True})
        logger.info('All sensors started (demo mode active)')

    def stop_monitoring(self, payload=None):
        self.process_monitor.stop()
        self.network_sniffer.stop()
        self.file_watcher.stop()
        self.demo_simulator.stop()
        self._monitoring = False
        emit('MONITORING_STOPPED', {'status': 'inactive'})

    def _sensor_watchdog(self):
        """Restart any sensor that dies silently. Runs for the lifetime of the process."""
        self._monitoring = True
        own_pid = os.getpid()
        while self._monitoring:
            time.sleep(10)
            try:
                # Restart dead sensors
                if not self.process_monitor.running:
                    logger.warning('ProcessMonitor died — restarting')
                    self.process_monitor.start()
                if not self.file_watcher.running:
                    logger.warning('FileWatcher died — restarting')
                    self.file_watcher.start()

                # Self-protection: detect if our own process is being targeted
                import psutil
                try:
                    own = psutil.Process(own_pid)
                    for child in psutil.process_iter(['pid', 'name', 'ppid']):
                        try:
                            if (child.info['ppid'] != own_pid and
                                    child.info['name'] and
                                    'mahoraga' in child.info['name'].lower()):
                                self.on_telemetry({
                                    'source': 'process', 'event': 'suspicious_ancestry',
                                    'pid': child.info['pid'], 'name': child.info['name'],
                                    'attack_hint': 'rootkit', 'severity_hint': 9,
                                    'detail': 'Process impersonating Mahoraga detected',
                                })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except Exception:
                    pass
            except Exception as e:
                logger.error(f'Watchdog error: {e}')

    def on_telemetry(self, telemetry: dict):
        if not self.config.get('anomaly_enabled', True):
            return

        # ── LAYER 2: DETECT ────────────────────────────────────────────
        anomaly_score = self.anomaly_detector.score(telemetry) if self.config.get('anomaly_enabled', True) else 0.0
        behaviour_hit = self.behaviour_classifier.classify(telemetry) if self.config.get('behaviour_enabled', True) else None
        heuristic_hit = self.heuristics.check(telemetry) if self.config.get('heuristics_enabled', True) else False

        # Vector similarity catch — known pattern = guaranteed detection
        similar = self.vector_index.find_similar(telemetry, top_k=1)
        similarity_hit = bool(similar)

        threshold = self.config.get('anomaly_threshold', 0.75)

        # Guaranteed floor — any sensor that explicitly flagged a high-severity
        # event or attack hint CANNOT be filtered out by the ML threshold.
        sensor_flagged = (
            telemetry.get('severity_hint', 0) >= 7 or
            bool(telemetry.get('attack_hint')) or
            bool(telemetry.get('event') in {
                'gatekeeper_bypass', 'persistence_mechanism', 'keychain_access',
                'download_execute', 'powershell_encoded', 'powershell_hidden',
                'shadow_copy_deletion', 'lolbin_download', 'credential_dump_tool',
                'kernel_module_load', 'ld_preload_injection', 'reverse_shell',
                'cron_modification', 'applescript_execution', 'persistence_file_drop',
                'ransomware_extension_detected', 'mass_file_modification',
                'high_entropy_write', 'suspicious_ancestry',
            })
        )

        is_threat = (
            anomaly_score > threshold or
            bool(behaviour_hit) or
            heuristic_hit or
            similarity_hit or
            sensor_flagged
        )
        if not is_threat:
            return

        # ── LAYER 3: ANALYSE ───────────────────────────────────────────
        attack_type = behaviour_hit or self.attack_classifier.classify(telemetry)
        mitre_id = self.mitre_tagger.tag(telemetry, attack_type)
        telemetry['attack_type'] = attack_type
        severity = self.severity_scorer.score(telemetry, anomaly_score)

        threat = {
            'threat_id':     str(uuid.uuid4()),
            'telemetry':     telemetry,
            'anomaly_score': anomaly_score,
            'attack_type':   attack_type,
            'mitre_id':      mitre_id,
            'severity':      severity,
            'similar_past':  similar,
        }

        emit('THREAT_DETECTED', threat)

        # ── LAYER 4: RESPOND ───────────────────────────────────────────
        response_taken = self.auto_respond(threat)

        # ── LAYER 5: ARCHIVE ───────────────────────────────────────────
        antibody = self.antibody_store.create(threat, response_taken)
        self.vector_index.add(antibody)

        # ── LAYER 6: INSIGHT ───────────────────────────────────────────
        insights = generate_insights(threat, antibody, response_taken)
        self.antibody_store.update_insights(antibody['id'], insights)

        emit('THREAT_NEUTRALISED', {
            'antibody_id': antibody['id'],
            'threat_id':   threat['threat_id'],
            'response':    response_taken,
            'severity':    severity,
            'insights':    insights,
            'threat_ref':  threat,
        })

    def auto_respond(self, threat: dict) -> list:
        severity = threat['severity']
        telemetry = threat['telemetry']
        threshold = self.config.get('auto_kill_threshold', 8)
        actions = []

        if severity >= threshold:
            if pid := telemetry.get('pid'):
                if self.process_killer.kill(int(pid)):
                    actions.append('PROCESS_KILLED')
            if self.config.get('auto_quarantine', True):
                if path := telemetry.get('file_path'):
                    if self.quarantine.quarantine(path):
                        actions.append('FILE_QUARANTINED')

        if (self.config.get('auto_isolate', False) and
                severity >= 6 and
                threat['attack_type'] in ('ransomware', 'c2_beacon', 'data_exfil')):
            if self.network_isolator.isolate():
                actions.append('NETWORK_ISOLATED')

        return actions

    def quarantine_file(self, payload: dict):
        if path := payload.get('path'):
            self.quarantine.quarantine(path)

    def kill_process(self, payload: dict):
        if pid := payload.get('pid'):
            self.process_killer.kill(int(pid))

    def isolate_network(self, payload=None):
        self.network_isolator.isolate()

    def get_archive(self, payload: dict):
        filters = payload or {}
        antibodies = self.antibody_store.query(filters)
        emit('ARCHIVE_DATA', {'antibodies': antibodies})

    def get_config(self, payload=None):
        emit('CONFIG_DATA', self.config.to_dict())

    def set_config(self, payload: dict):
        self.config.update(payload)
        self.config.save()

    def activate_license(self, payload: dict):
        key = payload.get('key', '')
        # Validate against Clive license server
        # POST https://clive.dev/api/subscriptions/validate { apiKey: key }
        valid = key.startswith('clive_') and len(key) > 20
        if valid:
            self.config.update({'tier': 'pro', 'license_key': key})
            self.config.save()
        emit('LICENSE_RESULT', {'valid': valid, 'tier': 'pro' if valid else 'free'})


if __name__ == '__main__':
    app = MahoragaApp()
    router = CommandRouter(app)
    server = IPCServer(router)
    set_server(server)
    server.start()
    app.start_monitoring()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        app.stop_monitoring()
        logger.info('Mahoraga shutdown')
