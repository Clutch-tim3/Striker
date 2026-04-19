class AttackClassifier:
    """
    Combines sensor hints and heuristic signals to determine attack type.
    Falls back to 'unknown' if insufficient signal.
    """

    SIGNAL_MAP = {
        # File events
        'ransomware_extension_detected': 'ransomware',
        'mass_file_modification':        'ransomware',
        'persistence_file_drop':         'backdoor',
        # Network events
        'beacon_pattern':                'c2_beacon',
        'suspicious_port_connection':    'c2_beacon',
        # Process events (Windows)
        'powershell_encoded':            'backdoor',
        'powershell_hidden':             'backdoor',
        'shadow_copy_deletion':          'ransomware',
        'lolbin_download':               'backdoor',
        'credential_dump_tool':          'privilege_escalation',
        # Process events (macOS)
        'gatekeeper_bypass':             'rootkit',
        'persistence_mechanism':         'backdoor',
        'applescript_execution':         'keylogger',
        'download_execute':              'backdoor',
        'keychain_access':               'keylogger',
        # Process events (Linux)
        'kernel_module_load':            'rootkit',
        'ld_preload_injection':          'rootkit',
        'reverse_shell':                 'c2_beacon',
        'cron_modification':             'backdoor',
        # Memory
        'wx_memory_region':              'rootkit',
    }

    def classify(self, telemetry: dict) -> str:
        # Direct hint from sensor (highest priority)
        hint = telemetry.get('attack_hint')
        if hint:
            return hint

        # Event-based signal
        event = telemetry.get('event', '')
        if event in self.SIGNAL_MAP:
            return self.SIGNAL_MAP[event]

        # high_risk_process needs name-based sub-classification
        if event == 'high_risk_process':
            name = (telemetry.get('name') or '').lower().rstrip('.exe')
            cmdline = ' '.join(telemetry.get('cmdline') or []).lower()
            if name in {'mimikatz', 'wce', 'procdump'}:
                return 'privilege_escalation'
            if name in {'powershell', 'pwsh'} and any(x in cmdline for x in ['-enc', '-encodedcommand']):
                return 'backdoor'
            if name in {'nc', 'ncat', 'netcat', 'socat'}:
                return 'c2_beacon'
            if name in {'insmod', 'modprobe'}:
                return 'rootkit'
            if name in {'crontab', 'launchctl', 'systemctl'}:
                return 'backdoor'
            return 'privilege_escalation'

        # Resource spike from unknown process → cryptominer candidate
        if event == 'resource_spike' and telemetry.get('cpu', 0) > 90:
            return 'cryptominer'

        # Network exfil pattern: large outbound to unusual port
        if telemetry.get('source') == 'network' and telemetry.get('packet_size', 0) > 50000:
            return 'data_exfil'

        return 'unknown'
