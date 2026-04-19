class AttackClassifier:
    """
    Combines sensor hints and heuristic signals to determine attack type.
    Falls back to 'unknown' if insufficient signal.
    """

    SIGNAL_MAP = {
        'ransomware_extension_detected': 'ransomware',
        'mass_file_modification':        'ransomware',
        'beacon_pattern':                'c2_beacon',
        'suspicious_port_connection':    'c2_beacon',
        'high_risk_process':             'privilege_escalation',
        'wx_memory_region':              'rootkit',
    }

    def classify(self, telemetry: dict) -> str:
        # Direct hint from sensor
        hint = telemetry.get('attack_hint')
        if hint:
            return hint

        # Event-based signal
        event = telemetry.get('event', '')
        if event in self.SIGNAL_MAP:
            return self.SIGNAL_MAP[event]

        # Resource spike from unknown process → cryptominer candidate
        if (telemetry.get('event') == 'resource_spike' and
                telemetry.get('cpu', 0) > 90):
            return 'cryptominer'

        # Network exfil pattern: large outbound to unusual port
        if (telemetry.get('source') == 'network' and
                telemetry.get('packet_size', 0) > 50000):
            return 'data_exfil'

        return 'unknown'
