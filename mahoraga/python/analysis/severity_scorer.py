class SeverityScorer:
    ATTACK_BASE_SCORES = {
        'ransomware':           10,
        'rootkit':              9,
        'c2_beacon':            8,
        'data_exfil':           8,
        'worm':                 7,
        'backdoor':             7,
        'privilege_escalation': 7,
        'keylogger':            6,
        'cryptominer':          4,
    }

    def score(self, telemetry: dict, anomaly_score: float) -> int:
        attack_type = telemetry.get('attack_type', '')
        base = self.ATTACK_BASE_SCORES.get(attack_type, 3)
        boost = round(anomaly_score * 2)
        hint = telemetry.get('severity_hint', 0)
        return min(10, max(base, hint, base + boost))
