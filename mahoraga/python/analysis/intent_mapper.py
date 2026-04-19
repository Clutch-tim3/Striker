INTENT_MAP = {
    'ransomware':           'Encrypt victim files and demand ransom payment',
    'keylogger':            'Capture keystrokes to steal credentials',
    'rootkit':              'Persist with elevated privileges, hide from OS',
    'c2_beacon':            'Maintain command-and-control channel with attacker',
    'data_exfil':           'Exfiltrate sensitive data to attacker-controlled server',
    'cryptominer':          'Hijack CPU/GPU resources for cryptocurrency mining',
    'worm':                 'Self-propagate to other hosts on the network',
    'backdoor':             'Maintain persistent remote access to the system',
    'privilege_escalation': 'Gain administrator or SYSTEM privileges',
}

class IntentMapper:
    def map(self, attack_type: str) -> str:
        return INTENT_MAP.get(attack_type, 'Intent unknown — further analysis required')
