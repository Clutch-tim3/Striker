TECHNIQUE_MAP = {
    'ransomware':           ('T1486', 'Data Encrypted for Impact'),
    'keylogger':            ('T1056', 'Input Capture'),
    'rootkit':              ('T1014', 'Rootkit'),
    'c2_beacon':            ('T1071', 'Application Layer Protocol'),
    'data_exfil':           ('T1041', 'Exfiltration Over C2 Channel'),
    'cryptominer':          ('T1496', 'Resource Hijacking'),
    'worm':                 ('T1210', 'Exploitation of Remote Services'),
    'backdoor':             ('T1543', 'Create or Modify System Process'),
    'privilege_escalation': ('T1068', 'Exploitation for Privilege Escalation'),
}

class MITRETagger:
    def tag(self, telemetry: dict, attack_type: str) -> dict:
        if attack_type in TECHNIQUE_MAP:
            tid, name = TECHNIQUE_MAP[attack_type]
            return {
                'technique_id':   tid,
                'technique_name': name,
                'url': f'https://attack.mitre.org/techniques/{tid}/',
            }
        return {'technique_id': 'T0000', 'technique_name': 'Unknown', 'url': ''}
