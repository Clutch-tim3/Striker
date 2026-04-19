class ZeroDayHeuristics:
    SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 31337, 12345}

    def check(self, telemetry: dict) -> bool:
        return any([
            self._check_process_injection(telemetry),
            self._check_suspicious_network(telemetry),
            self._check_ransomware_behaviour(telemetry),
            self._check_privilege_escalation(telemetry),
            self._check_living_off_land(telemetry),
        ])

    def _check_process_injection(self, t: dict) -> bool:
        name = (t.get('name') or '').lower()
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        return (
            'explorer.exe' in name and t.get('connections', 0) > 5
        ) or any(x in cmdline for x in [
            'virtualalloc', 'writeprocessmemory', 'createremotethread',
            '-encodedcommand', '-windowstyle hidden', 'bypass',
        ])

    def _check_suspicious_network(self, t: dict) -> bool:
        if t.get('source') != 'network':
            return False
        return (
            t.get('dest_port', 0) in self.SUSPICIOUS_PORTS or
            (t.get('packet_size', 0) < 100 and t.get('frequency', 0) > 10)
        )

    def _check_ransomware_behaviour(self, t: dict) -> bool:
        return t.get('event') in {
            'mass_file_modification', 'ransomware_extension_detected'
        } or t.get('attack_hint') == 'ransomware'

    def _check_privilege_escalation(self, t: dict) -> bool:
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        return any(x in cmdline for x in [
            'whoami /priv', 'net localgroup administrators',
            'sudo su', 'sudo -s', 'runas /user:administrator',
            'seimpersonateprivilege', 'token impersonat',
        ])

    def _check_living_off_land(self, t: dict) -> bool:
        name = (t.get('name') or '').lower()
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        lolbins = {'certutil', 'bitsadmin', 'regsvr32', 'mshta', 'wmic'}
        return name in lolbins and any(x in cmdline for x in [
            'http', 'download', 'urlcache', 'transfer',
        ])
