import platform

OS = platform.system()


class ZeroDayHeuristics:
    SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 31337, 12345, 9001, 8888}

    def check(self, telemetry: dict) -> bool:
        return any([
            self._check_process_injection(telemetry),
            self._check_suspicious_network(telemetry),
            self._check_ransomware_behaviour(telemetry),
            self._check_privilege_escalation(telemetry),
            self._check_living_off_land(telemetry),
            self._check_persistence(telemetry),
            self._check_macos(telemetry),
            self._check_linux(telemetry),
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
            # macOS
            'sudo bash', 'sudo sh', 'sudo python',
            # Linux
            'pkexec', '/etc/sudoers', 'chmod +s', 'chown root',
        ])

    def _check_living_off_land(self, t: dict) -> bool:
        name = (t.get('name') or '').lower()
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        # Windows LOLBins
        win_lolbins = {'certutil', 'bitsadmin', 'regsvr32', 'mshta', 'wmic', 'rundll32'}
        if name.rstrip('.exe') in win_lolbins and any(x in cmdline for x in [
            'http', 'download', 'urlcache', 'transfer',
        ]):
            return True
        # macOS LOLBins
        if name in {'osascript', 'xattr', 'launchctl'} and any(x in cmdline for x in [
            'quarantine', 'load', 'bootstrap',
        ]):
            return True
        # Linux: base64-decode-pipe-to-shell pattern
        if name == 'base64' or (name in {'sh', 'bash'} and 'base64' in cmdline):
            return True
        return False

    def _check_persistence(self, t: dict) -> bool:
        event = t.get('event', '')
        return event in {
            'persistence_file_drop', 'persistence_mechanism',
            'gatekeeper_bypass', 'cron_modification',
        }

    def _check_macos(self, t: dict) -> bool:
        if OS != 'Darwin':
            return False
        event = t.get('event', '')
        name = (t.get('name') or '').lower()
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        # AppleScript abuse
        if name == 'osascript':
            return True
        # Keychain dump
        if event == 'keychain_access':
            return True
        # Download and execute
        if event == 'download_execute':
            return True
        # plist tampering for persistence
        if name == 'defaults' and any(x in cmdline for x in ['write', 'launchagent', 'loginitems']):
            return True
        return False

    def _check_linux(self, t: dict) -> bool:
        if OS != 'Linux':
            return False
        event = t.get('event', '')
        name = (t.get('name') or '').lower()
        # Reverse shell signatures
        if event == 'reverse_shell':
            return True
        # LD_PRELOAD injection
        if event == 'ld_preload_injection':
            return True
        # Kernel module (rootkit install)
        if event == 'kernel_module_load':
            return True
        # socat/nc with exec flags → reverse shell
        cmdline = ' '.join(t.get('cmdline') or []).lower()
        if name in {'nc', 'ncat', 'netcat', 'socat'} and any(x in cmdline for x in [
            'exec', '/bin/sh', '/bin/bash', '-e',
        ]):
            return True
        return False
