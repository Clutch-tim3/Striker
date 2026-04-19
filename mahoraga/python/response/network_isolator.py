import subprocess
import platform
import threading
import time
from python.core.logger import get_logger

logger = get_logger('network_isolator')


class NetworkIsolator:
    def __init__(self):
        self._isolated = False
        self._auto_restore_timer = None

    def isolate(self, auto_restore_seconds: int = 300) -> bool:
        if self._isolated:
            return True
        try:
            system = platform.system()
            if system == 'Darwin':
                self._isolate_macos()
            elif system == 'Windows':
                self._isolate_windows()
            else:
                self._isolate_linux()

            self._isolated = True
            logger.warning(f'Network ISOLATED — auto-restore in {auto_restore_seconds}s')

            # Auto-restore after timeout so user isn't left offline permanently
            self._auto_restore_timer = threading.Timer(
                auto_restore_seconds, self.restore
            )
            self._auto_restore_timer.daemon = True
            self._auto_restore_timer.start()
            return True
        except Exception as e:
            logger.error(f'Network isolation failed: {e}')
            return False

    def restore(self) -> bool:
        if not self._isolated:
            return True
        try:
            system = platform.system()
            if system == 'Darwin':
                self._restore_macos()
            elif system == 'Windows':
                self._restore_windows()
            else:
                self._restore_linux()

            self._isolated = False
            if self._auto_restore_timer:
                self._auto_restore_timer.cancel()
            logger.info('Network restored')
            return True
        except Exception as e:
            logger.error(f'Network restore failed: {e}')
            return False

    def _isolate_macos(self):
        # Block all outbound traffic via pf — requires sudo
        pf_rules = 'block drop all\n'
        subprocess.run(['sudo', 'pfctl', '-ef', '-'], input=pf_rules.encode(),
                       capture_output=True, check=True)

    def _restore_macos(self):
        subprocess.run(['sudo', 'pfctl', '-d'], capture_output=True)

    def _isolate_windows(self):
        subprocess.run([
            'netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy',
            'blockinbound,blockoutbound'
        ], check=True)

    def _restore_windows(self):
        subprocess.run([
            'netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy',
            'blockinbound,allowoutbound'
        ])

    def _isolate_linux(self):
        subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'DROP'], check=True)

    def _restore_linux(self):
        subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'])
        subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'])
        subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'])
