import os
import platform
import subprocess
import threading
from python.core.logger import get_logger

logger = get_logger('network_isolator')

# Set MAHORAGA_REAL_ISOLATION=1 to enable actual firewall rules.
# Default is log-only — safe for desktop use.
REAL_ISOLATION = os.environ.get('MAHORAGA_REAL_ISOLATION', '0') == '1'


class NetworkIsolator:
    def __init__(self):
        self._isolated = False

    def isolate(self, auto_restore_seconds: int = 300) -> bool:
        if self._isolated:
            return True
        if not REAL_ISOLATION:
            self._isolated = True
            logger.warning('Network isolation triggered (log-only mode — set MAHORAGA_REAL_ISOLATION=1 for real blocking)')
            return True
        try:
            system = platform.system()
            if system == 'Darwin':
                pf_rules = 'block drop all\n'
                subprocess.run(['sudo', 'pfctl', '-ef', '-'], input=pf_rules.encode(),
                               capture_output=True, check=True)
            elif system == 'Windows':
                subprocess.run([
                    'netsh', 'advfirewall', 'set', 'allprofiles',
                    'firewallpolicy', 'blockinbound,blockoutbound'
                ], check=True)
            else:
                subprocess.run(['sudo', 'iptables', '-P', 'INPUT',   'DROP'], check=True)
                subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT',  'DROP'], check=True)
                subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'DROP'], check=True)

            self._isolated = True
            logger.warning(f'Network ISOLATED — auto-restore in {auto_restore_seconds}s')
            t = threading.Timer(auto_restore_seconds, self.restore)
            t.daemon = True
            t.start()
            return True
        except Exception as e:
            logger.error(f'Network isolation failed: {e}')
            return False

    def restore(self) -> bool:
        if not self._isolated:
            return True
        if REAL_ISOLATION:
            try:
                system = platform.system()
                if system == 'Darwin':
                    subprocess.run(['sudo', 'pfctl', '-d'], capture_output=True)
                elif system == 'Windows':
                    subprocess.run([
                        'netsh', 'advfirewall', 'set', 'allprofiles',
                        'firewallpolicy', 'blockinbound,allowoutbound'
                    ])
                else:
                    subprocess.run(['sudo', 'iptables', '-P', 'INPUT',   'ACCEPT'])
                    subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT',  'ACCEPT'])
                    subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'])
            except Exception as e:
                logger.error(f'Network restore failed: {e}')
                return False
        self._isolated = False
        logger.info('Network isolation lifted')
        return True
