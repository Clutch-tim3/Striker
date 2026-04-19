import psutil
import threading
import time
from python.core.logger import get_logger

logger = get_logger('process_monitor')

HIGH_RISK_PROCESS_NAMES = {
    'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'schtasks.exe',
}

class ProcessMonitor:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False
        self.known_pids = set()

    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        logger.info('Process monitor started')

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        while self.running:
            try:
                current_pids = set()
                for proc in psutil.process_iter([
                    'pid', 'name', 'exe', 'cmdline',
                    'cpu_percent', 'memory_percent',
                    'status', 'ppid'
                ]):
                    try:
                        info = proc.info
                        pid = info['pid']
                        current_pids.add(pid)

                        if pid not in self.known_pids:
                            self.known_pids.add(pid)
                            self.on_telemetry({
                                'source':  'process',
                                'event':   'new_process',
                                'pid':     pid,
                                'name':    info.get('name'),
                                'exe':     info.get('exe'),
                                'cmdline': info.get('cmdline'),
                                'ppid':    info.get('ppid'),
                                'cpu':     info.get('cpu_percent', 0),
                                'memory':  info.get('memory_percent', 0),
                                'connections': 0,
                            })

                        cpu = info.get('cpu_percent', 0) or 0
                        mem = info.get('memory_percent', 0) or 0
                        if cpu > 80 or mem > 50:
                            self.on_telemetry({
                                'source': 'process',
                                'event':  'resource_spike',
                                'pid':    pid,
                                'name':   info.get('name'),
                                'cpu':    cpu,
                                'memory': mem,
                            })

                        if (info.get('name') or '').lower() in HIGH_RISK_PROCESS_NAMES:
                            self.on_telemetry({
                                'source':  'process',
                                'event':   'high_risk_process',
                                'pid':     pid,
                                'name':    info.get('name'),
                                'cmdline': info.get('cmdline'),
                            })

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                self.known_pids -= (self.known_pids - current_pids)

            except Exception as e:
                logger.error(f'Process monitor loop error: {e}')

            time.sleep(2)
