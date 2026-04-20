import os
import psutil
from python.core.logger import get_logger

logger = get_logger('process_killer')

PROTECTED_PIDS = {1, os.getpid()}


class ProcessKiller:
    def kill(self, pid: int) -> bool:
        if pid in PROTECTED_PIDS:
            logger.warning(f'Refused to kill protected PID {pid}')
            return False
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            logger.info(f'Process {pid} terminated')
            return True
        except psutil.NoSuchProcess:
            logger.warning(f'Process {pid} already gone')
            return False
        except psutil.AccessDenied:
            logger.warning(f'Access denied killing pid {pid}')
            return False
        except Exception as e:
            logger.error(f'Kill pid {pid} failed: {e}')
            return False
