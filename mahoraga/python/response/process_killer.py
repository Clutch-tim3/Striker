import signal
import os
from python.core.logger import get_logger

logger = get_logger('process_killer')

# PIDs we must never kill
PROTECTED_PIDS = {1, os.getpid()}


class ProcessKiller:
    def kill(self, pid: int) -> bool:
        if pid in PROTECTED_PIDS:
            logger.warning(f'Refused to kill protected PID {pid}')
            return False
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            logger.info(f'Killed process PID {pid}')
            return True
        except Exception as e:
            logger.error(f'Failed to kill PID {pid}: {e}')
            return False
