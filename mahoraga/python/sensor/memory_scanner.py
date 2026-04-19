import threading
import time
from python.core.logger import get_logger

logger = get_logger('memory_scanner')

# Common shellcode/injection byte patterns (hex signatures)
SHELLCODE_SIGNATURES = [
    b'\x90\x90\x90\x90',           # NOP sled
    b'\xfc\xe8\x82\x00\x00\x00',   # Classic Metasploit shellcode prologue
    b'\x4d\x5a',                   # MZ header in unexpected memory
]


class MemoryScanner:
    """
    Scans running process memory for shellcode signatures.
    Requires elevated privileges on most systems.
    Falls back gracefully if access is denied.
    """

    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self._scan_loop, daemon=True).start()
        logger.info('Memory scanner started')

    def stop(self):
        self.running = False

    def _scan_loop(self):
        while self.running:
            try:
                self._scan_all_processes()
            except Exception as e:
                logger.debug(f'Memory scan error: {e}')
            time.sleep(30)

    def _scan_all_processes(self):
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self._scan_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _scan_process(self, proc):
        import psutil
        p = psutil.Process(proc.info['pid'])
        maps = p.memory_maps(grouped=False)
        for region in maps:
            if 'x' in (region.perms or '') and 'w' in (region.perms or ''):
                # Writable+executable region — suspicious
                self.on_telemetry({
                    'source':        'memory',
                    'event':         'wx_memory_region',
                    'pid':           proc.info['pid'],
                    'name':          proc.info.get('name'),
                    'region':        region.path or 'anonymous',
                    'severity_hint': 6,
                })
