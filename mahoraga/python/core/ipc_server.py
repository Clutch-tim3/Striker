import sys
import json
import threading
from python.core.logger import get_logger

logger = get_logger('ipc_server')

class IPCServer:
    def __init__(self, command_router):
        self.router = command_router
        self.running = False

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._read_loop, daemon=True)
        thread.start()
        logger.info('IPC server started')

    def _read_loop(self):
        while self.running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                msg = json.loads(line.strip())
                self._handle(msg)
            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.error(f'IPC read error: {e}')

    def _handle(self, msg):
        command = msg.get('command')
        payload = msg.get('payload', {})
        try:
            self.router.route(command, payload)
        except Exception as e:
            self.emit('ERROR', {'command': command, 'error': str(e)})

    def emit(self, event_type: str, data: dict):
        msg = json.dumps({'type': event_type, 'data': data})
        sys.stdout.write(msg + '\n')
        sys.stdout.flush()

_server: IPCServer = None

def set_server(server: IPCServer):
    global _server
    _server = server

def emit(event_type: str, data: dict):
    if _server:
        _server.emit(event_type, data)
