import os
import time
import threading
from python.core.logger import get_logger

logger = get_logger('file_watcher')

SENSITIVE_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png',
    '.psd', '.sql', '.db', '.wallet', '.key', '.pem', '.env',
}

RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypt', '.enc', '.ransom',
    '.wncry', '.locky', '.cerber', '.zepto',
}

def _get_watch_paths():
    import platform
    system = platform.system()
    home = os.path.expanduser('~')
    if system == 'Windows':
        return [
            os.path.join(os.environ.get('USERPROFILE', 'C:\\Users'), 'Documents'),
            os.path.join(os.environ.get('USERPROFILE', 'C:\\Users'), 'Desktop'),
            'C:\\Windows\\System32',
        ]
    elif system == 'Darwin':
        return [
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Desktop'),
            '/Applications',
        ]
    else:
        return [
            os.path.join(home, 'Documents'),
            '/etc',
            '/usr/bin',
        ]


class FileWatcher:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.observer = None
        self.running = False

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            class Handler(FileSystemEventHandler):
                def __init__(self, cb):
                    self.cb = cb
                    self.recent_mods = []

                def on_modified(self, event):
                    if event.is_directory:
                        return
                    self._emit('file_modified', event.src_path)
                    self._ransomware_check(event.src_path)

                def on_created(self, event):
                    if event.is_directory:
                        return
                    self._emit('file_created', event.src_path)

                def on_deleted(self, event):
                    self._emit('file_deleted', event.src_path)

                def on_moved(self, event):
                    self._emit('file_moved', event.src_path, dest=event.dest_path)
                    dest_ext = os.path.splitext(event.dest_path)[1].lower()
                    if dest_ext in RANSOMWARE_EXTENSIONS:
                        self.cb({
                            'source': 'file', 'event': 'ransomware_extension_detected',
                            'src': event.src_path, 'dest': event.dest_path,
                            'severity_hint': 9, 'attack_hint': 'ransomware',
                        })

                def _emit(self, event_type, path, dest=None):
                    ext = os.path.splitext(path)[1].lower()
                    self.cb({
                        'source': 'file', 'event': event_type,
                        'file_path': path, 'extension': ext,
                        'is_sensitive': ext in SENSITIVE_EXTENSIONS,
                        'dest': dest,
                    })

                def _ransomware_check(self, path):
                    ext = os.path.splitext(path)[1].lower()
                    if ext not in SENSITIVE_EXTENSIONS:
                        return
                    now = time.time()
                    self.recent_mods.append(now)
                    self.recent_mods = [t for t in self.recent_mods if now - t < 10]
                    if len(self.recent_mods) > 20:
                        self.cb({
                            'source': 'file', 'event': 'mass_file_modification',
                            'count': len(self.recent_mods),
                            'severity_hint': 10, 'attack_hint': 'ransomware',
                        })

            self.observer = Observer()
            handler = Handler(self.on_telemetry)
            for path in _get_watch_paths():
                try:
                    if os.path.exists(path):
                        self.observer.schedule(handler, path, recursive=True)
                except Exception:
                    pass
            self.observer.start()
            self.running = True
            logger.info('File watcher started')
        except ImportError:
            logger.warning('watchdog not installed — file watcher disabled')
        except Exception as e:
            logger.error(f'File watcher start error: {e}')

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.running = False
