import os
import time
import platform
import threading
from python.core.logger import get_logger

logger = get_logger('file_watcher')

OS = platform.system()

SENSITIVE_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png',
    '.psd', '.sql', '.db', '.wallet', '.key', '.pem', '.env',
    '.ssh', '.kdbx', '.p12', '.pfx', '.ppk',
}

RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypt', '.enc', '.ransom',
    '.wncry', '.locky', '.cerber', '.zepto', '.ryuk',
}


def _get_watch_paths():
    home = os.path.expanduser('~')
    if OS == 'Windows':
        userprofile = os.environ.get('USERPROFILE', 'C:\\Users\\Default')
        appdata = os.environ.get('APPDATA', os.path.join(userprofile, 'AppData', 'Roaming'))
        localappdata = os.environ.get('LOCALAPPDATA', os.path.join(userprofile, 'AppData', 'Local'))
        return [p for p in [
            os.path.join(userprofile, 'Documents'),
            os.path.join(userprofile, 'Desktop'),
            'C:\\Windows\\System32\\Tasks',           # scheduled task persistence
            'C:\\Windows\\SysWOW64',
            os.path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(localappdata, 'Temp'),        # payload drop zone
            'C:\\ProgramData',
        ] if p]
    elif OS == 'Darwin':
        return [p for p in [
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Desktop'),
            os.path.join(home, 'Library', 'LaunchAgents'),   # user persistence
            '/Library/LaunchAgents',                          # system persistence
            '/Library/LaunchDaemons',
            '/tmp',                                           # payload staging
            '/var/tmp',
            os.path.join(home, '.ssh'),                       # key theft
            '/Applications',
        ] if os.path.exists(p)]
    else:  # Linux
        return [p for p in [
            os.path.join(home, 'Documents'),
            '/tmp',                          # payload staging
            '/var/tmp',
            '/etc/cron.d',                   # cron persistence
            '/etc/cron.daily',
            '/etc/cron.weekly',
            '/etc/init.d',                   # SysV init persistence
            '/etc/systemd/system',           # systemd persistence
            '/usr/local/bin',                # binary replacement
            os.path.join(home, '.ssh'),      # key theft
            os.path.join(home, '.bashrc'),   # shell persistence (file itself)
            os.path.join(home, '.profile'),
        ] if os.path.exists(p)]


def _check_persistence_path(path):
    """Return an attack hint if the file path is a known persistence location."""
    pl = path.lower().replace('\\', '/')
    if OS == 'Darwin':
        if 'launchagents' in pl or 'launchdaemons' in pl:
            return 'backdoor'
    elif OS == 'Windows':
        if 'startup' in pl or 'tasks' in pl:
            return 'backdoor'
    elif OS == 'Linux':
        if any(x in pl for x in ['/cron.d/', '/cron.daily/', '/init.d/', '/systemd/system/']):
            return 'backdoor'
        if pl.endswith('.bashrc') or pl.endswith('.profile'):
            return 'backdoor'
    return None


class FileWatcher:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.observer = None
        self.running = False

    def start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            cb = self.on_telemetry

            class Handler(FileSystemEventHandler):
                def __init__(self):
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
                    self._persistence_check(event.src_path, 'file_created')

                def on_deleted(self, event):
                    self._emit('file_deleted', event.src_path)

                def on_moved(self, event):
                    self._emit('file_moved', event.src_path, dest=event.dest_path)
                    dest_ext = os.path.splitext(event.dest_path)[1].lower()
                    if dest_ext in RANSOMWARE_EXTENSIONS:
                        cb({
                            'source': 'file', 'event': 'ransomware_extension_detected',
                            'src': event.src_path, 'dest': event.dest_path,
                            'severity_hint': 9, 'attack_hint': 'ransomware',
                            'platform': OS,
                        })

                def _emit(self, event_type, path, dest=None):
                    ext = os.path.splitext(path)[1].lower()
                    cb({
                        'source': 'file', 'event': event_type,
                        'file_path': path, 'extension': ext,
                        'is_sensitive': ext in SENSITIVE_EXTENSIONS,
                        'dest': dest, 'platform': OS,
                    })

                def _persistence_check(self, path, event_type):
                    hint = _check_persistence_path(path)
                    if hint:
                        cb({
                            'source': 'file', 'event': 'persistence_file_drop',
                            'file_path': path, 'attack_hint': hint,
                            'severity_hint': 8, 'platform': OS,
                        })

                def _ransomware_check(self, path):
                    ext = os.path.splitext(path)[1].lower()
                    if ext not in SENSITIVE_EXTENSIONS:
                        return
                    now = time.time()
                    self.recent_mods.append(now)
                    self.recent_mods = [t for t in self.recent_mods if now - t < 10]
                    if len(self.recent_mods) > 20:
                        cb({
                            'source': 'file', 'event': 'mass_file_modification',
                            'count': len(self.recent_mods),
                            'severity_hint': 10, 'attack_hint': 'ransomware',
                            'platform': OS,
                        })

            self.observer = Observer()
            handler = Handler()
            for path in _get_watch_paths():
                try:
                    is_dir = os.path.isdir(path)
                    self.observer.schedule(handler, path if is_dir else os.path.dirname(path), recursive=is_dir)
                except Exception:
                    pass
            self.observer.start()
            self.running = True
            logger.info(f'File watcher started (platform={OS})')
        except ImportError:
            logger.warning('watchdog not installed — file watcher disabled')
        except Exception as e:
            logger.error(f'File watcher start error: {e}')

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.running = False
