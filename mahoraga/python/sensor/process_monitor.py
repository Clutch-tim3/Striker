import psutil
import threading
import time
import platform
from python.core.logger import get_logger

logger = get_logger('process_monitor')

OS = platform.system()  # 'Darwin', 'Windows', 'Linux'

# Windows high-risk process names
WINDOWS_HIGH_RISK = {
    'cmd.exe', 'powershell.exe', 'powershell_ise.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
    'schtasks.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe',
    'msiexec.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe',
    'cmstp.exe', 'msbuild.exe', 'msconfig.exe', 'at.exe',
}

# macOS high-risk process names / patterns
MACOS_HIGH_RISK = {
    'osascript',      # AppleScript — used for UI spoofing, persistence, keylogging
    'xattr',          # Strip Gatekeeper quarantine attributes
    'launchctl',      # Load/unload launch agents (persistence)
    'defaults',       # Modify plist settings for persistence
    'ditto',          # Archive/copy — used to exfil or unpack payloads
    'spctl',          # Disable Gatekeeper
    'system_profiler', # Reconnaissance
    'screencapture',  # Surveillance
    'security',       # Keychain access
}

# Linux high-risk process names / patterns
LINUX_HIGH_RISK = {
    'nc', 'ncat', 'netcat',  # Reverse shells
    'nmap',                   # Reconnaissance
    'masscan',                # Fast port scanner
    'socat',                  # Advanced netcat
    'base64',                 # Often used to decode payloads
    'xxd',                    # Hex encode/decode payloads
    'insmod', 'modprobe',     # Kernel module loading (rootkit install)
    'iptables', 'ufw',        # Firewall manipulation
    'crontab',                # Cron persistence
    'systemctl',              # Systemd service creation/manipulation
    'useradd', 'adduser',     # Backdoor account creation
    'passwd',                 # Credential change
    'chattr',                 # Make files immutable (hide persistence)
    'at',                     # Job scheduler for persistence
}

HIGH_RISK = WINDOWS_HIGH_RISK | MACOS_HIGH_RISK | LINUX_HIGH_RISK


class ProcessMonitor:
    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False
        self.known_pids = set()
        self._suspicious_counts = {}   # pid -> spike_count (avoid spam)

    def start(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        logger.info(f'Process monitor started (platform={OS})')

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        while self.running:
            try:
                current_pids = set()
                for proc in psutil.process_iter([
                    'pid', 'name', 'exe', 'cmdline',
                    'cpu_percent', 'memory_percent',
                    'status', 'ppid', 'username',
                ]):
                    try:
                        info = proc.info
                        pid = info['pid']
                        current_pids.add(pid)
                        name = (info.get('name') or '').lower()
                        cmdline = info.get('cmdline') or []
                        cmdline_str = ' '.join(cmdline).lower()

                        # ── New process appeared ────────────────────────────
                        if pid not in self.known_pids:
                            self.known_pids.add(pid)
                            self.on_telemetry({
                                'source':   'process',
                                'event':    'new_process',
                                'pid':      pid,
                                'name':     info.get('name'),
                                'exe':      info.get('exe'),
                                'cmdline':  cmdline,
                                'ppid':     info.get('ppid'),
                                'cpu':      info.get('cpu_percent', 0) or 0,
                                'memory':   info.get('memory_percent', 0) or 0,
                                'username': info.get('username'),
                                'connections': 0,
                                'platform': OS,
                            })

                        # ── Resource spike ───────────────────────────────────
                        cpu = info.get('cpu_percent', 0) or 0
                        mem = info.get('memory_percent', 0) or 0
                        if cpu > 80 or mem > 50:
                            count = self._suspicious_counts.get(pid, 0)
                            if count < 3:  # Limit alerts per process
                                self._suspicious_counts[pid] = count + 1
                                self.on_telemetry({
                                    'source':  'process',
                                    'event':   'resource_spike',
                                    'pid':     pid,
                                    'name':    info.get('name'),
                                    'cpu':     cpu,
                                    'memory':  mem,
                                    'platform': OS,
                                })

                        # ── High-risk process name ───────────────────────────
                        if name in HIGH_RISK or name.rstrip('.exe') in HIGH_RISK:
                            self.on_telemetry({
                                'source':   'process',
                                'event':    'high_risk_process',
                                'pid':      pid,
                                'name':     info.get('name'),
                                'cmdline':  cmdline,
                                'platform': OS,
                            })

                        # ── Platform-specific checks ─────────────────────────
                        if OS == 'Darwin':
                            self._check_macos(pid, name, cmdline_str, cmdline, info)
                        elif OS == 'Windows':
                            self._check_windows(pid, name, cmdline_str, cmdline, info)
                        elif OS == 'Linux':
                            self._check_linux(pid, name, cmdline_str, cmdline, info)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                self.known_pids -= (self.known_pids - current_pids)
                # Clean up spike counts for dead processes
                for pid in list(self._suspicious_counts):
                    if pid not in current_pids:
                        del self._suspicious_counts[pid]

            except Exception as e:
                logger.error(f'Process monitor loop error: {e}')

            time.sleep(2)

    def _check_macos(self, pid, name, cmdline_str, cmdline, info):
        # Gatekeeper bypass via xattr
        if name == 'xattr' and '-d' in cmdline_str and 'quarantine' in cmdline_str:
            self.on_telemetry({
                'source': 'process', 'event': 'gatekeeper_bypass',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'rootkit', 'severity_hint': 8, 'platform': OS,
            })

        # Launch agent persistence via launchctl
        if name == 'launchctl' and ('load' in cmdline_str or 'bootstrap' in cmdline_str):
            # Suspicious if loading from user writable locations
            if any(p in cmdline_str for p in ['/tmp/', '/var/folders/', '~/library/launchagents']):
                self.on_telemetry({
                    'source': 'process', 'event': 'persistence_mechanism',
                    'pid': pid, 'name': name, 'cmdline': cmdline,
                    'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': OS,
                })

        # osascript — AppleScript execution (UI spoofing, keylogging)
        if name == 'osascript':
            self.on_telemetry({
                'source': 'process', 'event': 'applescript_execution',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'severity_hint': 6, 'platform': OS,
            })

        # Curl/wget piped to shell — download and execute
        if name in ('curl', 'wget') and any(x in cmdline_str for x in ['-o /tmp', '| sh', '| bash', '| python']):
            self.on_telemetry({
                'source': 'process', 'event': 'download_execute',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': OS,
            })

        # Keychain access via 'security' binary
        if name == 'security' and any(x in cmdline_str for x in ['find-generic-password', 'find-internet-password', 'dump-keychain']):
            self.on_telemetry({
                'source': 'process', 'event': 'keychain_access',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'keylogger', 'severity_hint': 9, 'platform': OS,
            })

    def _check_windows(self, pid, name, cmdline_str, cmdline, info):
        # PowerShell encoded command
        if name in ('powershell.exe', 'pwsh.exe'):
            if any(x in cmdline_str for x in ['-encodedcommand', '-enc ', '-e ']):
                self.on_telemetry({
                    'source': 'process', 'event': 'powershell_encoded',
                    'pid': pid, 'name': name, 'cmdline': cmdline,
                    'attack_hint': 'backdoor', 'severity_hint': 8, 'platform': OS,
                })
            if '-windowstyle hidden' in cmdline_str or '-nop' in cmdline_str:
                self.on_telemetry({
                    'source': 'process', 'event': 'powershell_hidden',
                    'pid': pid, 'name': name, 'cmdline': cmdline,
                    'severity_hint': 7, 'platform': OS,
                })

        # LSASS access — credential dumping
        if name in ('procdump.exe', 'mimikatz.exe', 'wce.exe'):
            self.on_telemetry({
                'source': 'process', 'event': 'credential_dump_tool',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'privilege_escalation', 'severity_hint': 10, 'platform': OS,
            })

        # Shadow copy deletion — ransomware signature
        if 'vssadmin' in cmdline_str and ('delete' in cmdline_str or 'shadows' in cmdline_str):
            self.on_telemetry({
                'source': 'process', 'event': 'shadow_copy_deletion',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'ransomware', 'severity_hint': 10, 'platform': OS,
            })

        # Certutil downloading payload
        if name == 'certutil.exe' and any(x in cmdline_str for x in ['urlcache', '-f ', 'http']):
            self.on_telemetry({
                'source': 'process', 'event': 'lolbin_download',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'backdoor', 'severity_hint': 8, 'platform': OS,
            })

    def _check_linux(self, pid, name, cmdline_str, cmdline, info):
        # Download and execute
        if name in ('curl', 'wget') and any(x in cmdline_str for x in ['| sh', '| bash', '| python', '-o /tmp']):
            self.on_telemetry({
                'source': 'process', 'event': 'download_execute',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'backdoor', 'severity_hint': 9, 'platform': OS,
            })

        # Kernel module loading — rootkit install
        if name in ('insmod', 'modprobe') and cmdline:
            self.on_telemetry({
                'source': 'process', 'event': 'kernel_module_load',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'rootkit', 'severity_hint': 9, 'platform': OS,
            })

        # LD_PRELOAD injection
        env = {}
        try:
            env = psutil.Process(pid).environ()
        except Exception:
            pass
        if 'LD_PRELOAD' in env:
            self.on_telemetry({
                'source': 'process', 'event': 'ld_preload_injection',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'rootkit', 'severity_hint': 10, 'platform': OS,
            })

        # Reverse shell via bash -i or nc
        if name in ('bash', 'sh', 'dash') and any(x in cmdline_str for x in ['-i >& /dev/tcp', '/dev/tcp/', 'exec /bin/sh']):
            self.on_telemetry({
                'source': 'process', 'event': 'reverse_shell',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'c2_beacon', 'severity_hint': 10, 'platform': OS,
            })

        # Cron persistence
        if name == 'crontab' and '-e' in cmdline_str:
            self.on_telemetry({
                'source': 'process', 'event': 'cron_modification',
                'pid': pid, 'name': name, 'cmdline': cmdline,
                'attack_hint': 'backdoor', 'severity_hint': 7, 'platform': OS,
            })
