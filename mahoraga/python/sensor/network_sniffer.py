import threading
import time
from python.core.logger import get_logger

logger = get_logger('network_sniffer')

SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 31337, 12345, 9001, 8888}
BEACON_INTERVAL_THRESHOLD = 5   # seconds between repeat connections = beacon candidate


class NetworkSniffer:
    """
    Passive network telemetry via psutil connections.
    Scapy deep-packet capture is available but requires root/admin;
    psutil provides enough metadata for anomaly detection without privileges.
    """

    def __init__(self, on_telemetry):
        self.on_telemetry = on_telemetry
        self.running = False
        self.seen_connections = {}   # (laddr, raddr) -> last_seen timestamp
        self.beacon_candidates = {}  # raddr -> list of timestamps

    def start(self):
        self.running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
        logger.info('Network sniffer started (psutil mode)')

    def stop(self):
        self.running = False

    def _poll_loop(self):
        import psutil
        while self.running:
            try:
                try:
                    connections = psutil.net_connections(kind='inet')
                except (psutil.AccessDenied, PermissionError):
                    time.sleep(10)
                    continue
                now = time.time()
                for conn in connections:
                    if conn.status != 'ESTABLISHED':
                        continue
                    if not conn.raddr:
                        continue

                    rip = conn.raddr.ip
                    rport = conn.raddr.port
                    key = (str(conn.laddr), str(conn.raddr))

                    is_new = key not in self.seen_connections
                    self.seen_connections[key] = now

                    if is_new:
                        self.on_telemetry({
                            'source':    'network',
                            'event':     'new_connection',
                            'pid':       conn.pid,
                            'dest_ip':   rip,
                            'dest_port': rport,
                            'src_port':  conn.laddr.port if conn.laddr else 0,
                            'packet_size': 0,
                        })

                    if rport in SUSPICIOUS_PORTS:
                        self.on_telemetry({
                            'source':        'network',
                            'event':         'suspicious_port_connection',
                            'dest_ip':       rip,
                            'dest_port':     rport,
                            'pid':           conn.pid,
                            'severity_hint': 7,
                        })

                    # Beacon detection: repeated connections to same host
                    self.beacon_candidates.setdefault(rip, [])
                    self.beacon_candidates[rip].append(now)
                    self.beacon_candidates[rip] = [
                        t for t in self.beacon_candidates[rip] if now - t < 60
                    ]
                    if len(self.beacon_candidates[rip]) > 10:
                        self.on_telemetry({
                            'source':        'network',
                            'event':         'beacon_pattern',
                            'dest_ip':       rip,
                            'dest_port':     rport,
                            'frequency':     len(self.beacon_candidates[rip]),
                            'packet_size':   64,
                            'severity_hint': 6,
                            'attack_hint':   'c2_beacon',
                        })

                # Prune stale connections
                cutoff = now - 30
                self.seen_connections = {
                    k: v for k, v in self.seen_connections.items() if v > cutoff
                }

            except Exception as e:
                logger.error(f'Network sniffer error: {e}')

            time.sleep(3)
