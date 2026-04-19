import sqlite3
import json
from datetime import datetime, timezone
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS vectors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT    NOT NULL,
    attack_type TEXT,
    severity    INTEGER,
    platform    TEXT,
    mitre_id    TEXT,
    source_hash TEXT,
    vector_json TEXT    NOT NULL,
    used_in_training INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS training_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    vectors_used    INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'running',
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_type   ON vectors(attack_type);
CREATE INDEX IF NOT EXISTS idx_used          ON vectors(used_in_training);
CREATE INDEX IF NOT EXISTS idx_received_at   ON vectors(received_at);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def insert_vector(entry: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO vectors
                (received_at, attack_type, severity, platform, mitre_id, source_hash, vector_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            entry.get('attack_type'),
            entry.get('severity'),
            entry.get('platform'),
            entry.get('mitre_id'),
            entry.get('source_hash'),
            json.dumps(entry['vector']),
        ))
        conn.commit()
        return cur.lastrowid


def get_untrained_vectors():
    with get_conn() as conn:
        rows = conn.execute(
            'SELECT * FROM vectors WHERE used_in_training = 0'
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_vectors():
    with get_conn() as conn:
        rows = conn.execute('SELECT * FROM vectors').fetchall()
        return [dict(r) for r in rows]


def mark_vectors_trained(ids):
    with get_conn() as conn:
        conn.execute(
            f'UPDATE vectors SET used_in_training = 1 WHERE id IN ({",".join("?" * len(ids))})',
            ids
        )
        conn.commit()


def vector_count() -> int:
    with get_conn() as conn:
        return conn.execute('SELECT COUNT(*) FROM vectors').fetchone()[0]


def untrained_count() -> int:
    with get_conn() as conn:
        return conn.execute(
            'SELECT COUNT(*) FROM vectors WHERE used_in_training = 0'
        ).fetchone()[0]


def log_training_run(vectors_used: int, status: str, error: str = None) -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO training_runs (started_at, finished_at, vectors_used, status, error)
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(),
            vectors_used,
            status,
            error,
        ))
        conn.commit()
        return cur.lastrowid


def last_training_run():
    with get_conn() as conn:
        row = conn.execute(
            'SELECT * FROM training_runs ORDER BY id DESC LIMIT 1'
        ).fetchone()
        return dict(row) if row else None
