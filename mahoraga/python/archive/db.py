import sqlite3
import threading
import time
import os
from python.core.logger import get_logger

logger = get_logger('database')
DB_PATH = os.path.expanduser('~/.mahoraga/archive.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS antibodies (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    attack_type     TEXT,
    mitre_id        TEXT,
    mitre_name      TEXT,
    severity        INTEGER,
    anomaly_score   REAL,
    telemetry_json  TEXT,
    response_json   TEXT,
    vector_json     TEXT,
    detection_ms        INTEGER,
    neutralised_ms      INTEGER,
    source              TEXT,
    platform            TEXT,
    insights_json       TEXT,
    offensive_unlocked  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS offensive_strategies (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    attack_types    TEXT,
    locked          INTEGER DEFAULT 1,
    unlock_key      TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_type ON antibodies(attack_type);
CREATE INDEX IF NOT EXISTS idx_severity    ON antibodies(severity);
CREATE INDEX IF NOT EXISTS idx_created_at  ON antibodies(created_at);
CREATE INDEX IF NOT EXISTS idx_strat_locked ON offensive_strategies(locked);
"""


class Database:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        # One connection per thread — thread-safe by construction.
        # WAL mode allows concurrent reads alongside writes.
        self._local = threading.local()
        self._lock  = threading.Lock()
        self._init_conn()
        logger.info(f'Database ready at {DB_PATH}')

    def _init_conn(self):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.executescript(SCHEMA)
        self._migrate(conn)
        conn.commit()
        self._local.conn = conn
        return conn

    @property
    def conn(self):
        c = getattr(self._local, 'conn', None)
        if c is None:
            c = self._init_conn()
        return c

    def _migrate(self, conn=None):
        c = conn or self.conn
        for ddl in [
            'ALTER TABLE antibodies ADD COLUMN insights_json TEXT',
            'ALTER TABLE antibodies ADD COLUMN offensive_unlocked INTEGER DEFAULT 0',
            'ALTER TABLE offensive_strategies ADD COLUMN name TEXT',
            'ALTER TABLE offensive_strategies ADD COLUMN description TEXT',
            'ALTER TABLE offensive_strategies ADD COLUMN attack_types TEXT',
            'ALTER TABLE offensive_strategies ADD COLUMN locked INTEGER DEFAULT 1',
            'ALTER TABLE offensive_strategies ADD COLUMN unlock_key TEXT',
        ]:
            try:
                c.execute(ddl)
                c.commit()
            except sqlite3.OperationalError:
                pass

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        max_retries = 5
        for attempt in range(max_retries):
            try:
                with self._lock:
                    return self.conn.execute(sql, params)
            except sqlite3.OperationalError as e:
                if 'database is locked' in str(e) and attempt < max_retries - 1:
                    time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                    continue
                raise

    def commit(self):
        max_retries = 5
        for attempt in range(max_retries):
            try:
                with self._lock:
                    self.conn.commit()
                    return
            except sqlite3.OperationalError as e:
                if 'database is locked' in str(e) and attempt < max_retries - 1:
                    time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                    continue
                raise
