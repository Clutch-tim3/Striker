import sqlite3
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

CREATE INDEX IF NOT EXISTS idx_attack_type ON antibodies(attack_type);
CREATE INDEX IF NOT EXISTS idx_severity    ON antibodies(severity);
CREATE INDEX IF NOT EXISTS idx_created_at  ON antibodies(created_at);
"""


class Database:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()
        logger.info(f'Database ready at {DB_PATH}')

    def _migrate(self):
        for ddl in [
            'ALTER TABLE antibodies ADD COLUMN insights_json TEXT',
            'ALTER TABLE antibodies ADD COLUMN offensive_unlocked INTEGER DEFAULT 0',
        ]:
            try:
                self.conn.execute(ddl)
                self.conn.commit()
            except sqlite3.OperationalError:
                pass

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def commit(self):
        self.conn.commit()
