import json
import uuid
import platform
from datetime import datetime, timezone
from python.archive.db import Database
from python.core.logger import get_logger

logger = get_logger('antibody_store')


class AntibodyStore:
    def __init__(self, db: Database):
        self.db = db

    def create(self, threat: dict, response_taken: list, insights: dict = None) -> dict:
        antibody_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        telemetry = threat.get('telemetry', {})
        mitre = threat.get('mitre_id', {})

        antibody = {
            'id':             antibody_id,
            'created_at':     now,
            'attack_type':    threat.get('attack_type'),
            'mitre_id':       mitre.get('technique_id'),
            'mitre_name':     mitre.get('technique_name'),
            'severity':       threat.get('severity', 0),
            'anomaly_score':  threat.get('anomaly_score', 0.0),
            'telemetry_json': json.dumps(telemetry),
            'response_json':  json.dumps(response_taken),
            'vector_json':    json.dumps(telemetry),
            'detection_ms':   0,
            'neutralised_ms': 0,
            'source':         telemetry.get('source'),
            'platform':       platform.system(),
            'insights_json':  json.dumps(insights) if insights else None,
        }

        self.db.execute("""
            INSERT INTO antibodies VALUES (
                :id, :created_at, :attack_type, :mitre_id, :mitre_name,
                :severity, :anomaly_score, :telemetry_json, :response_json,
                :vector_json, :detection_ms, :neutralised_ms, :source, :platform,
                :insights_json
            )
        """, antibody)
        self.db.commit()
        logger.info(f'Antibody created: {antibody_id} ({threat.get("attack_type")})')
        return antibody

    def query(self, filters: dict = None) -> list:
        conditions, params = [], []
        if filters:
            if at := filters.get('attack_type'):
                conditions.append('attack_type = ?')
                params.append(at)
            if ms := filters.get('min_severity'):
                conditions.append('severity >= ?')
                params.append(ms)

        where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
        rows = self.db.execute(
            f'SELECT * FROM antibodies {where} ORDER BY created_at DESC LIMIT 100',
            params
        ).fetchall()
        return [dict(row) for row in rows]

    def update_insights(self, antibody_id: str, insights: dict):
        self.db.execute(
            'UPDATE antibodies SET insights_json = ? WHERE id = ?',
            (json.dumps(insights), antibody_id)
        )
        self.db.commit()

    def count(self) -> int:
        return self.db.execute('SELECT COUNT(*) FROM antibodies').fetchone()[0]

    def get_all_vectors(self) -> list:
        rows = self.db.execute(
            'SELECT id, attack_type, vector_json FROM antibodies'
        ).fetchall()
        return [dict(r) for r in rows]
