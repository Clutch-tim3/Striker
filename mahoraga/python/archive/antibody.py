import json
import uuid
import platform
from datetime import datetime, timezone
from typing import Optional
from python.archive.db import Database
from python.core.logger import get_logger

logger = get_logger('antibody_store')


class AntibodyStore:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def _safe_json(obj) -> Optional[str]:
        try:
            return json.dumps(obj, default=str)
        except Exception as e:
            logger.error(f'JSON serialization failed for {type(obj).__name__}: {e}')
            return None  # Don't mask failure with empty object

    def create(self, threat: dict, response_taken: list, insights: dict = None) -> dict:
        antibody_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        telemetry = threat.get('telemetry', {})
        mitre = threat.get('mitre_id', {})

        # Serialize all fields with proper error handling first
        telemetry_json = self._safe_json(telemetry)
        response_json = self._safe_json(response_taken)
        vector_json = self._safe_json(telemetry)

        if not all([telemetry_json, response_json, vector_json]):
            raise ValueError(
                f'Failed to serialize antibody fields: '
                f'telemetry={bool(telemetry_json)}, response={bool(response_json)}, vector={bool(vector_json)}'
            )

        antibody = {
            'id':             antibody_id,
            'created_at':     now,
            'attack_type':    threat.get('attack_type') or 'unknown',
            'mitre_id':       mitre.get('technique_id') if isinstance(mitre, dict) else None,
            'mitre_name':     mitre.get('technique_name') if isinstance(mitre, dict) else None,
            'severity':       int(threat.get('severity', 0)),
            'anomaly_score':  float(threat.get('anomaly_score', 0.0)),
            'telemetry_json': telemetry_json,
            'response_json':  response_json,
            'vector_json':    vector_json,
            'detection_ms':   0,
            'neutralised_ms': 0,
            'source':              telemetry.get('source', 'unknown'),
            'platform':            platform.system(),
            'insights_json':       self._safe_json(insights) if insights else None,
            'offensive_unlocked':  0,
        }

        self.db.execute("""
            INSERT INTO antibodies VALUES (
                :id, :created_at, :attack_type, :mitre_id, :mitre_name,
                :severity, :anomaly_score, :telemetry_json, :response_json,
                :vector_json, :detection_ms, :neutralised_ms, :source, :platform,
                :insights_json, :offensive_unlocked
            )
        """, antibody)
        self.db.commit()
        logger.info(f'Antibody created: {antibody_id} ({antibody["attack_type"]})')
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
        # Convert SQLite rows to JSON-safe dicts
        result = []
        for row in rows:
            d = dict(row)
            # Ensure all fields are JSON-serializable
            d['severity'] = int(d.get('severity', 0))
            d['anomaly_score'] = float(d.get('anomaly_score', 0.0))
            result.append(d)
        return result

    def update_insights(self, antibody_id: str, insights: dict):
        insights_json = self._safe_json(insights)
        if insights_json is None:
            raise ValueError('Failed to serialize insights')
        self.db.execute(
            'UPDATE antibodies SET insights_json = ? WHERE id = ?',
            (insights_json, antibody_id)
        )
        self.db.commit()

    def get_stats(self) -> dict:
        try:
            total = self.db.execute('SELECT COUNT(*) FROM antibodies').fetchone()[0]
            by_type = self.db.execute(
                'SELECT attack_type, COUNT(*) FROM antibodies GROUP BY attack_type'
            ).fetchall()
            avg_sev = self.db.execute(
                'SELECT AVG(severity) FROM antibodies'
            ).fetchone()[0] or 0
            return {
                'total':       total,
                'avg_severity': round(float(avg_sev), 1),
                'by_type':     {row[0]: row[1] for row in by_type},
            }
        except Exception as e:
            logger.error(f'Archive stats failed: {e}')
            return {'total': 0, 'avg_severity': 0, 'by_type': {}}

    def count(self) -> int:
        return self.db.execute('SELECT COUNT(*) FROM antibodies').fetchone()[0]

    def get_all_vectors(self) -> list:
        rows = self.db.execute(
            'SELECT id, attack_type, vector_json FROM antibodies'
        ).fetchall()
        return [dict(r) for r in rows]
