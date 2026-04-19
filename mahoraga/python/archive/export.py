import json
import csv
import os
from datetime import datetime, timezone
from python.archive.antibody import AntibodyStore
from python.core.logger import get_logger

logger = get_logger('export')

EXPORT_DIR = os.path.expanduser('~/.mahoraga/exports')


class Exporter:
    def __init__(self, store: AntibodyStore):
        self.store = store

    def export_csv(self, filters: dict = None) -> str:
        os.makedirs(EXPORT_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        path = os.path.join(EXPORT_DIR, f'antibodies_{ts}.csv')

        antibodies = self.store.query(filters or {})
        if not antibodies:
            logger.info('No antibodies to export')
            return ''

        fields = ['id', 'created_at', 'attack_type', 'mitre_id', 'mitre_name',
                  'severity', 'anomaly_score', 'source', 'platform']
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(antibodies)

        logger.info(f'Exported {len(antibodies)} antibodies to {path}')
        return path

    def export_anonymous_vectors(self) -> list:
        """Returns anonymised vectors suitable for federated upload."""
        from python.federated.anonymiser import Anonymiser
        anon = Anonymiser()
        antibodies = self.store.query({})
        return [v for ab in antibodies if (v := anon.anonymise(ab))]
