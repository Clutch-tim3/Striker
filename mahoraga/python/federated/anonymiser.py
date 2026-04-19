import hashlib
import numpy as np


class Anonymiser:
    """
    Strips all PII before any data leaves the machine.
    Only anonymous behavioural vectors are ever uploaded.
    """

    def anonymise(self, antibody: dict):
        try:
            vector = self._extract_safe_vector(antibody)
            return {
                'vector':      vector.tolist(),
                'attack_type': antibody.get('attack_type'),
                'severity':    antibody.get('severity'),
                'platform':    antibody.get('platform'),
                'mitre_id':    antibody.get('mitre_id'),
                'source_hash': hashlib.sha256(
                    antibody.get('id', '').encode()
                ).hexdigest()[:16],
            }
        except Exception:
            return None

    def _extract_safe_vector(self, ab: dict) -> np.ndarray:
        return np.array([
            float(ab.get('anomaly_score', 0)),
            float(ab.get('severity', 0)) / 10,
            1.0 if ab.get('attack_type') == 'ransomware' else 0.0,
            1.0 if ab.get('attack_type') == 'c2_beacon' else 0.0,
            1.0 if ab.get('attack_type') == 'data_exfil' else 0.0,
            1.0 if ab.get('attack_type') == 'rootkit' else 0.0,
            1.0 if ab.get('source') == 'network' else 0.0,
            1.0 if ab.get('source') == 'file' else 0.0,
        ])
