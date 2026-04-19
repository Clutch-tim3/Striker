import pickle
import numpy as np
import os
from python.core.logger import get_logger

logger = get_logger('behaviour_classifier')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../models/behaviour_classifier.pkl')

ATTACK_FAMILIES = [
    'benign', 'ransomware', 'keylogger', 'rootkit',
    'c2_beacon', 'data_exfil', 'cryptominer', 'worm',
    'backdoor', 'privilege_escalation',
]


class BehaviourClassifier:
    def __init__(self):
        self.model = self._load_or_create()

    def _load_or_create(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    return pickle.load(f)
            except Exception:
                pass
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(n_estimators=100, random_state=42)

    def _extract_features(self, t: dict) -> np.ndarray:
        def _f(v, default=0):
            try: return float(v) if v is not None else float(default)
            except (TypeError, ValueError): return float(default)
        return np.array([
            _f(t.get('cpu'), 0),
            _f(t.get('memory'), 0),
            _f(t.get('connections'), 0),
            1.0 if t.get('source') == 'network' else 0.0,
            1.0 if t.get('event') == 'mass_file_modification' else 0.0,
            1.0 if t.get('event') == 'high_risk_process' else 0.0,
            1.0 if t.get('event') == 'ransomware_extension_detected' else 0.0,
            _f(t.get('packet_size'), 0) / 65535,
            1.0 if t.get('dest_port') in {4444, 1337, 6667, 8080} else 0.0,
            float(len(t.get('cmdline') or []) > 3),
        ]).reshape(1, -1)

    def classify(self, telemetry: dict):
        try:
            features = self._extract_features(telemetry)
            if not hasattr(self.model, 'classes_'):
                return None
            proba = self.model.predict_proba(features)[0]
            max_idx = int(np.argmax(proba))
            confidence = proba[max_idx]
            label = self.model.classes_[max_idx]
            if label == 'benign' or confidence < 0.65:
                return None
            return label
        except Exception as e:
            logger.error(f'Behaviour classify error: {e}')
            return None

    def retrain(self, X: np.ndarray, y: np.ndarray):
        try:
            self.model.fit(X, y)
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump(self.model, f)
            logger.info('Behaviour classifier retrained')
        except Exception as e:
            logger.error(f'Behaviour retrain failed: {e}')
