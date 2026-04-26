import pickle
import numpy as np
import threading
import os
from python.core.logger import get_logger

logger = get_logger('anomaly_detector')

# Store trained model outside the source tree so it is never committed.
MODEL_PATH = os.path.expanduser('~/.mahoraga/models/anomaly_model.pkl')

# Fallback: migrate model from old source-tree location on first run.
_LEGACY_PATH = os.path.join(os.path.dirname(__file__), '../../models/anomaly_model.pkl')

ROLLING_WINDOW = 2000   # how many samples to train on each cycle
_SEED_RATIO    = 2      # keep buffer_limit // _SEED_RATIO samples after retrain


class AnomalyDetector:
    def __init__(self):
        self.model = self._load_or_create()
        self.training_buffer = []
        self.buffer_limit = 500
        self._lock = threading.Lock()
        self._retraining = False

    def _load_or_create(self):
        for path in [MODEL_PATH, _LEGACY_PATH]:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        return pickle.load(f)
                except Exception:
                    pass
        from sklearn.ensemble import IsolationForest
        return IsolationForest(contamination=0.05, random_state=42)

    def _to_vector(self, t: dict) -> np.ndarray:
        def _f(v, default=0):
            try: return float(v) if v is not None else float(default)
            except (TypeError, ValueError): return float(default)
        return np.array([
            _f(t.get('cpu'), 0),
            _f(t.get('memory'), 0),
            _f(t.get('connections'), 0),
            1.0 if t.get('is_sensitive') else 0.0,
            1.0 if t.get('event') == 'new_process' else 0.0,
            1.0 if t.get('source') == 'network' else 0.0,
            _f(t.get('packet_size'), 0) / 65535,
            1.0 if t.get('event') == 'mass_file_modification' else 0.0,
        ]).reshape(1, -1)

    def score(self, telemetry: dict) -> float:
        try:
            vec = self._to_vector(telemetry)
            raw = self.model.score_samples(vec)[0]
            score = max(0.0, min(1.0, (raw + 0.5) * -1))

            trigger = False
            with self._lock:
                self.training_buffer.append(vec[0])
                if len(self.training_buffer) >= self.buffer_limit and not self._retraining:
                    self._retraining = True
                    trigger = True

            if trigger:
                self._incremental_retrain()

            return score
        except Exception as e:
            logger.error(f'Anomaly score error: {e}')
            return 0.0

    def _incremental_retrain(self):
        def retrain():
            with self._lock:
                # Train on the rolling window of most-recent samples.
                buf = list(self.training_buffer[-ROLLING_WINDOW:])
                # Keep a seed below buffer_limit so the next retrain requires
                # buffer_limit // _SEED_RATIO new samples before firing again.
                self.training_buffer = self.training_buffer[-(self.buffer_limit // _SEED_RATIO):]
            try:
                X = np.array(buf)
                self.model.fit(X)
                os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
                with open(MODEL_PATH, 'wb') as f:
                    pickle.dump(self.model, f)
                logger.info(f'Anomaly model retrained — {len(buf)} samples, window={ROLLING_WINDOW}')
            except Exception as e:
                logger.error(f'Retrain failed: {e}')
            finally:
                with self._lock:
                    self._retraining = False

        threading.Thread(target=retrain, daemon=True).start()

    def update_with_threat(self, telemetry: dict):
        vec = self._to_vector(telemetry)
        with self._lock:
            self.training_buffer.append(vec[0])
