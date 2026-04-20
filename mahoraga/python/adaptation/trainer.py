import numpy as np
import json
from python.core.logger import get_logger
from python.core.ipc_server import emit
from python.adaptation.reward_function import RewardFunction

logger = get_logger('trainer')

ATTACK_FAMILIES = [
    'benign', 'ransomware', 'keylogger', 'rootkit',
    'c2_beacon', 'data_exfil', 'cryptominer', 'worm',
    'backdoor', 'privilege_escalation',
]


class Trainer:
    def __init__(self, antibody_store, anomaly_detector, behaviour_classifier):
        self.store = antibody_store
        self.anomaly_detector = anomaly_detector
        self.behaviour_classifier = behaviour_classifier
        self.reward_fn = RewardFunction()

    def run(self):
        """Full nightly retrain cycle."""
        logger.info('Starting adaptation training cycle')
        antibodies = self.store.query({})
        if len(antibodies) < 10:
            logger.info(f'Not enough antibodies to retrain ({len(antibodies)} < 10)')
            return

        self._retrain_behaviour_classifier(antibodies)
        self._retrain_anomaly_detector(antibodies)
        logger.info('Adaptation training cycle complete')
        try:
            emit('ADAPTATION_UPDATED', {
                'antibody_count': len(antibodies),
                'status': 'retrained',
            })
        except Exception:
            pass

    def _retrain_behaviour_classifier(self, antibodies: list):
        rows = [(ab, ab.get('attack_type', 'benign')) for ab in antibodies
                if ab.get('attack_type')]
        if not rows:
            return

        X, y, weights = [], [], []
        for ab, label in rows:
            t = self._parse_telemetry(ab)
            features = self._extract_features(t)
            reward = self.reward_fn.calculate({'true_positive': True})
            X.append(features)
            y.append(label)
            weights.append(self.reward_fn.weight_from_reward(reward))

        X = np.array(X)
        y = np.array(y)
        weights = np.array(weights)

        try:
            self.behaviour_classifier.retrain(X, y)
            logger.info(f'Behaviour classifier retrained on {len(X)} samples')
        except Exception as e:
            logger.error(f'Behaviour classifier retrain failed: {e}')

    def _retrain_anomaly_detector(self, antibodies: list):
        for ab in antibodies:
            t = self._parse_telemetry(ab)
            self.anomaly_detector.update_with_threat(t)
        logger.info(f'Anomaly detector updated with {len(antibodies)} threat samples')

    def _parse_telemetry(self, ab: dict) -> dict:
        try:
            return json.loads(ab.get('telemetry_json', '{}'))
        except Exception:
            return {}

    def _extract_features(self, t: dict) -> np.ndarray:
        return np.array([
            float(t.get('cpu', 0)),
            float(t.get('memory', 0)),
            float(t.get('connections', 0)),
            1.0 if t.get('source') == 'network' else 0.0,
            1.0 if t.get('event') == 'mass_file_modification' else 0.0,
            1.0 if t.get('event') == 'high_risk_process' else 0.0,
            1.0 if t.get('event') == 'ransomware_extension_detected' else 0.0,
            float(t.get('packet_size', 0)) / 65535,
            1.0 if t.get('dest_port') in {4444, 1337, 6667, 8080} else 0.0,
            float(len(t.get('cmdline') or []) > 3),
        ])
