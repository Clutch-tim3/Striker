"""
Federated model trainer.

Aggregates anonymised vectors from all Mahoraga clients,
retrains the global IsolationForest + behaviour classifier,
and saves the result to models/global_model.pkl.

Clients download this model via GET /model/global_model.pkl
and it replaces their local model, making every installation
smarter from what other users' machines have seen.
"""

import json
import os
import pickle
import logging
import numpy as np
from datetime import datetime, timezone

import db
from config import MODEL_PATH

logger = logging.getLogger('trainer')

ATTACK_FAMILIES = [
    'ransomware', 'c2_beacon', 'data_exfil', 'rootkit',
    'backdoor', 'privilege_escalation', 'keylogger',
    'cryptominer', 'worm', 'unknown',
]


def _parse_vectors(rows):
    vectors, labels, ids = [], [], []
    for row in rows:
        try:
            v = json.loads(row['vector_json'])
            vectors.append(v)
            labels.append(row.get('attack_type') or 'unknown')
            ids.append(row['id'])
        except Exception:
            continue
    return np.array(vectors, dtype='float32'), labels, ids


def retrain(force: bool = False) -> dict:
    """
    Run a full federated retrain cycle.
    Returns a summary dict with status, vectors_used, duration_ms.
    """
    t0 = datetime.now(timezone.utc)

    untrained = db.get_untrained_vectors()
    all_rows   = db.get_all_vectors()

    if not force and len(untrained) == 0:
        return {'status': 'skipped', 'reason': 'no new vectors', 'vectors_used': 0}

    if len(all_rows) < 10:
        return {'status': 'skipped', 'reason': f'only {len(all_rows)} total vectors — need ≥ 10', 'vectors_used': 0}

    vectors, labels, all_ids = _parse_vectors(all_rows)
    _, _, untrained_ids = _parse_vectors(untrained)

    logger.info(f'Retraining on {len(vectors)} vectors ({len(untrained)} new)')

    result = {}
    try:
        models = _train(vectors, labels)
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(models, f)

        db.mark_vectors_trained(untrained_ids)

        duration = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
        logger.info(f'Retrain complete in {duration}ms — model saved to {MODEL_PATH}')

        db.log_training_run(len(vectors), 'success')
        result = {
            'status':       'success',
            'vectors_used': len(vectors),
            'duration_ms':  duration,
            'model_path':   MODEL_PATH,
        }

    except Exception as e:
        logger.error(f'Retrain failed: {e}')
        db.log_training_run(len(vectors), 'failed', str(e))
        result = {'status': 'failed', 'error': str(e)}

    return result


def _train(vectors, labels):
    from sklearn.ensemble import IsolationForest, RandomForestClassifier

    # ── Anomaly model (unsupervised) ────────────────────────────────
    anomaly = IsolationForest(contamination=0.05, random_state=42, n_estimators=200)
    anomaly.fit(vectors)

    # ── Behaviour classifier (supervised) ───────────────────────────
    # Only train if we have enough labelled variety
    unique_labels = set(labels)
    behaviour = None
    if len(unique_labels) >= 3 and len(vectors) >= 30:
        behaviour = RandomForestClassifier(n_estimators=200, random_state=42)
        behaviour.fit(vectors, labels)
        logger.info(f'Behaviour classifier trained on {len(unique_labels)} classes')
    else:
        logger.info('Skipping behaviour classifier — not enough label diversity')

    return {
        'anomaly':   anomaly,
        'behaviour': behaviour,
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'vector_count': len(vectors),
    }


def model_exists() -> bool:
    return os.path.exists(MODEL_PATH)


def model_info() -> dict:
    if not model_exists():
        return {'exists': False}
    stat = os.stat(MODEL_PATH)
    try:
        with open(MODEL_PATH, 'rb') as f:
            m = pickle.load(f)
        return {
            'exists':       True,
            'trained_at':   m.get('trained_at'),
            'vector_count': m.get('vector_count', 0),
            'size_kb':      round(stat.st_size / 1024, 1),
        }
    except Exception:
        return {'exists': True, 'trained_at': None, 'corrupted': True}
