from fastapi import APIRouter, HTTPException, Header
from config import ADMIN_API_KEY
import db
import trainer
import threading

router = APIRouter()


def _require_admin(key: str):
    if key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail='Invalid admin key')


@router.post('/admin/retrain')
async def force_retrain(x_api_key: str = Header(...)):
    _require_admin(x_api_key)
    result = {}

    def run():
        nonlocal result
        result = trainer.retrain(force=True)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=120)

    return result


@router.get('/admin/stats')
async def stats(x_api_key: str = Header(...)):
    _require_admin(x_api_key)
    return {
        'total_vectors':    db.vector_count(),
        'untrained_vectors': db.untrained_count(),
        'last_training_run': db.last_training_run(),
        'model':            trainer.model_info(),
    }


@router.delete('/admin/vectors')
async def purge_vectors(x_api_key: str = Header(...)):
    """Delete all stored vectors (e.g. for GDPR compliance or fresh start)."""
    _require_admin(x_api_key)
    import sqlite3
    from config import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM vectors')
        conn.commit()
    return {'ok': True, 'message': 'All vectors purged'}
