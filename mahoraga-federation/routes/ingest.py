from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, field_validator
from typing import Optional, List
import logging

import db
import trainer
from config import CLIENT_API_KEY, RETRAIN_THRESHOLD

router = APIRouter()
logger = logging.getLogger('ingest')


class VectorPayload(BaseModel):
    vector:      List[float]
    attack_type: Optional[str] = None
    severity:    Optional[int] = None
    platform:    Optional[str] = None
    mitre_id:    Optional[str] = None
    source_hash: Optional[str] = None

    @field_validator('vector')
    @classmethod
    def vector_length(cls, v):
        if len(v) != 8:
            raise ValueError('vector must be length 8')
        for x in v:
            if not (0.0 <= x <= 1.0):
                raise ValueError('all vector values must be in [0.0, 1.0]')
        return v

    @field_validator('severity')
    @classmethod
    def severity_range(cls, v):
        if v is not None and not (0 <= v <= 10):
            raise ValueError('severity must be 0–10')
        return v


@router.post('/ingest')
async def ingest(payload: VectorPayload, x_api_key: str = Header(...)):
    if x_api_key != CLIENT_API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')

    row_id = db.insert_vector(payload.model_dump())
    logger.info(f'Vector {row_id} received — attack_type={payload.attack_type} severity={payload.severity}')

    # Trigger incremental retrain if enough new vectors have built up
    untrained = db.untrained_count()
    if untrained >= RETRAIN_THRESHOLD:
        logger.info(f'{untrained} untrained vectors — triggering incremental retrain')
        import threading
        threading.Thread(target=trainer.retrain, daemon=True).start()

    return {
        'ok':              True,
        'id':              row_id,
        'total_vectors':   db.vector_count(),
        'untrained':       untrained,
    }
