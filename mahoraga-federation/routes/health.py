from fastapi import APIRouter
import db
import trainer

router = APIRouter()


@router.get('/health')
async def health():
    return {
        'status':        'ok',
        'total_vectors': db.vector_count(),
        'model':         trainer.model_info(),
        'last_run':      db.last_training_run(),
    }
