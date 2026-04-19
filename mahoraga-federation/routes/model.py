import os
from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import FileResponse
from config import CLIENT_API_KEY, MODEL_PATH
import trainer

router = APIRouter()


@router.get('/model/global_model.pkl')
async def download_model(x_api_key: str = Header(...)):
    if x_api_key != CLIENT_API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')

    if not trainer.model_exists():
        raise HTTPException(status_code=404, detail='No global model available yet — check back after the first training run')

    return FileResponse(
        MODEL_PATH,
        media_type='application/octet-stream',
        filename='global_model.pkl',
    )


@router.get('/model/info')
async def model_info(x_api_key: str = Header(...)):
    if x_api_key != CLIENT_API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')

    return trainer.model_info()
