"""
Mahoraga Federation Server
--------------------------
Self-hosted replacement for:
  AWS Lambda  → POST /ingest       (receive anonymised threat vectors)
  AWS S3      → GET  /model/...    (serve global model to clients)
  SageMaker   → scheduler + trainer (retrain global model nightly)

Run:
  uvicorn main:app --host 0.0.0.0 --port 8000

Deploy:
  docker-compose up -d  (see deploy/docker-compose.yml)
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

import db
import scheduler
from routes import ingest, model, admin, health
from config import LOG_LEVEL

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, 'INFO'),
    format='%(asctime)s  %(levelname)-8s  %(name)s  %(message)s',
)
logger = logging.getLogger('main')


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs('models', exist_ok=True)
    db.init_db()
    scheduler.start()
    logger.info('Mahoraga Federation Server started')
    yield
    scheduler.stop()
    logger.info('Mahoraga Federation Server stopped')


app = FastAPI(
    title='Mahoraga Federation Server',
    description='Self-hosted federated learning backend for Mahoraga EDR',
    version='1.0.0',
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(model.router)
app.include_router(admin.router)
