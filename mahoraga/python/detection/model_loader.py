import pickle
import os
from python.core.logger import get_logger

logger = get_logger('model_loader')

MODELS_DIR = os.path.join(os.path.dirname(__file__), '../../models')


def load_model(filename: str):
    path = os.path.join(MODELS_DIR, filename)
    if not os.path.exists(path):
        logger.warning(f'Model not found: {path}')
        return None
    try:
        with open(path, 'rb') as f:
            model = pickle.load(f)
        logger.info(f'Loaded model: {filename}')
        return model
    except Exception as e:
        logger.error(f'Failed to load model {filename}: {e}')
        return None


def save_model(model, filename: str):
    path = os.path.join(MODELS_DIR, filename)
    os.makedirs(MODELS_DIR, exist_ok=True)
    try:
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        logger.info(f'Saved model: {filename}')
    except Exception as e:
        logger.error(f'Failed to save model {filename}: {e}')
