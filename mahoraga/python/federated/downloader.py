import os
import urllib.request
import urllib.error
from python.core.config import Config
from python.core.logger import get_logger

logger = get_logger('federated_downloader')

MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../models/global_model.pkl')
DEFAULT_FEDERATION_URL = 'http://localhost:8000'


class FederatedDownloader:
    def check_and_update(self) -> bool:
        config = Config.load()
        if not config.get('federated_enabled', False):
            return False

        api_key = config.get('federation_api_key', '')
        if not api_key:
            return False

        base_url = config.get('federation_server_url', DEFAULT_FEDERATION_URL).rstrip('/')
        model_url = f'{base_url}/model/global_model.pkl'

        try:
            # Check server model info before downloading
            info = self._get_model_info(base_url, api_key)
            if not info.get('exists'):
                logger.info('No global model on server yet')
                return False

            local_trained_at = config.get('global_model_trained_at', '')
            remote_trained_at = info.get('trained_at', '')
            if remote_trained_at and remote_trained_at == local_trained_at:
                logger.info('Global model already up to date')
                return False

            # Download the model
            req = urllib.request.Request(
                model_url,
                headers={'X-Api-Key': api_key},
            )
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            with urllib.request.urlopen(req, timeout=30) as resp:
                with open(MODEL_PATH, 'wb') as f:
                    f.write(resp.read())

            config.update({'global_model_trained_at': remote_trained_at})
            config.save()
            logger.info(f'Global model updated (trained_at={remote_trained_at})')
            return True

        except urllib.error.HTTPError as e:
            logger.warning(f'Model download HTTP {e.code}: {e.reason}')
        except Exception as e:
            logger.warning(f'Global model download failed (non-critical): {e}')
        return False

    def _get_model_info(self, base_url: str, api_key: str) -> dict:
        try:
            req = urllib.request.Request(
                f'{base_url}/model/info',
                headers={'X-Api-Key': api_key},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                import json
                return json.loads(resp.read())
        except Exception:
            return {}
