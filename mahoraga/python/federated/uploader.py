import json
import urllib.request
import urllib.error
from python.federated.anonymiser import Anonymiser
from python.core.config import Config
from python.core.logger import get_logger

logger = get_logger('federated_uploader')

# Point at your self-hosted federation server (set federation_server_url in config)
DEFAULT_FEDERATION_URL = 'http://localhost:8000'


class FederatedUploader:
    def __init__(self):
        self.anonymiser = Anonymiser()

    def upload(self, antibody: dict) -> bool:
        config = Config.load()
        if not config.get('federated_enabled', False):
            return False
        if config.get('tier', 'free') != 'pro':
            return False

        api_key = config.get('federation_api_key', '')
        if not api_key:
            logger.warning('federated_enabled=true but no federation_api_key in config')
            return False

        base_url = config.get('federation_server_url', DEFAULT_FEDERATION_URL).rstrip('/')
        safe_vector = self.anonymiser.anonymise(antibody)
        if not safe_vector:
            return False

        try:
            payload = json.dumps(safe_vector).encode()
            req = urllib.request.Request(
                f'{base_url}/ingest',
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'X-Api-Key':    api_key,
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                result = json.loads(resp.read())
                logger.info(f'Vector uploaded — server total: {result.get("total_vectors")}')
                return True
        except urllib.error.HTTPError as e:
            logger.warning(f'Federation upload HTTP {e.code}: {e.reason}')
        except Exception as e:
            logger.warning(f'Federation upload failed (non-critical): {e}')
        return False
