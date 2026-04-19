import os
import base64
from python.core.logger import get_logger

logger = get_logger('encryption')


def _get_key() -> bytes:
    key_path = os.path.expanduser('~/.mahoraga/.key')
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()
    key = os.urandom(32)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, 'wb') as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key


def encrypt(data: bytes) -> bytes:
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(_get_key())
        f = Fernet(key)
        return f.encrypt(data)
    except ImportError:
        logger.warning('cryptography package not installed — data stored unencrypted')
        return data


def decrypt(data: bytes) -> bytes:
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(_get_key())
        f = Fernet(key)
        return f.decrypt(data)
    except ImportError:
        return data
