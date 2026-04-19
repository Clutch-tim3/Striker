import logging
import os
import sys

LOG_DIR = os.path.expanduser('~/.mahoraga/logs')

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f'mahoraga.{name}')
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s %(message)s',
        datefmt='%H:%M:%S'
    )

    # Stderr handler (captured by Electron)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(formatter)
    sh.setLevel(logging.DEBUG)
    logger.addHandler(sh)

    # File handler
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        fh = logging.FileHandler(os.path.join(LOG_DIR, 'mahoraga.log'))
        fh.setFormatter(formatter)
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)
    except Exception:
        pass

    logger.propagate = False
    return logger
