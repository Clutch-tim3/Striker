import json
import os
from typing import Any

CONFIG_PATH = os.path.expanduser('~/.mahoraga/config.json')

DEFAULTS = {
    'tier': 'free',
    'license_key': '',
    'anomaly_enabled': True,
    'behaviour_enabled': True,
    'heuristics_enabled': True,
    'auto_kill_threshold': 8,
    'auto_quarantine': True,
    'auto_isolate': False,
    'nightly_retrain': True,
    'federated_enabled': False,
    'anomaly_threshold': 0.75,
}

class Config:
    def __init__(self, data: dict):
        self._data = {**DEFAULTS, **data}

    @classmethod
    def load(cls) -> 'Config':
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH) as f:
                    return cls(json.load(f))
        except Exception:
            pass
        return cls({})

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def update(self, data: dict):
        self._data.update(data)

    def save(self):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(self._data, f, indent=2)

    def to_dict(self) -> dict:
        return dict(self._data)
