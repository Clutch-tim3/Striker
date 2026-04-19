import os
import shutil
import json
from datetime import datetime, timezone
from python.core.logger import get_logger

logger = get_logger('quarantine')

VAULT_DIR = os.path.expanduser('~/.mahoraga/quarantine')
MANIFEST_PATH = os.path.join(VAULT_DIR, 'manifest.json')


class Quarantine:
    def __init__(self):
        os.makedirs(VAULT_DIR, exist_ok=True)

    def quarantine(self, path: str) -> bool:
        if not os.path.exists(path):
            logger.warning(f'Quarantine target not found: {path}')
            return False
        try:
            filename = os.path.basename(path)
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            dest = os.path.join(VAULT_DIR, f'{timestamp}_{filename}')
            shutil.move(path, dest)

            # Append to manifest
            manifest = self._load_manifest()
            manifest.append({
                'original_path': path,
                'quarantine_path': dest,
                'quarantined_at': datetime.now(timezone.utc).isoformat(),
            })
            self._save_manifest(manifest)

            logger.info(f'Quarantined: {path} → {dest}')
            return True
        except Exception as e:
            logger.error(f'Quarantine failed for {path}: {e}')
            return False

    def restore(self, quarantine_path: str) -> bool:
        manifest = self._load_manifest()
        entry = next((e for e in manifest if e['quarantine_path'] == quarantine_path), None)
        if not entry:
            logger.warning(f'No manifest entry for {quarantine_path}')
            return False
        try:
            shutil.move(quarantine_path, entry['original_path'])
            manifest = [e for e in manifest if e['quarantine_path'] != quarantine_path]
            self._save_manifest(manifest)
            logger.info(f'Restored: {quarantine_path} → {entry["original_path"]}')
            return True
        except Exception as e:
            logger.error(f'Restore failed: {e}')
            return False

    def list_quarantined(self) -> list:
        return self._load_manifest()

    def _load_manifest(self) -> list:
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_manifest(self, manifest: list):
        with open(MANIFEST_PATH, 'w') as f:
            json.dump(manifest, f, indent=2)
