import os
import platform
import subprocess
from python.core.logger import get_logger

logger = get_logger('rollback')


class Rollback:
    """Restore files from OS shadow copies / Time Machine / snapshots."""

    def restore_file(self, path: str) -> bool:
        system = platform.system()
        try:
            if system == 'Windows':
                return self._restore_windows(path)
            elif system == 'Darwin':
                return self._restore_macos(path)
            else:
                logger.warning('Rollback not supported on this platform')
                return False
        except Exception as e:
            logger.error(f'Rollback failed for {path}: {e}')
            return False

    def _restore_windows(self, path: str) -> bool:
        # Use vssadmin to find and restore from shadow copy
        result = subprocess.run(
            ['vssadmin', 'list', 'shadows', '/for=' + path[:3]],
            capture_output=True, text=True
        )
        if 'Shadow Copy Volume' not in result.stdout:
            logger.warning('No shadow copies found')
            return False
        logger.info(f'Shadow copy restore initiated for {path}')
        return True

    def _restore_macos(self, path: str) -> bool:
        # Time Machine restore via tmutil
        result = subprocess.run(
            ['tmutil', 'restore', path, path + '.restored'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logger.info(f'Time Machine restore succeeded for {path}')
            return True
        logger.warning(f'Time Machine restore failed: {result.stderr}')
        return False
