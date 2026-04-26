import random
import uuid
from datetime import datetime, timezone
from python.core.logger import get_logger

logger = get_logger('strategy_generator')

ADJECTIVES = [
    'Silent', 'Shadow', 'Swift', 'Steel', 'Viper', 'Raven', 'Ghost', 'Storm',
    'Phantom', 'Nexus', 'Cipher', 'Prism', 'Specter', 'Titan', 'Wraith', 'Vector',
    'Apex', 'Void', 'Surge', 'Eclipse', 'Inferno', 'Tempest', 'Horizon', 'Obsidian',
]

NOUNS = [
    'Strike', 'Breach', 'Exodus', 'Cipher', 'Vector', 'Wraith', 'Nexus', 'Titan',
    'Specter', 'Prism', 'Vortex', 'Sentinel', 'Phoenix', 'Reaper', 'Condor', 'Mirage',
    'Havoc', 'Inferno', 'Eclipse', 'Horizon', 'Odyssey', 'Phantom', 'Enigma', 'Assault',
]


class StrategyGenerator:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def generate_name():
        return f"{random.choice(ADJECTIVES)} {random.choice(NOUNS)}"

    def create_strategy(self, attack_types: list, adaptation_version: int = 0) -> dict:
        strategy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        name = self.generate_name()

        if attack_types:
            at_str = ', '.join(attack_types[:3])
            description = f"Offensive strategy leveraging {at_str} techniques"
            if len(attack_types) > 3:
                description += f" and {len(attack_types) - 3} more"
        else:
            description = "Offensive strategy with unspecified techniques"

        strategy = {
            'id':                strategy_id,
            'created_at':        now,
            'name':              name,
            'description':       description,
            'attack_types':      ','.join(attack_types) if attack_types else '',
            'locked':            0,
            'unlock_key':        None,
            'adaptation_version': adaptation_version,
            'last_updated':      now,
        }

        try:
            self.db.execute("""
                INSERT OR IGNORE INTO offensive_strategies (
                    id, created_at, name, description, attack_types,
                    locked, unlock_key, adaptation_version, last_updated
                ) VALUES (
                    :id, :created_at, :name, :description, :attack_types,
                    :locked, :unlock_key, :adaptation_version, :last_updated
                )
            """, strategy)
            self.db.commit()
            logger.info(f'Strategy created: {strategy_id} ({name}) v{adaptation_version}')
        except Exception as e:
            logger.error(f'Failed to create strategy: {e}')

        return strategy

    def query_strategies(self) -> list:
        try:
            rows = self.db.execute(
                'SELECT * FROM offensive_strategies ORDER BY created_at DESC LIMIT 100'
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f'Failed to query strategies: {e}')
            return []

    def get_stale_strategies(self, current_version: int) -> list:
        """Return strategies whose adaptation_version is behind current_version."""
        try:
            rows = self.db.execute(
                'SELECT * FROM offensive_strategies WHERE adaptation_version < ?',
                (current_version,)
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f'Failed to query stale strategies: {e}')
            return []

    def bump_strategy_versions(self, new_version: int) -> int:
        """Advance all strategies below new_version to new_version. Returns count updated."""
        try:
            self.db.execute(
                'UPDATE offensive_strategies '
                'SET adaptation_version = ?, last_updated = CURRENT_TIMESTAMP '
                'WHERE adaptation_version < ?',
                (new_version, new_version)
            )
            self.db.commit()
            return self.db.execute('SELECT changes()').fetchone()[0]
        except Exception as e:
            logger.error(f'Failed to bump strategy versions: {e}')
            return 0

    def count_strategies(self) -> int:
        try:
            return self.db.execute('SELECT COUNT(*) FROM offensive_strategies').fetchone()[0]
        except Exception:
            return 0
