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
        """Generate random military-style codename"""
        return f"{random.choice(ADJECTIVES)} {random.choice(NOUNS)}"

    def create_strategy(self, attack_types: list) -> dict:
        """Create new offensive strategy from attack types"""
        strategy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        name = self.generate_name()
        
        # Description based on attack types
        if attack_types:
            at_str = ', '.join(attack_types[:3])
            description = f"Offensive strategy leveraging {at_str} techniques"
            if len(attack_types) > 3:
                description += f" and {len(attack_types) - 3} more"
        else:
            description = "Offensive strategy with unspecified techniques"
        
        strategy = {
            'id': strategy_id,
            'created_at': now,
            'name': name,
            'description': description,
            'attack_types': ','.join(attack_types) if attack_types else '',
            'locked': 0,
            'unlock_key': None,
        }
        
        try:
            self.db.execute("""
                INSERT INTO offensive_strategies VALUES (
                    :id, :created_at, :name, :description, :attack_types, :locked, :unlock_key
                )
            """, strategy)
            self.db.commit()
            logger.info(f'Strategy created: {strategy_id} ({name})')
        except Exception as e:
            logger.error(f'Failed to create strategy: {e}')
        
        return strategy

    def query_strategies(self):
        """Get all strategies ordered by creation time"""
        try:
            rows = self.db.execute(
                'SELECT * FROM offensive_strategies ORDER BY created_at DESC LIMIT 100'
            ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['locked'] = int(d.get('locked', 0))
                result.append(d)
            return result
        except Exception as e:
            logger.error(f'Failed to query strategies: {e}')
            return []

    def unlock_strategy(self, strategy_id: str, key: str) -> bool:
        """Unlock individual strategy"""
        try:
            self.db.execute(
                'UPDATE offensive_strategies SET locked = 0, unlock_key = ? WHERE id = ?',
                (key, strategy_id)
            )
            self.db.commit()
            logger.info(f'Strategy unlocked: {strategy_id}')
            return True
        except Exception as e:
            logger.error(f'Failed to unlock strategy: {e}')
            return False

    def count_strategies(self) -> int:
        """Count total strategies"""
        try:
            return self.db.execute('SELECT COUNT(*) FROM offensive_strategies').fetchone()[0]
        except Exception:
            return 0
