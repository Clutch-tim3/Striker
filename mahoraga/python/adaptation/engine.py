"""
AdaptationEngine — strategic intelligence layer.

Distinct from Trainer (which retrains ML models).
This engine analyses committed antibodies, computes learned patterns,
writes to adaptation_log, and bumps adaptation_version on all entities.
Every run is deterministic given the same input antibody set.
"""

import json
import random
import threading
from collections import defaultdict
from datetime import datetime, timezone

from python.core.logger import get_logger
from python.core.ipc_server import emit

logger = get_logger('adaptation.engine')

ADAPTATION_BATCH_SIZE = 25


class AdaptationEngine:
    def __init__(self, db, antibody_store, strategy_generator):
        self.db = db
        self.antibody_store = antibody_store
        self.strategy_generator = strategy_generator
        self._lock = threading.Lock()
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────────

    def run_cycle(self) -> dict:
        """Run one adaptation cycle. Thread-safe; skips if already running."""
        with self._lock:
            if self._running:
                logger.info('AdaptationEngine: cycle already running — skipping')
                return {}
            self._running = True
        try:
            return self._do_cycle()
        finally:
            with self._lock:
                self._running = False

    def get_current_cycle(self) -> int:
        """Return the count of completed adaptation cycles."""
        try:
            return self.db.execute('SELECT COUNT(*) FROM adaptation_log').fetchone()[0]
        except Exception:
            return 0

    # ── Core cycle ────────────────────────────────────────────────────────────

    def _do_cycle(self) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        new_cycle = self.get_current_cycle() + 1
        logger.info(f'AdaptationEngine: Starting cycle {new_cycle}')

        # Read all antibodies sorted deterministically by created_at
        antibodies = sorted(
            self.antibody_store.query({}),
            key=lambda ab: ab.get('created_at', '')
        )

        if not antibodies:
            logger.info('AdaptationEngine: No antibodies — skipping cycle')
            return {}

        # Compute learned patterns (deterministic: RNG seeded from antibody IDs)
        learned_patterns = self._compute_patterns(antibodies, seed=new_cycle)

        # Log which strategies are stale (for the applied_changes record)
        stale = self.strategy_generator.get_stale_strategies(new_cycle)
        applied_changes = self._compute_applied_changes(stale, learned_patterns)

        # Advance strategy versions
        updated_strategies = self.strategy_generator.bump_strategy_versions(new_cycle)

        # Advance antibody versions so future cycles don't re-count them
        self._bump_antibody_versions(new_cycle)

        # Persist cycle record
        log_id = self._write_log(
            cycle_time=now,
            input_count=len(antibodies),
            output_count=updated_strategies,
            learned_patterns=learned_patterns,
            applied_changes=applied_changes,
        )

        for at, data in learned_patterns.items():
            logger.info(
                f'AdaptationEngine: Learned patterns: '
                f'{{{at}: {{confidence:{data["confidence"]:.2f}, '
                f'tactics:{data["suggested_tactics"]}}}}}'
            )
        logger.info(
            f'AdaptationEngine: Cycle {new_cycle} complete — '
            f'{len(antibodies)} antibodies, {updated_strategies} strategies updated'
        )

        emit('ADAPTATION_COMPLETED', {
            'cycle':                 new_cycle,
            'log_id':                log_id,
            'input_antibody_count':  len(antibodies),
            'output_strategy_count': updated_strategies,
            'learned_patterns':      learned_patterns,
        })

        return {
            'cycle':             new_cycle,
            'learned_patterns':  learned_patterns,
            'strategies_updated': updated_strategies,
        }

    # ── Pattern computation (deterministic) ──────────────────────────────────

    def _compute_patterns(self, antibodies: list, seed: int = 0) -> dict:
        rng = random.Random(seed)  # seeded — same input → same output

        type_counts: dict[str, int] = defaultdict(int)
        type_tactics: dict[str, set] = defaultdict(set)
        total = len(antibodies)

        for ab in antibodies:
            at = ab.get('attack_type', 'unknown')
            if at == 'unknown':
                continue
            type_counts[at] += 1

            # Tactics from response actions
            try:
                for r in json.loads(ab.get('response_json') or '[]'):
                    if r and r != 'LOGGED':
                        type_tactics[at].add(r)
            except Exception:
                pass

            # Tactics from adaptation insights
            try:
                ins = json.loads(ab.get('insights_json') or '{}')
                if ins.get('adapted'):
                    type_tactics[at].add('model_adaptation')
            except Exception:
                pass

        patterns = {}
        for at, count in type_counts.items():
            confidence = min(1.0, count / max(total * 0.5, 1))
            # Sort tactics list so output is deterministic
            tactics = sorted(type_tactics.get(at, set()))
            patterns[at] = {
                'confidence':      round(confidence, 3),
                'encounter_count': count,
                'suggested_tactics': tactics,
            }

        # Sort by confidence desc (deterministic tie-break on key name)
        return dict(sorted(patterns.items(), key=lambda x: (-x[1]['confidence'], x[0])))

    def _compute_applied_changes(self, stale: list, learned_patterns: dict) -> dict:
        changes = {}
        for s in stale:
            ats = [t.strip() for t in s.get('attack_types', '').split(',') if t.strip()]
            affected = {at: learned_patterns[at] for at in ats if at in learned_patterns}
            if affected:
                changes[s['id']] = {
                    'strategy_name':       s['name'],
                    'version_from':        s.get('adaptation_version', 0),
                    'affected_attack_types': list(affected.keys()),
                    'confidence_gains':    {at: v['confidence'] for at, v in affected.items()},
                }
        return changes

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _bump_antibody_versions(self, new_version: int):
        try:
            self.db.execute(
                'UPDATE antibodies SET adaptation_version = ? WHERE adaptation_version < ?',
                (new_version, new_version)
            )
            self.db.commit()
        except Exception as e:
            logger.error(f'AdaptationEngine: Failed to bump antibody versions: {e}')

    def _write_log(self, cycle_time: str, input_count: int, output_count: int,
                   learned_patterns: dict, applied_changes: dict) -> int:
        try:
            cur = self.db.execute(
                'INSERT INTO adaptation_log '
                '(cycle_time, input_antibody_count, output_strategy_count, '
                ' learned_patterns_json, applied_changes_json) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    cycle_time,
                    input_count,
                    output_count,
                    json.dumps(learned_patterns, sort_keys=True),
                    json.dumps(applied_changes, sort_keys=True),
                )
            )
            self.db.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error(f'AdaptationEngine: Failed to write adaptation_log: {e}')
            return -1
