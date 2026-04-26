import threading
import time
from datetime import datetime
from python.core.logger import get_logger
from python.adaptation.trainer import Trainer

logger = get_logger('scheduler')

RETRAIN_HOUR = 2   # 2 AM local time


class AdaptationScheduler:
    def __init__(self, antibody_store, anomaly_detector, behaviour_classifier):
        self.trainer = Trainer(antibody_store, anomaly_detector, behaviour_classifier)
        self.engine = None   # Set via set_engine() after AdaptationEngine is constructed
        self.running = False

    def set_engine(self, engine):
        self.engine = engine

    def start(self):
        self.running = True
        threading.Thread(target=self._schedule_loop, daemon=True).start()
        logger.info('Adaptation scheduler started')

    def stop(self):
        self.running = False

    def _schedule_loop(self):
        last_retrain_day = None
        while self.running:
            now = datetime.now()
            today = now.date()
            if (now.hour == RETRAIN_HOUR and
                    now.minute < 5 and
                    last_retrain_day != today):
                logger.info('Nightly retrain triggered')
                try:
                    self._run_full_cycle()
                    last_retrain_day = today
                except Exception as e:
                    logger.error(f'Nightly retrain error: {e}')
            time.sleep(60)

    def trigger_now(self):
        """Manual retrain trigger — runs ML retraining + strategic adaptation cycle."""
        threading.Thread(target=self._run_full_cycle, daemon=True).start()

    def _run_full_cycle(self):
        self.trainer.run()
        if self.engine:
            self.engine.run_cycle()
