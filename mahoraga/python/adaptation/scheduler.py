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
        self.running = False

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
                    self.trainer.run()
                    last_retrain_day = today
                except Exception as e:
                    logger.error(f'Nightly retrain error: {e}')
            time.sleep(60)

    def trigger_now(self):
        """Manual retrain trigger (e.g. from settings UI)."""
        threading.Thread(target=self.trainer.run, daemon=True).start()
