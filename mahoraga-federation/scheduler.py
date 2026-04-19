"""
Schedules the daily federated model retrain.
Runs at 02:00 UTC by default (configurable via env vars).
Also retriggers if RETRAIN_THRESHOLD new vectors arrive between runs.
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

import trainer
from config import RETRAIN_HOUR, RETRAIN_MINUTE

logger = logging.getLogger('scheduler')
_scheduler = BackgroundScheduler()


def _daily_retrain():
    logger.info('Daily retrain triggered by scheduler')
    result = trainer.retrain()
    logger.info(f'Daily retrain result: {result}')


def start():
    _scheduler.add_job(
        _daily_retrain,
        CronTrigger(hour=RETRAIN_HOUR, minute=RETRAIN_MINUTE),
        id='daily_retrain',
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(f'Scheduler started — daily retrain at {RETRAIN_HOUR:02d}:{RETRAIN_MINUTE:02d} UTC')


def stop():
    _scheduler.shutdown(wait=False)
