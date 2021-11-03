from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from user.views import check_uncompleted_tasks
import os

def start():
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_uncompleted_tasks, 'interval', minutes= 1)
    scheduler.start()