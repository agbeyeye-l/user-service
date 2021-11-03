from celery import shared_task, Task
from requests.exceptions import RequestException
from user.utils import MessengerService, MessengerData, TaskType
import logging

logger = logging.getLogger(__name__)

# Set autoretry_for, max_retries, retry_backoff, retry_backoff_max
class BaseTaskWithRetry(Task):
    autoretry_for = (TypeError,RequestException,)
    max_retries = 1000
    retry_backoff = True
    retry_backoff_max = 30
    retry_jitter = False


# Task should be retried when request to external service fails: default number of time is 5
# @shared_task(name="send_user_data", bind=True, autoretry_for=(RequestException,ConnectionError,
#                                                                 ConnectionRefusedError,), 
#                                                                 retry_backoff=True, retry_backoff_max = 1*60)

# No auto retry
@shared_task(name="send_user_data", bind=True)
def MessengerToExternalServiceTask(self, data, task_id, task_type):
    """
    This task send user crud operation updates to other services such as post-service
    """
    if task_type == TaskType.POST:
        result = MessengerService.new_user_created(data=data, task_id=task_id)
        logger.info(result.status_code, result.text)
        return
    elif task_type == TaskType.UPDATE:
        result = MessengerService.update_user(data=data, task_id=task_id)
        logger.info(result.status_code, result.text)
        return
    elif task_type == TaskType.DELETE:
        result = MessengerService.remove_user(user_id=data, task_id=task_id)
        logger.info(result.status_code, result.text)
        return


