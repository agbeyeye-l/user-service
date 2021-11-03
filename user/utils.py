from django.core.mail import EmailMessage
from user.models import CeleryTaskTracker
import requests
from rest_framework import status
import logging

logger = logging.getLogger(__name__)

class Util:
    @staticmethod
    def send_email(data):
        email=EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.send()


class SITSC_POST_Service:
    ENDPOINT = 'http://192.168.96.8:8000/users/'
    NAME = 'Post Service'
    STATUS = False


class MessengerService:
    @staticmethod
    def new_user_created(data, task_id):
        result = requests.post(url=SITSC_POST_Service.ENDPOINT, data = {'id': data.get('id'), 'first_name':data.get('first_name'),
                                                                        'last_name':data.get('last_name'), 'email':data.get('email'),
                                                                        'avatar':data.get("avatar"),'phone': data.get('phone_number'),'role':3})
        if result.status_code==status.HTTP_201_CREATED:
            job_instance = CeleryTaskTracker.objects.get(pk=task_id)
            job_instance.isCompleted=True
            job_instance.save()
        return result

    @staticmethod
    def update_user(data, task_id):
        result = requests.put(url=SITSC_POST_Service.ENDPOINT+str(data.get('id'))+'/', data = {'id': data.get('id'), 'first_name':data.get('first_name'),
                                                                        'last_name':data.get('last_name'), 'email':data.get('email'),
                                                                        'avatar':data.get("avatar"),'phone': data.get('phone_number'),'role':3})
        if result.status_code==status.HTTP_200_OK:
            job_instance = CeleryTaskTracker.objects.get(pk=task_id)
            job_instance.isCompleted=True
            job_instance.save()
        return result

    @staticmethod
    def remove_user(user_id, task_id):
        result = requests.delete(url=SITSC_POST_Service.ENDPOINT+str(user_id)+'/', data = {'id':user_id})
        if result.status_code==status.HTTP_204_NO_CONTENT:
            job_instance = CeleryTaskTracker.objects.get(pk=task_id)
            job_instance.isCompleted=True
            job_instance.save()
        return result


class MessengerData:
    """
    Represents the data to be sent to external services
    """
    
    task_id=0
    task_type=''
    def __init__(self, data, task_id, task_type) -> None:
        self.data=data
        self.task_id=task_id
        self.task_type=task_type
    

class TaskType:
    """
    Represents the type of task to be executed by celery worker
    """
    UPDATE = 'update'
    POST = 'post'
    DELETE = 'delete'