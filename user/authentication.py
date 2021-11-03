from django.contrib.auth.backends import BaseBackend
from user.models import UserProfile

class UserServiceBackend(BaseBackend):
    """
    This class provides a customized authentication backend for the user service
    """
    def authenticate(self, email=None, password=None):
        try:
            user = UserProfile.objects.get(email=email, password=password)
        except UserProfile.DoesNotExist:   
            return None
        return user

    def get_user(self, user_id):
        try:
            return UserProfile.objects.get(pk=user_id)
        except UserProfile.DoesNotExist:
            return None