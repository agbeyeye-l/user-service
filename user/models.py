from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser, User
from django.db.models.signals import post_save
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import ugettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from enum import Enum


# represent user roles
class UserRole(Enum):
    Student = 'STUDENT'
    Staff = 'STAFF'



class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    use_in_migrations = True
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)
    

# Create your models here.
class UserProfile(AbstractUser):
    username = None
    bio = models.CharField(max_length=5000, unique=False, blank= True, null= True,
        help_text=_('Short descritpion of user'))
    nationality = models.CharField(max_length=254, unique=False, blank= True, null= True,
        help_text=_('Represent the country of origin of the user'))
    phone_number= models.CharField(max_length=254, unique=True, blank= True, null= True,
        help_text=_('Designates contact of user'))
    role = models.CharField(max_length=254,unique=False,
        help_text=_('Designates type of user on the platform. Whether student or staff'))
    is_verified = models.BooleanField(default=False)
    email = models.EmailField(unique=True, help_text=_('Designates the email address of user'))
    avatar = models.CharField(max_length=5000,unique=False, blank= True, null= True,
        help_text=_('Profile picture of user'))
    label = models.CharField(max_length= 100, blank= True, null= True,
        help_text=_('Designates a high profile user'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    # string representation of user
    def __str__(self):
        return self.email

    class Meta:
        ordering = ('id',)

class Student(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    programme = models.CharField(max_length=200, blank=True, null=True)
    start_year = models.CharField(max_length= 100, blank= True, null= True)
    end_year = models.CharField(max_length= 100, blank= True, null= True)
    is_alumni = models.BooleanField(default=False)

    def __str__(self):
        return self.user.email


class Staff(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    type = models.CharField(max_length= 100, blank= True, null= True)
    start_year = models.CharField(max_length= 100, blank= True, null= True)

    def __str__(self):
        return self.user.email



class DefaultPermission(models.Model):
    role = models.CharField(max_length=254, unique = True)
    post = ArrayField(models.CharField(max_length=5),4)
    story = ArrayField(models.CharField(max_length=5), 4)
    gallery = ArrayField(models.CharField(max_length=5), 4)
    shelf = ArrayField(models.CharField(max_length=5), 4)
    book = ArrayField(models.CharField(max_length=5), 4)
    announcement = ArrayField(models.CharField(max_length=5), 4)
    event = ArrayField(models.CharField(max_length=5), 4)
    suggestion = ArrayField(models.CharField(max_length=5), 4)

    # string representation of user
    def __str__(self):
        return self.role 


class UserPermission(models.Model):
    user = models.OneToOneField(UserProfile, on_delete = models.CASCADE)
    post = ArrayField(models.CharField(max_length=5),4)
    story = ArrayField(models.CharField(max_length=5), 4)
    gallery = ArrayField(models.CharField(max_length=5), 4)
    shelf = ArrayField(models.CharField(max_length=5), 4)
    book = ArrayField(models.CharField(max_length=5), 4)
    announcement = ArrayField(models.CharField(max_length=5), 4)
    event = ArrayField(models.CharField(max_length=5), 4)
    suggestion = ArrayField(models.CharField(max_length=5), 4)
  

    # string representation of permission
    def __str__(self):
        return self.user.email 


# create a new student record
def create_student(instance):
    student = Student.objects.create(user= instance)
    student.save()

# create a new staff record
def create_staff(instance):
    staff = Staff.objects.create(user = instance)
    staff.save()

# send user data to post service
def send_to_post_service(instance):
    # use celery for this job
    pass

# callback function whenever a new user is created
def new_user_created(sender, instance, created, **kwargs):
    if created:
        if str(instance.role).upper() == UserRole.Student.value:
            create_student(instance)
        elif str(instance.role).upper() == UserRole.Staff.value:
            create_staff(instance)

# signal for running create student and staff function
post_save.connect(new_user_created, sender= UserProfile)


class CeleryTaskTracker(models.Model):
    instance_id = models.IntegerField()
    createdAt = models.DateTimeField(verbose_name="createdAt",auto_now=True)
    isCompleted = models.BooleanField(default= False,help_text=('Denotes whether a task has been completed by worker'))
    taskType = models.CharField(max_length= 20)

    def get_instance(self):
        instance = UserProfile.objects.get(pk=self.instance_id)
        return instance

    def __str__(self):
        return str(self.instance_id)
