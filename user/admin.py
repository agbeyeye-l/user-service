from django.contrib import admin
from user.models import UserProfile, DefaultPermission, UserPermission, Student, Staff, CeleryTaskTracker

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(DefaultPermission)
admin.site.register(UserPermission)
admin.site.register(Student)
admin.site.register(Staff)
admin.site.register(CeleryTaskTracker)
