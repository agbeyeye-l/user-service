# Generated by Django 3.2.6 on 2021-08-28 15:50

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_auto_20210828_1433'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='userprofile',
            options={'ordering': ('id',)},
        ),
        migrations.AlterField(
            model_name='userpermission',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='avatar',
            field=models.CharField(blank=True, help_text='Profile picture of user', max_length=5000, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='bio',
            field=models.CharField(blank=True, help_text='Short descritpion of user', max_length=5000, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='email',
            field=models.EmailField(help_text='Designates the email address of user', max_length=254, unique=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='label',
            field=models.CharField(blank=True, help_text='Designates a high profile user', max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='nationality',
            field=models.CharField(blank=True, help_text='Represent the country of origin of the user', max_length=254, null=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='phone_number',
            field=models.CharField(blank=True, help_text='Designates contact of user', max_length=254, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(help_text='Designates type of user on the platform. Whether student or staff', max_length=254),
        ),
    ]
