# Generated by Django 3.2.6 on 2021-09-19 22:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_auto_20210828_1750'),
    ]

    operations = [
        migrations.CreateModel(
            name='CeleryJobTracker',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('instance_id', models.IntegerField()),
                ('createdAt', models.DateTimeField(auto_now=True, verbose_name='createdAt')),
                ('isCompleted', models.BooleanField(default=False, help_text='Denotes whether a task has been completed by worker')),
            ],
        ),
    ]
