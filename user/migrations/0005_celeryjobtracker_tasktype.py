# Generated by Django 3.2.6 on 2021-09-25 20:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_celeryjobtracker'),
    ]

    operations = [
        migrations.AddField(
            model_name='celeryjobtracker',
            name='taskType',
            field=models.CharField(default='get', max_length=100),
        ),
    ]
