# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('easyaudit', '0003_auto_20170228_1505'),
    ]

    operations = [
        migrations.CreateModel(
            name='RequestEvent',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.CharField(max_length=255, db_index=True)),
                ('type', models.CharField(max_length=20, db_index=True)),
                ('query_string', models.CharField(max_length=255, null=True)),
                ('remote_ip', models.CharField(max_length=20, db_index=True)),
                ('datetime', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, blank=True, to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
                'ordering': ['-datetime'],
                'verbose_name': 'request event',
                'verbose_name_plural': 'reques events',
            },
        ),
        migrations.AddField(
            model_name='loginevent',
            name='remote_ip',
            field=models.CharField(max_length=20, null=True, db_index=True),
        ),
    ]
