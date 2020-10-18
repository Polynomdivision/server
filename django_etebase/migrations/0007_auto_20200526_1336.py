# Generated by Django 3.0.3 on 2020-05-26 13:36

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_etebase', '0006_auto_20200526_1040'),
    ]

    operations = [
        migrations.AlterField(
            model_name='collection',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, validators=[django.core.validators.RegexValidator(message='Not a valid UID', regex='^[a-zA-Z0-9]*$')]),
        ),
        migrations.AlterField(
            model_name='collectioninvitation',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, validators=[django.core.validators.RegexValidator(message='Expected a base64url.', regex='^[a-zA-Z0-9\\-_]{42,43}$')]),
        ),
        migrations.AlterField(
            model_name='collectionitem',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, null=True, validators=[django.core.validators.RegexValidator(message='Not a valid UID', regex='^[a-zA-Z0-9]*$')]),
        ),
        migrations.AlterField(
            model_name='collectionitemchunk',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, validators=[django.core.validators.RegexValidator(message='Expected a base64url.', regex='^[a-zA-Z0-9\\-_]{42,43}$')]),
        ),
        migrations.AlterField(
            model_name='collectionitemrevision',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, unique=True, validators=[django.core.validators.RegexValidator(message='Expected a base64url.', regex='^[a-zA-Z0-9\\-_]{42,43}$')]),
        ),
    ]
