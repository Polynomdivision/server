# Generated by Django 3.1 on 2020-09-07 07:52

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_etebase', '0025_auto_20200804_1216'),
    ]

    operations = [
        migrations.RenameField(
            model_name='collectioninvitation',
            old_name='accessLevel',
            new_name='accessLevelOld',
        ),
        migrations.RenameField(
            model_name='collectionmember',
            old_name='accessLevel',
            new_name='accessLevelOld',
        ),
    ]
