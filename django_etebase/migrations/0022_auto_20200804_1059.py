# Generated by Django 3.0.3 on 2020-08-04 10:59

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_etebase', '0021_auto_20200626_0913'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='collectionitemchunk',
            unique_together={('item', 'uid')},
        ),
    ]
