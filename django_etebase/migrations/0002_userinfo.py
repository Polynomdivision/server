# Generated by Django 3.0.3 on 2020-05-14 09:51

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myauth', '0001_initial'),
        ('django_etebase', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserInfo',
            fields=[
                ('owner', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('version', models.PositiveSmallIntegerField(default=1)),
                ('pubkey', models.BinaryField(editable=True)),
                ('salt', models.BinaryField(editable=True)),
            ],
        ),
    ]
