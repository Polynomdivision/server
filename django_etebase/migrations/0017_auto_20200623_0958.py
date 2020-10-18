# Generated by Django 3.0.3 on 2020-06-23 09:58

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('django_etebase', '0016_auto_20200623_0820'),
    ]

    operations = [
        migrations.AlterField(
            model_name='collection',
            name='main_item',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='parent', to='django_etebase.CollectionItem'),
        ),
        migrations.AlterField(
            model_name='collectionitem',
            name='uid',
            field=models.CharField(db_index=True, max_length=43, validators=[django.core.validators.RegexValidator(message='Not a valid UID', regex='^[a-zA-Z0-9]*$')]),
        ),
    ]
