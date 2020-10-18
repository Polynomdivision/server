# Generated by Django 3.0.3 on 2020-08-04 12:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('django_etebase', '0024_auto_20200804_1209'),
    ]

    operations = [
        migrations.AlterField(
            model_name='collectionitemchunk',
            name='collection',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='chunks', to='django_etebase.Collection'),
        ),
        migrations.AlterUniqueTogether(
            name='collectionitemchunk',
            unique_together={('collection', 'uid')},
        ),
        migrations.RemoveField(
            model_name='collectionitemchunk',
            name='item',
        ),
    ]
