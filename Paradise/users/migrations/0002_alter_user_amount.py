# Generated by Django 5.1 on 2024-08-17 13:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='amount',
            field=models.DecimalField(decimal_places=2, max_digits=15),
        ),
    ]
