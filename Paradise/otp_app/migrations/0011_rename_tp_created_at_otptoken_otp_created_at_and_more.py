# Generated by Django 5.1 on 2024-08-16 11:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otp_app', '0010_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.RenameField(
            model_name='otptoken',
            old_name='tp_created_at',
            new_name='otp_created_at',
        ),
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(max_length=6),
        ),
    ]
