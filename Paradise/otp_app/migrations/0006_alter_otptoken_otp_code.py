# Generated by Django 5.1 on 2024-08-16 10:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otp_app', '0005_alter_otptoken_otp_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otptoken',
            name='otp_code',
            field=models.CharField(default='412f13', max_length=6),
        ),
    ]
