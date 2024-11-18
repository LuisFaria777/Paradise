# Generated by Django 5.0 on 2024-08-23 10:42

import django.db.models.deletion
import django_countries.fields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_profile'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='user',
            managers=[
            ],
        ),
        migrations.CreateModel(
            name='OtpToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp_code', models.CharField(max_length=6)),
                ('otp_created_at', models.DateTimeField(auto_now_add=True)),
                ('otp_expires_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otps', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('phone_number', models.CharField(max_length=15, unique=True)),
                ('address', models.CharField(blank=True, max_length=100, null=True, verbose_name='Address')),
                ('town', models.CharField(blank=True, max_length=100, null=True, verbose_name='Town/City')),
                ('county', models.CharField(blank=True, max_length=100, null=True, verbose_name='County')),
                ('post_code', models.CharField(blank=True, max_length=8, null=True, verbose_name='Post Code')),
                ('country', django_countries.fields.CountryField(blank=True, max_length=2, null=True, verbose_name='Country')),
                ('is_active', models.BooleanField(default=True)),
                ('email_verified', models.BooleanField(default=False)),
                ('two_step_active', models.BooleanField(default=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('token', models.CharField(blank=True, max_length=100, null=True)),
                ('two_step_code', models.CharField(blank=True, max_length=6, null=True)),
                ('is_email', models.BooleanField(default=False)),
                ('is_password', models.BooleanField(default=False)),
                ('is_sms', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]