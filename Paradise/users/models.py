from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.exceptions import ValidationError
from decimal import Decimal
from django.utils.translation import gettext_lazy as _
from django.conf import settings
import uuid
from django.utils import timezone
from django_countries.fields import CountryField

from .choices import COUNTRIES

class UserManager(BaseUserManager):
    def create_user(self, email, cpf, password=None, **extra_fields):
        if not email:
            raise ValueError('O usuário deve ter um endereço de email')
        if not cpf:
            raise ValueError('O usuário deve ter um CPF')

        email = self.normalize_email(email)
        user = self.model(email=email, cpf=cpf, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, cpf, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser deve ter is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser deve ter is_superuser=True.')

        return self.create_user(email, cpf, password, **extra_fields)

class User(AbstractUser):
    cpf = models.CharField(max_length=14, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'cpf', 'phone_number']

    objects = UserManager()

    def __str__(self):
        return self.email

    def clean(self):
        super().clean()

        # Verifica se já existe um usuário com o mesmo CPF
        if User.objects.filter(cpf=self.cpf).exclude(pk=self.pk).exists():
            raise ValidationError({'cpf': _('Este CPF já está cadastrado. Por favor, insira outro CPF.')})

        # Verifica se já existe um usuário com o mesmo email
        if User.objects.filter(email=self.email).exclude(pk=self.pk).exists():
            raise ValidationError({'email': _('Este email já está cadastrado. Por favor, insira outro email.')})

    def save(self, *args, **kwargs):
        self.cpf = self.cpf.replace('.', '').replace('-', '')
        self.clean()
        super().save(*args, **kwargs)

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    birthday = models.DateField(null=True, blank=True)
    address = models.CharField(verbose_name="Address", max_length=100, null=True, blank=True)
    town = models.CharField(verbose_name="Town/City", max_length=100, null=True, blank=True)
    county = models.CharField(verbose_name="County", max_length=100, null=True, blank=True)
    post_code = models.CharField(verbose_name="Post Code", max_length=8, null=True, blank=True)
    country = CountryField(verbose_name="Country", null=True, blank=True)
    updated = models.DateTimeField(auto_now=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    auth_token = models.UUIDField(default=uuid.uuid4, editable=False)
    is_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    two_step_active = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.user.email

class OtpToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=6)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"OTP for {self.user.email} - Expires at {self.otp_expires_at}"

    @classmethod
    def check_otp(cls, user, otp_code):
        try:
            otp = cls.objects.get(user=user, otp_code=otp_code)
            if otp.otp_expires_at > timezone.now():
                return True
            else:
                return False
        except cls.DoesNotExist:
            return False

class UserToken(models.Model):
    updated = models.DateTimeField(auto_now=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, null=True, blank=True)
    two_step_code = models.CharField(max_length=6, null=True, blank=True)
    
    # used to change the object type
    is_email = models.BooleanField(default=False)
    is_password = models.BooleanField(default=False)
    is_sms = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.user}'
