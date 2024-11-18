from django.core.mail import send_mail
from django.conf import settings
from .models import OtpToken
import random
from twilio.rest import Client
from django.utils import timezone

def send_mail_otp(user):
    otp_code = str(random.randint(100000, 999999))
    OtpToken.objects.create(user=user, otp_code=otp_code, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
    subject = "Your OTP Code"
    message = f"Your OTP code is {otp_code}. It expires in 5 minutes."
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)

def send_sms_verification(user):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    otp_code = str(random.randint(100000, 999999))
    OtpToken.objects.create(user=user, otp_code=otp_code, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
    message = client.messages.create(
        body=f"Your OTP code is {otp_code}. It expires in 5 minutes.",
        from_=settings.TWILIO_PHONE_NUMBER,
        to=user.phone_number
    )
    return otp_code

def check_otp(user, otp_code):
    try:
        otp = OtpToken.objects.get(user=user, otp_code=otp_code)
        if otp.otp_expires_at > timezone.now():
            return True
        else:
            return False
    except OtpToken.DoesNotExist:
        return False
