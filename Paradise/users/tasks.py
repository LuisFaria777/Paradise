from twilio.rest import Client
from django.core.mail import send_mail
from django.conf import settings

def send_verification_email(email, subject, content, is_html=False):
    sender_email = settings.DEFAULT_FROM_EMAIL
    receiver = [email]

    if is_html:
        send_mail(
            subject,
            '',
            sender_email,
            receiver,
            html_message=content,
            fail_silently=False,
        )
    else:
        send_mail(
            subject,
            content,
            sender_email,
            receiver,
            fail_silently=False,
        )

def send_verification_sms(phone_number, otp_code):
    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=f"Your verification code is {otp_code}. It expires in 5 minutes.",
        from_=settings.TWILIO_PHONE_NUMBER,
        to=phone_number
    )

    return message.sid
