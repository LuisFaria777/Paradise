from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import OtpToken
from django.core.mail import send_mail
from django.conf import settings

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_token(sender, instance, created, **kwargs):
    if created:
        if instance.is_superuser:
            return
        
        # Cria o token OTP e salva o código gerado no modelo
        otp = OtpToken.objects.create(user=instance, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
        
        # Desativa a conta até que a verificação por email seja concluída
        instance.is_active = False
        instance.save()

        # Envia o email com o OTP
        subject = "Email Verification"
        message = f"""
            Hi {instance.email}, here is your OTP {otp.otp_code} 
            It expires in 5 minutes. Use the URL below to redirect back to the website:
            http://127.0.0.1:8000/verify-email/{instance.email}
        """
        sender_email = "clintonmatics@gmail.com"
        receiver = [instance.email, ]

        send_mail(
            subject,
            message,
            sender_email,
            receiver,
            fail_silently=False,
        )
