from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import OtpToken, Profile
from django.conf import settings
from .tasks import send_verification_sms, send_verification_email
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_token(sender, instance, created, **kwargs):
    if created:
        try:
            if instance.is_superuser:
                return
            
            # Cria o token OTP e salva o código gerado no modelo
            otp = OtpToken.objects.create(user=instance, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
            
            # Desativa a conta até que a verificação por SMS e e-mail seja concluída
            instance.is_active = False
            instance.save()

            # Envia o SMS e o e-mail usando Twilio e Django
            send_verification_sms(instance.phone_number, otp.otp_code)
            send_verification_email(instance.email, otp.otp_code)

        except Exception as e:
            logger.error(f"Erro ao criar token ou enviar SMS/e-mail para {instance.email} ou {instance.phone_number}: {str(e)}")

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_profile(sender, instance, created, **kwargs):
    if created:
        # Cria um perfil para o usuário se ele for criado
        Profile.objects.create(user=instance)
    else:
        # Atualiza o perfil do usuário caso já exista
        instance.profile.save()
