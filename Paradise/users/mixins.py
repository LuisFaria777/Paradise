from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from urllib.parse import urlencode
import six
import string
import random
import phonenumbers
import pycountry
from twilio.rest import Client as TwilioClient
from .models import UserToken

def FormErrors(*args):
    """
    Processa erros de formulário e retorna como uma string de texto.

    Args:
        *args: Instâncias de formulários Django.

    Returns:
        str: Mensagens de erro concatenadas.
    """
    message = ""
    for f in args:
        if f.errors:
            message = f.errors.as_text()
    return message

def RedirectParams(**kwargs):
    """
    Redireciona usuários para uma URL específica, anexando parâmetros à query string.

    Args:
        **kwargs: url (str), params (dict).

    Returns:
        HttpResponse: Resposta de redirecionamento com parâmetros anexados.
    """
    url = kwargs.get("url")
    params = kwargs.get("params")
    response = redirect(url)
    if params:
        query_string = urlencode(params)
        response['Location'] += '?' + query_string
    return response

class TokenGenerator(PasswordResetTokenGenerator):
    """
    Gera um token usado para verificação de e-mail e redefinição de senha.
    """

    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) +
            six.text_type(timestamp) +
            six.text_type(user.is_active)
        )

class CreateEmail:
    """
    Classe para criar e enviar e-mails utilizando uma conta de e-mail específica.

    Args:
        request (HttpRequest): Requisição HTTP para obter informações do usuário.
        email_account (str): Conta de e-mail a ser usada.
        subject (str): Assunto do e-mail.
        email (str): Endereço de e-mail do destinatário.
        template (str): Template HTML para renderizar o e-mail.
        context (dict): Contexto para o template.
        cc_email (str): E-mail em cópia.
        token (str): Token para verificação.
        url_safe (str): URL segura para verificação.
    """

    def __init__(self, request, *args, **kwargs):
        self.email_account = kwargs.get("email_account")
        self.subject = kwargs.get("subject", "")
        self.email = kwargs.get("email")
        self.template = kwargs.get("template")
        self.context = kwargs.get("context")
        self.cc_email = kwargs.get("cc_email")
        self.token = kwargs.get("token")
        self.url_safe = kwargs.get("url_safe")

        domain = settings.CURRENT_SITE
        context = {
            "user": request.user,
            "domain": domain,
        }

        if self.token:
            context["token"] = self.token

        if self.url_safe:
            context["url_safe"] = self.url_safe

        email_accounts = {
            "donotreply": {
                'name': settings.EMAIL_HOST_USER,
                'password': settings.DONOT_REPLY_EMAIL_PASSWORD,
                'from': settings.EMAIL_HOST_USER,
                'display_name': settings.DISPLAY_NAME},
        }

        html_content = render_to_string(self.template, context)
        text_content = strip_tags(html_content)

        with get_connection(
                host=settings.EMAIL_HOST,
                port=settings.EMAIL_PORT,
                username=email_accounts[self.email_account]["name"],
                password=email_accounts[self.email_account]["password"],
                use_tls=settings.EMAIL_USE_TLS,
        ) as connection:
            msg = EmailMultiAlternatives(
                self.subject,
                text_content,
                f'{email_accounts[self.email_account]["display_name"]} <{email_accounts[self.email_account]["from"]}>',
                [self.email],
                cc=[self.cc_email],
                connection=connection)
            msg.attach_alternative(html_content, "text/html")
            msg.send()

class CreateSMS:
    """
    Classe para enviar SMS utilizando uma conta Twilio.

    Args:
        number (str): Número de telefone do destinatário.
        message (str): Mensagem de texto a ser enviada.
    """

    def __init__(self, **kwargs):
        self.number = kwargs.get("number")
        self.message = kwargs.get("message")

        sid = settings.TWILIO_ACC_SID
        token = settings.TWILIO_AUTH_TOKEN
        twilio_number = settings.TWILIO_NUMBER

        client = TwilioClient(sid, token)

        client.messages.create(
            body=self.message,
            from_=twilio_number,
            to=self.number
        )

class ActivateTwoStep:
    """
    Classe para gerar e enviar um código de verificação por SMS para autenticação em duas etapas.

    Args:
        user (User): Instância do usuário para o qual o código será gerado.
        token (str): Token para verificação.
    """

    def __init__(self, **kwargs):
        self.user = kwargs.get("user")
        self.token = kwargs.get("token")

        size = 6
        chars = string.digits
        code = ''.join(random.choice(chars) for _ in range(size))

        ut = UserToken.objects.create(
            user=self.user,
            token=self.token,
            two_step_code=code,
            is_sms=True
        )

        # Acessa o país do perfil associado ao usuário
        profile = self.user.profile  # Acessa o perfil do usuário
        country_code = pycountry.countries.get(alpha_2=profile.country).alpha_2  # Acessa o código do país
        number_object = phonenumbers.parse(self.user.phone_number, country_code)
        phone_number = f'+{number_object.country_code}{number_object.national_number}'

        send_sms = CreateSMS(
            number=phone_number,
            message=f'Seu código de verificação é: {code}'
        )
