from django.urls import reverse_lazy
from django.views.generic import CreateView
from django.shortcuts import redirect, render, reverse
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from rest_framework.views import APIView
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from .tasks import send_verification_email
import uuid
import json
import random
import os
import datetime
from datetime import timedelta
from twilio.rest import Client
from dotenv import load_dotenv
load_dotenv()
import logging
logger = logging.getLogger(__name__)
from django.utils.crypto import get_random_string

from django.core.exceptions import ValidationError
from django.views.generic import FormView
from django.shortcuts import redirect
from .forms import CPFForm, NameEmailForm, EmailVerificationForm, PhoneNumberForm, SMSVerificationForm, DateOfBirthForm, PasswordForm
from .services import send_mail_otp, send_sms_verification
from .models import OtpToken
from django.views.generic import TemplateView



from .models import (
    User, 
    Profile,
	UserToken,
)

from .mixins import (
	FormErrors,
	RedirectParams,
	TokenGenerator,
	ActivateTwoStep,
	CreateEmail
)

from .forms import (

	ProfileForm,  # Substitua UserProfileForm por ProfileForm
	ForgottenPasswordForm,
	AuthForm,
	RequestPasswordForm,
	TwoStepForm,
    RegisterForm,
)




class CPFView(FormView):
    template_name = 'register/cpf.html'
    form_class = CPFForm

    def form_valid(self, form):
        self.request.session['cpf'] = form.cleaned_data['cpf']
        return redirect('name_email')


class NameEmailView(FormView):
    template_name = 'register/name_email.html'
    form_class = NameEmailForm

    def form_valid(self, form):
        self.request.session['first_name'] = form.cleaned_data['first_name']
        self.request.session['last_name'] = form.cleaned_data['last_name']
        self.request.session['email'] = form.cleaned_data['email']

        # Envia o OTP para o email
        user = User(
            email=self.request.session['email'],
            first_name=self.request.session['first_name'],
            last_name=self.request.session['last_name'],
            cpf=self.request.session['cpf'],
        )
        user.set_unusable_password()
        user.save()
        send_mail_otp(user)

        return redirect('email_verification')


class EmailVerificationView(FormView):
    template_name = 'register/email_verification.html'
    form_class = EmailVerificationForm

    def form_valid(self, form):
        otp_code = form.cleaned_data['otp_code']
        if OtpToken.check_otp(self.request.user, otp_code):
            return redirect('phone_number')
        else:
            form.add_error('otp_code', 'Código OTP inválido')
            return self.form_invalid(form)


class PhoneNumberView(FormView):
    template_name = 'register/phone_number.html'
    form_class = PhoneNumberForm

    def form_valid(self, form):
        self.request.session['phone_number'] = form.cleaned_data['phone_number']

        # Envia o OTP para o número de celular
        send_sms_verification(self.request.session['phone_number'])

        return redirect('sms_verification')


class SMSVerificationView(FormView):
    template_name = 'register/sms_verification.html'
    form_class = SMSVerificationForm

    def form_valid(self, form):
        otp_code = form.cleaned_data['otp_code']
        if OtpToken.check_otp(self.request.user, otp_code):
            return redirect('date_of_birth')
        else:
            form.add_error('otp_code', 'Código OTP inválido')
            return self.form_invalid(form)


class DateOfBirthView(FormView):
    template_name = 'register/date_of_birth.html'
    form_class = DateOfBirthForm

    def form_valid(self, form):
        self.request.session['date_of_birth'] = form.cleaned_data['date_of_birth']
        return redirect('password')


class PasswordView(FormView):
    template_name = 'register/password.html'
    form_class = PasswordForm

    def form_valid(self, form):
        user = User.objects.create(
            cpf=self.request.session['cpf'],
            first_name=self.request.session['first_name'],
            last_name=self.request.session['last_name'],
            email=self.request.session['email'],
            phone_number=self.request.session['phone_number'],
            date_of_birth=self.request.session['date_of_birth'],
            is_active=True
        )
        user.set_password(form.cleaned_data['password1'])
        user.save()

        # Limpa a sessão após o registro
        self.request.session.flush()

        return redirect('registration_complete')


class RegistrationCompleteView(FormView):
    template_name = 'register/registration_complete.html'
    form_class = None


def home(request):
    return render(request, 'home.html')


def terms_of_service(request):
    return render(request, 'terms_of_service.html')
























#########################################################################################































def user_registration(request):
    if request.user.is_authenticated:
        return redirect(reverse_lazy('account'))

    form = RegisterForm() if request.method == 'GET' else RegisterForm(request.POST)
    p_form = ProfileForm() if request.method == 'GET' else ProfileForm(request.POST)  # Alterado de up_form para p_form

    result = None
    message = "Something went wrong. Please check and try again"

    if settings.TWILIO_AUTH_TOKEN == "XXX":
        return JsonResponse({"result": "error", "message": "Twilio is not configured."})

    if request.method == 'POST':
        if form.is_valid() and p_form.is_valid() and p_form.is_valid():  # Alterado para p_form
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            auth_token = str(uuid.uuid4())
            profile = Profile.objects.create(user=user, auth_token=auth_token)
            profile.save()

            send_mail_after_registration(user.email, auth_token)

            token = TokenGenerator()
            make_token = token.make_token(user)
            url_safe = urlsafe_base64_encode(force_bytes(user.pk))

            sms_code = ActivateTwoStep(user=user, token=make_token)

            # Redireciona para a página de verificação de email
            return redirect(reverse('email_verification'))

        else:
            message = FormErrors(form, p_form, p_form)
            result = "error"
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({"result": result, "message": message})

            messages.error(request, message)

    context = {'form': form, 'u_form': p_form, 'p_form': p_form, 'result': result}  # Alterado para p_form
    return render(request, 'register.html', context)

@login_required
def email_verification(request):
    result = "error"
    message = "Something went wrong. Please check and try again"

    # Verificação de email
    if request.method == "POST":
        try:
            user = request.user

            # Gera um novo token
            token_generator = TokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Cria ou atualiza o token de verificação de email
            ut, created = UserToken.objects.get_or_create(user=user, defaults={'token': token, 'is_email': True})
            if not created:
                ut.token = token
                ut.save()

            # Envia o e-mail de verificação
            verification_link = f"{request.scheme}://{request.get_host()}/verification/{uid}/{token}/"
            email_subject = "Verify your email"
            email_content = f"Please click the link to verify your email: {verification_link}"
            send_verification_email(user.email, email_subject, email_content)

            result = "perfect"
            message = "We have sent you an email to verify your account. Please check your inbox."
            status_code = 200

        except Exception as e:
            message = f"An error occurred: {str(e)}"
            status_code = 500

        return JsonResponse({"result": result, "message": message}, status=status_code)

    # Página de verificação de email
    context = {}
    return render(request, "email_verification.html", context)

def user_authentication(request):
    # Redirecionar se o usuário já estiver autenticado
    if request.user.is_authenticated:
        return redirect(reverse_lazy('account'))

    form = AuthForm() if request.method == 'GET' else AuthForm(request.POST)
    result = "error"
    message = "Something went wrong. Please check and try again"

    if request.method == 'POST':
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)

            if user is not None:
                # Verificar se o usuário está verificado
                if not user.is_email_verified:  # Checando diretamente o campo de verificação de email
                    messages.error(request, 'User is not verified. Check your email.')
                    return redirect('/login')

                # Verificação de dois fatores
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    if user.two_step_active:  # Checando diretamente o campo de verificação de dois fatores
                        token = TokenGenerator()
                        make_token = token.make_token(user)
                        url_safe = urlsafe_base64_encode(force_bytes(user.pk))

                        sms_code = ActivateTwoStep(user=user, token=make_token)
                        message = 'We have sent you an SMS'
                        result = "perfect"
                        return HttpResponse(
                            json.dumps({"result": result, "message": message, "url_safe": url_safe, "token": make_token}),
                            content_type="application/json"
                        )
                
                # Login do usuário
                login(request, user)
                return redirect('/')
            else:
                messages.error(request, 'Wrong email or password.')
        else:
            messages.error(request, 'Invalid form data.')
            message = FormErrors(form)

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return HttpResponse(
                json.dumps({"result": result, "message": message}),
                content_type="application/json"
            )

    # Contexto para renderização
    context = {'form': form}
    token_error = request.GET.get("token_error", None)
    context["token_error"] = "true" if token_error else "false"

    return render(request, 'login.html', context)

@login_required
def account(request):
    if request.method == "POST":
        toggle = request.POST.get("toggle")
        if toggle in ["on", "off"]:
            return handle_two_step_toggle(request, toggle)
        return invalid_toggle_response()

    context = {
        "verified": "true" if request.GET.get("verified", None) else "false"
    }

    return render(request, 'account.html', context)

def handle_two_step_toggle(request, toggle):
    user = request.user
    user.two_step_active = (toggle == "on")

    try:
        user.save()
        return success_response()
    except Exception as e:
        return error_response(f"An error occurred while saving your preferences: {str(e)}")

def invalid_toggle_response():
    return HttpResponse(
        json.dumps({"status": "error", "message": "Invalid toggle value. Please use 'on' or 'off'."}),
        content_type="application/json"
    )

def success_response():
    return HttpResponse(
        json.dumps({"status": "success", "message": "Your two-step verification preference has been updated."}),
        content_type="application/json"
    )

def error_response(message):
    return HttpResponse(
        json.dumps({"status": "error", "message": message}),
        content_type="application/json"
    )

@login_required
@csrf_protect
def email(request):
    result = "error"
    message = "Something went wrong. Please check and try again"

    if request.method == "POST":
        csrf_token = get_token(request)  # Garantir que o CSRF token está presente
        try:
            user = request.user
            # Cria um novo token
            token = TokenGenerator()
            make_token = token.make_token(user)
            url_safe = urlsafe_base64_encode(force_bytes(user.pk))

            # Cria um objeto UserToken para armazenar o token
            ut = UserToken.objects.create(
                user=user,
                token=make_token,
                is_email=True
            )
            
            # Envia o e-mail de verificação
            CreateEmail(
                request,
                email_account="donotreply",
                subject='Verify your email',
                email=user.username,
                cc=[],
                template="verification_email.html",
                token=make_token,
                url_safe=url_safe
            )

            result = "perfect"
            message = "We have sent you an email to verify"
            status_code = 200

        except Exception as e:
            logger.error(f"An error occurred while sending verification email: {str(e)}")  # Logando o erro
            message = f"An error occurred: {str(e)}"
            status_code = 500
        
        return JsonResponse({"result": result, "message": message}, status=status_code)

    # Tratar requisições não-POST
    return JsonResponse({"result": result, "message": message}, status=400)

def validate_token(user, token, token_type):
    try:
        ut = UserToken.objects.get(user=user, token=token, is_active=True)
        if token_type == 'email' and ut.is_email:
            return ut
        elif token_type == 'password' and ut.is_password:
            return ut
        elif token_type == '2fa' and ut.two_step_code:
            return ut
    except UserToken.DoesNotExist:
        return None

def deactivate_token(ut):
    ut.is_active = False
    ut.save()

def is_two_step_code_valid(ut):
    # Exemplo: o código de duas etapas é válido por 5 minutos
    validity_period = datetime.timedelta(minutes=5)
    return (datetime.datetime.now() - ut.created_at) <= validity_period

@login_required
def verification(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        # Redirecionar com erro de token
        return RedirectParams(url='login', params={"token_error": "true"})

    ut = validate_token(user, token, 'email') or validate_token(user, token, 'password') or validate_token(user, token, '2fa')
    if not ut:
        # Redirecionar com erro de token
        return RedirectParams(url='login', params={"token_error": "true"})

    # Se o token for de verificação de e-mail
    if ut.is_email:
        deactivate_token(ut)
        user.is_email_verified = True  # Marcando como verificado diretamente no user
        user.save()

        login(request, user)
        return RedirectParams(url='account', params={"verified": "true"})
    
    # Se o token for de redefinição de senha
    elif ut.is_password:
        fp_form = ForgottenPasswordForm(user=user)
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' and request.method == "POST":
            fp_form = ForgottenPasswordForm(data=request.POST, user=user)
            result = "error"
            message = "Something went wrong. Please check and try again"
            
            if fp_form.is_valid():
                fp_form.save()
                deactivate_token(ut)
                login(request, user)
                result = "perfect"
                message = "Your password has been updated"
            else:
                message = FormErrors(fp_form)

            return JsonResponse({"result": result, "message": message}, status=200 if result == "perfect" else 400)

        context = {'fp_form': fp_form, "uidb64": uidb64, "token": token}
        return render(request, 'verification.html', context)
    
    # Se o token for de verificação de dois fatores (2FA)
    elif ut.two_step_code:
        if not is_two_step_code_valid(ut):
            message = "The 2FA code has expired. Please request a new one."
            return JsonResponse({"result": "error", "message": message}, status=400)

        ts_form = TwoStepForm()
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' and request.method == "POST":
            ts_form = TwoStepForm(data=request.POST)
            result = "error"
            message = "Something went wrong. Please check and try again"

            if ts_form.is_valid():
                two_step_code = ts_form.cleaned_data.get('two_step_code')

                if two_step_code == ut.two_step_code:
                    user.is_active = True
                    user.save()
                    deactivate_token(ut)
                    login(request, user)
                    result = "perfect"
                    message = "Success! You are now signed in"
                else:
                    message = "Incorrect code, please try again."
            else:
                message = FormErrors(ts_form)

            return JsonResponse({"result": result, "message": message}, status=200 if result == "perfect" else 400)

        context = {'ts_form': ts_form, "uidb64": uidb64, "token": token}
        return render(request, 'two_step_verification.html', context)

    # Se algo der errado, redirecionar com erro de token
    return RedirectParams(url='login', params={"token_error": "true"})

class sendOtp(APIView):
    def generateOTP(self):
        return random.randrange(100000, 999999)
    
    def post(self, request):
        try:
            phone_number = os.getenv("PHONE_NUMBER")
            account_sid = os.getenv("TWILIO_ACCOUNT_SID")
            auth_token = os.getenv("TWILIO_AUTH_TOKEN")
            number = request.data['number']
            client = Client(account_sid, auth_token)
            otp = self.generateOTP()
            
            body = "Your OTP is " + str(otp)
            message = client.messages.create(from_=phone_number, body=body, to=number)
            
            if message.sid:
                logger.info("OTP sent successfully")
                return JsonResponse({"success": True})
            else:
                logger.warning("Failed to send OTP")
                return JsonResponse({"success": False})

        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            return JsonResponse({"success": False, "error": str(e)}, status=500)

def verify(request, auth_token):
    try:
        # Buscar o perfil do usuário com o token fornecido
        profile_obj = Profile.objects.filter(auth_token=auth_token).first()
        if profile_obj:
            # Verificar se o token já foi utilizado
            if profile_obj.is_verified:
                messages.success(request, 'Your account is already verified.')
                return redirect('/login')

            # Verificar se o token expirou
            token_age = datetime.datetime.now() - profile_obj.timestamp
            if token_age > timedelta(hours=24):
                messages.error(request, 'Verification token has expired. Please request a new one.')
                return redirect('/error')

            # Verificar se o token é válido após um determinado número de tentativas
            if profile_obj.is_verified:
                messages.error(request, 'Too many verification attempts. Please request a new token.')
                return redirect('/error')

            # Marcar o perfil como verificado e ativar a conta do usuário
            profile_obj.is_verified = True
            profile_obj.user.is_active = True
            profile_obj.user.save()
            profile_obj.save()

            messages.success(request, 'Your account has been verified.')
            return redirect('/login')

        else:
            messages.error(request, 'Invalid token. Please contact support.')
            return redirect('/error')
    
    except Exception as e:
        logger.error(f"Error during verification: {str(e)}")
        messages.error(request, 'An error occurred during verification. Please try again.')
        return redirect('/')

def send_mail_after_registration(email, token):
    try:
        subject = 'Verify Your Account'
        verification_link = f"{settings.SITE_URL}/verify/{token}"
        
        # Template HTML para melhorar a experiência do usuário
        html_message = f'''
        <html>
        <body>
            <h2>Welcome to Our Platform</h2>
            <p>Hi,</p>
            <p>Thank you for registering on our platform. Please click the link below to verify your account:</p>
            <p><a href="{verification_link}">Verify Your Account</a></p>
            <p>If you did not request this verification, please ignore this email.</p>
            <p>Best regards,<br>Our Platform Team</p>
        </body>
        </html>
        '''

        send_verification_email(email, subject, html_message, is_html=True)

        logger.info(f"Verification email sent to {email}")
    
    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {str(e)}")

def index(request):
    return render(request, "index.html")

def error_page(request):
    return render(request, 'error.html', status=404)

class UserLogin(LoginView):
    def get_success_url(self):
        return reverse_lazy("user_profile")

    def form_invalid(self, form):
        logger.warning(f"Failed login attempt with data: {form.cleaned_data}")
        messages.error(self.request, "Invalid login credentials. Please try again.")
        return super().form_invalid(form)

class UserLogout(LogoutView):
    def get(self, request, *args, **kwargs):
        messages.success(request, 'You have been logged out successfully.')
        return HttpResponseRedirect(reverse_lazy('login_attempt'))

def terms_of_service(request):
    return render(request, 'terms_of_service.html')

def success(request):
    return render(request, 'success.html')

def token_send(request):
    return render(request, 'token_send.html')

@login_required
def home(request):
    return render(request, 'home.html')

class CustomLogoutView(LogoutView):
    template_name = 'logout.html'

class UsuarioCreate(CreateView):
    model = User
    form_class = RegisterForm
    template_name = 'register.html'
    success_url = reverse_lazy('login_attempt')

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, 'Registration successful. Please check your email to verify your account.')
        logger.info(f"New user registered: {form.instance.email}")
        return response

    def form_invalid(self, form):
        messages.error(self.request, 'There were errors in your submission. Please correct them and try again.')
        logger.warning(f"Failed registration attempt with data: {form.cleaned_data}")
        return super().form_invalid(form)
