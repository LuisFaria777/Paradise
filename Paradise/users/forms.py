from .models import User, Profile, UserToken
from django import forms
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import gettext_lazy as _
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, SetPasswordForm, PasswordResetForm
from .choices import COUNTRIES
from django.core.validators import RegexValidator
from django.contrib.sites.shortcuts import get_current_site
from validate_docbr import CPF
import logging
from .models import OtpToken
logger = logging.getLogger(__name__)

UserModel = get_user_model()



######### REGISTRO DO USUARIO ##########
### 1. Formulário para CPF ###

class CPFForm(forms.Form):
    cpf = forms.CharField(
        max_length=14, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'CPF..'})
    )

    def clean_cpf(self):
        cpf = self.cleaned_data.get('cpf')
        cpf_validator = CPF()
        if not cpf_validator.validate(cpf):
            raise forms.ValidationError("O CPF inserido não é válido.")
        if User.objects.filter(cpf=cpf).exists():
            raise forms.ValidationError("Já existe um usuário com este CPF.")
        return cpf


### 2. Formulário para Nome, Sobrenome, Email e Confirmação do Email ###

class NameEmailForm(forms.Form):
    first_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Nome..'})
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Sobrenome..'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'Email..'})
    )
    confirm_email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'Confirme seu Email..'})
    )

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")
        confirm_email = cleaned_data.get("confirm_email")

        if email != confirm_email:
            raise forms.ValidationError("Os emails não coincidem.")

        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Já existe um usuário com este email.")

        return cleaned_data


### 3. Formulário para Verificação do Email por Código OTP ###

class EmailVerificationForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Código OTP..'}),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(EmailVerificationForm, self).__init__(*args, **kwargs)

    def clean_otp_code(self):
        otp_code = self.cleaned_data.get('otp_code')
        # Verifica se o OTP é válido
        if not OtpToken.check_otp(self.user, otp_code):
            raise forms.ValidationError("Código OTP inválido.")
        return otp_code


### 4. Formulário para Captura do Número de Celular ###

class PhoneNumberForm(forms.Form):
    phone_number = forms.CharField(
        max_length=15,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Número de Celular..'}),
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="O número de telefone deve estar no formato: '+999999999'."
        )]
    )

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if User.objects.filter(phone_number=phone_number).exists():
            raise forms.ValidationError("Já existe um usuário com este número de telefone.")
        return phone_number


### 5. Formulário para Verificação de SMS por Código OTP ###

class SMSVerificationForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Código OTP..'}),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(SMSVerificationForm, self).__init__(*args, **kwargs)

    def clean_otp_code(self):
        otp_code = self.cleaned_data.get('otp_code')
        if not OtpToken.check_otp(self.user, otp_code):
            raise forms.ValidationError("Código OTP inválido.")
        return otp_code


### 6. Formulário para Captura da Data de Nascimento ###

class DateOfBirthForm(forms.Form):
    date_of_birth = forms.DateField(
        required=True,
        widget=forms.DateInput(attrs={'placeholder': 'Data de Nascimento..', 'type': 'date'}),
    )

    def clean_date_of_birth(self):
        dob = self.cleaned_data.get('date_of_birth')
        # Validações adicionais se necessário
        return dob


### 7. Formulário para Captura e Confirmação de Senha ###

class PasswordForm(forms.Form):
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Senha..', 'class': 'password'}),
        validators=[
            RegexValidator(
                regex=r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$',
                message="A senha deve ter pelo menos 8 caracteres, incluir pelo menos um dígito e uma letra maiúscula."
            )
        ]
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirme a Senha..', 'class': 'password'})
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("As senhas não coincidem.")
        return cleaned_data














################################################################################

















class OtpForm(forms.Form):
    otp_code = forms.CharField(max_length=6, required=True)

class RegisterForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Your first name..'})
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Your last name..'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': '*Email..'})
    )
    telephone = forms.CharField(
        max_length=15, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Telephone..'}),
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$', 
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )]
    )
    cpf = forms.CharField(
        max_length=14, 
        required=True,
        widget=forms.TextInput(attrs={'placeholder': '*CPF..'})
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '*Password..', 
            'class': 'password'
        }),
        validators=[
            RegexValidator(
                regex=r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$',
                message="Password must be at least 8 characters long, contain at least one digit, and one uppercase letter."
            )
        ]
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '*Confirm Password..', 
            'class': 'password'
        })
    )

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'telephone', 'cpf', 'username', 'password1', 'password2')

    def clean_cpf(self):
        cpf = self.cleaned_data.get('cpf')
        cpf_validator = CPF()
        if not cpf_validator.validate(cpf):
            raise forms.ValidationError("The CPF entered is not valid.")
        if User.objects.filter(cpf=cpf).exists():
            raise forms.ValidationError("A user with this CPF already exists.")
        return cpf

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

class PasswordResetForm(forms.Form):
    email = forms.EmailField(
        label=_("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        try:
            subject = loader.render_to_string(subject_template_name, context)
            subject = "".join(subject.splitlines())
            body = loader.render_to_string(email_template_name, context)

            email_message = EmailMultiAlternatives(subject, body, from_email, [to_email])
            if html_email_template_name is not None:
                html_email = loader.render_to_string(html_email_template_name, context)
                email_message.attach_alternative(html_email, "text/html")

            email_message.send()
            logger.info(f"Email successfully sent to: {to_email}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")

    def get_users(self, email):
        email_field_name = UserModel.get_email_field_name()
        active_users = UserModel._default_manager.filter(
            **{
                "%s__iexact" % email_field_name: email,
                "is_active": True,
                "is_email_verified": True,
            }
        )
        return (
            u
            for u in active_users
            if u.has_usable_password()
            and email.lower() == getattr(u, email_field_name).lower()
        )

    def save(
        self,
        domain_override=None,
        subject_template_name="registration/password_reset_subject.txt",
        email_template_name="registration/password_reset_email.html",
        use_https=False,
        token_generator=default_token_generator,
        from_email=None,
        request=None,
        html_email_template_name=None,
        extra_email_context=None,
    ):
        email = self.cleaned_data["email"]
        if not domain_override:
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = domain_override
        email_field_name = UserModel.get_email_field_name()
        for user in self.get_users(email):
            user_email = getattr(user, email_field_name)
            context = {
                "email": user_email,
                "domain": domain,
                "site_name": site_name,
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "user": user,
                "token": token_generator.make_token(user),
                "protocol": "https" if use_https else "http",
                **(extra_email_context or {}),
            }
            self.send_mail(
                subject_template_name,
                email_template_name,
                context,
                from_email,
                user_email,
                html_email_template_name=html_email_template_name,
            )

class AuthForm(AuthenticationForm):
    email = forms.EmailField(
        max_length=254, 
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': '*Email..'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': '*Password..', 'class': 'password'})
    )

    class Meta:
        model = User
        fields = ('email', 'password',)

    def confirm_login_allowed(self, user):
        if not user.is_superuser:
            if not user.is_email_verified:
                raise forms.ValidationError(
                    "Your email address is not verified.",
                    code='email_not_verified',
                )
            if not user.is_phone_verified:
                raise forms.ValidationError(
                    "Your phone number is not verified.",
                    code='phone_not_verified',
                )

class ProfileForm(forms.ModelForm):
    telephone = forms.CharField(max_length=15, required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Telephone..'}),
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")])
    address = forms.CharField(max_length=100, required=True, 
        widget=forms.TextInput(attrs={'placeholder': '*First line of address..'}))
    town = forms.CharField(max_length=100, required=True, 
        widget=forms.TextInput(attrs={'placeholder': '*Town or City..'}))
    county = forms.CharField(max_length=100, required=True, 
        widget=forms.TextInput(attrs={'placeholder': '*County..'}))
    post_code = forms.CharField(max_length=8, required=True, 
        widget=forms.TextInput(attrs={'placeholder': '*Postal Code..'}))
    country = forms.CharField(max_length=100, required=True, 
        widget=forms.Select(attrs={"class": "selection"}, choices=COUNTRIES))

    class Meta:
        model = Profile
        fields = ('telephone', 'address', 'town', 'county', 'post_code', 'country')

class RequestPasswordForm(PasswordResetForm):
    email = forms.EmailField(max_length=254, required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Email..'}))

    class Meta:
        model = User
        fields = ('email',)

class ForgottenPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': '*Password..', 'class': 'password'}),
        validators=[
            RegexValidator(
                regex=r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
                message="Password must be at least 8 characters long, contain at least one digit, one uppercase letter, and one special character."
            )
        ]
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': '*Confirm Password..', 'class': 'password'})
    )

    class Meta:
        model = User
        fields = ('new_password1', 'new_password2')

class TwoStepForm(forms.ModelForm):
    two_step_code = forms.CharField(max_length=6, required=True,
        widget=forms.TextInput(attrs={'placeholder': '*Code..'}))

    class Meta:
        model = UserToken
        fields = ('two_step_code',)
