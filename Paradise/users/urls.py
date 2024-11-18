from django.contrib import admin
from .views import *
from django.urls import path, include
from django.contrib.auth import views as auth_views
from .forms import PasswordResetForm
from . import views



urlpatterns = [
    path('', home, name='index'),
    path('index/', home, name='index'),
    path('login/' , auth_views.LoginView.as_view (template_name='login.html') , name="login_attempt"),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    path('register/cpf/', CPFView.as_view(), name='cpf'),
    path('register/name-email/', NameEmailView.as_view(), name='name_email'),
    path('register/email-verification/', EmailVerificationView.as_view(), name='email_verification'),
    path('register/phone-number/', PhoneNumberView.as_view(), name='phone_number'),
    path('register/sms-verification/', SMSVerificationView.as_view(), name='sms_verification'),
    path('register/date-of-birth/', DateOfBirthView.as_view(), name='date_of_birth'),
    path('register/password/', PasswordView.as_view(), name='password'),
    path('register/complete/', RegistrationCompleteView.as_view(), name='registration_complete'),
    path('terms-of-service/', terms_of_service, name='terms_of_service'),
    
    path('token/' , token_send , name="token_send"),
    path('success/' , success , name='success'),
    path('verify/<auth_token>/' , verify , name="verify"),
    path('error/' , error_page , name="error"),
    
    path('password_reset/', auth_views.PasswordResetView.as_view(
    form_class=PasswordResetForm,
    template_name='registration/password_reset_form.html',
    email_template_name='registration/password_reset_email.html',
    subject_template_name='registration/password_reset_subject.txt',
    extra_context={
        'protocol': 'http',
    }
), name='password_reset'),

    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(
    template_name='registration/password_reset_done.html'
), name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='registration/password_reset_confirm.html',
        success_url='/login/'
    ), name='password_reset_confirm'),

    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
    template_name='registration/password_reset_complete.html'
), name='password_reset_complete'),

    path('password_change/', auth_views.PasswordChangeView.as_view(
        template_name='registration/password_change_form.html',
        success_url='/password_change_done/'
    ), name='password_change'),

    # URL para confirmação de alteração de senha
    path('password_change_done/', auth_views.PasswordChangeDoneView.as_view(
        template_name='registration/password_change_done.html',
    ), name='password_change_done'),

    path('terms-of-service/', views.terms_of_service, name='terms_of_service'),
    path('email-verification/', views.email_verification, name='email_verification'),
    path('send_otp/', views.sendOtp.as_view(), name='sendotp'),
    path('email/', views.email, name="email"),
    path('account/', views.account, name="account"),
    path('verification/<uidb64>/<token>/', views.verification, name='verification'),
]



