from django.contrib import admin
from django.utils import timezone
from .models import User, OtpToken, Profile, UserToken

@admin.register(OtpToken)
class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp_code', 'otp_created_at', 'otp_expires_at')
    search_fields = ('user__email', 'otp_code')
    ordering = ('otp_created_at',)
    list_filter = ('otp_expires_at',)  # Filtro lateral para expiração do OTP
    actions = ['expire_otps']

    def expire_otps(self, request, queryset):
        queryset.update(otp_expires_at=timezone.now())
        self.message_user(request, "Selected OTPs have been expired.")

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'user_email', 'timestamp')
    search_fields = ('user__email', 'user__first_name', 'user__last_name')
    ordering = ('timestamp',)
    list_filter = ('user__is_active',)  # Filtro lateral para o status ativo do usuário

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'

@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'token', 'timestamp')
    search_fields = ('user__email', 'token')
    ordering = ('timestamp',)
    list_filter = ('is_active',)  # Filtro lateral para tokens ativos

@admin.register(User)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'phone_number', 'is_staff', 'is_active')
    search_fields = ('email', 'first_name', 'last_name', 'cpf', 'phone_number')
    ordering = ('email',)
    list_filter = ('is_staff', 'is_active', 'is_email_verified', 'is_phone_verified')  # Filtros laterais para status de verificação
