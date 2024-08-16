from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from app.views import index

urlpatterns = [

    path('admin/', admin.site.urls),
    path("", include("otp_app.urls"))
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
