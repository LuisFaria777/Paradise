from django.urls import path
from app.views import UserProfile



urlpatterns = [
    path('accounts/profile/', UserProfile.as_view(), name='profile'),
    
]

