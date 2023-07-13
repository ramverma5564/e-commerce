from django.urls import path
from .views import (
    UserRegistrationView,
    EmailVerificationView,
    UserLoginView,
    UserLogoutView,
    PasswordResetView,
    UserProfileView,
    ChangePasswordView
)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('email-verification/<str:token>/<int:uid>/',
         EmailVerificationView.as_view(), name='email-verification'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
