from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from .views import *

app_name = 'authentication'

urlpatterns = [
    # Endpoints d'authentification
    path('register/', views.RegisterAPIView.as_view(), name='register'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Vérification d'email
    # path('verify-email-request/', views.EmailVerificationView.as_view(), name='verify_email_request'),
    # path('verify-email/<str:uidb64>/<str:token>/', views.EmailVerificationAPIView.as_view(), name='verify_email'),
    
    path('verify-email-request/', views.EmailVerificationRequestView.as_view(), name='verify_email_request'),
    path('verify-email/<str:uidb64>/<str:token>/', views.EmailVerificationView.as_view(), name='verify_email'),
    path('verify-email/', views.EmailVerificationAPIView.as_view(), name='api_verify_email'),

    # Réinitialisation de mot de passe
    path('password-reset-request/', views.PasswordResetView.as_view(), name='password_reset_request'),
    path(
        'password-reset-confirm/<uidb64>/<token>/',
        PasswordResetConfirmAPIView.as_view(),
        name='password_reset_confirm'
    ),
    path('change-password/', views.ChangePasswordAPIView.as_view(), name='change_password'),
    
    # Gestion du profil utilisateur
    path('profile/', views.UserProfileAPIView.as_view(), name='profile'),
    # path('profile/upload-picture/', views.ProfilePictureUploadView.as_view(), name='upload_profile_picture'),
    
    # MFA
    path('mfa/setup/', views.MFASetupView.as_view(), name='mfa_setup'),
    path('mfa/status/', views.MFAStatusAPIView.as_view(), name='mfa_status'),
    # path('mfa/disable/', views.MFAStatusSerializer.as_view(), name='mfa_disable'),
    
    # Gestion des sessions
    path('sessions/', views.UserSessionsAPIView.as_view(), name='sessions_list'),
    path('sessions/<uuid:session_id>/revoke/', views.RevokeSessionAPIView.as_view(), name='session_revoke'),
    
    # Historique d'activité
    path('activity-log/', views.UserActivitiesAPIView.as_view(), name='activity_log'),
    
    # Pages HTML pour les tests
    # path('', views.home_view, name='home'),
    path('login-page/', LoginView.as_view(), name='login_page'),
    path('register-page/', RegisterView.as_view(), name='register_page'),
    path('profile-page/', ProfileView.as_view(), name='profile_page'),
    path('password-reset-page/', PasswordResetView.as_view(), name='password_reset_page'),
    path('mfa-setup-page/', MFASetupView.as_view(), name='mfa_setup_page'),
    path('verifymail/<str:uidb64>/<str:token>/', verifymailVerifyEmailView.as_view(), name='verifymail'),


]