import logging
import json
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.contrib import messages

from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    UserSerializer, UserProfileSerializer, RegisterSerializer, LoginSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer, EmailVerificationSerializer,
    MFASetupSerializer, MFAStatusSerializer, UserSessionSerializer, AuthActivitySerializer,
    ChangePasswordSerializer
)
from .services import (
    send_verification_email, verify_email, send_password_reset_email, reset_password,
    setup_mfa, enable_mfa, disable_mfa, create_user_session, invalidate_user_session,
    invalidate_all_sessions, log_auth_activity, get_user_auth_activities
)
from .tokens import get_tokens_for_user, verify_mfa_token
from .models import UserSession, AuthActivity

logger = logging.getLogger('authentication')
User = get_user_model()

# Vues pour les templates HTML
class RegisterView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')
    
class verifymailVerifyEmailView(View):
    def get(self, request, uidb64, token):
        return render(request, 'authentication/email_verification.html')

@method_decorator(login_required, name='dispatch')
class ProfileView(View):
    def get(self, request):
        return render(request, 'authentication/profile.html', {'user': request.user})

class PasswordResetView(View):
    def get(self, request):
        return render(request, 'authentication/password_reset.html')

# class PasswordResetConfirmAPIView(APIView):
#     permission_classes = [AllowAny]
    
#     def post(self, request):
#         serializer = PasswordResetConfirmSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(
#                 {"detail": _("Password has been reset successfully.")},
#                 status=status.HTTP_200_OK
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(login_required, name='dispatch')
class MFASetupView(View):
    def get(self, request):
        secret, uri = setup_mfa(request.user)
        return render(request, 'authentication/mfa_setup.html', {
            'secret': secret,
            'uri': uri
        })

# API RESTful
class RegisterAPIView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Enregistrer l'activité
            log_auth_activity(
                user=user,
                action='register',
                request=request
            )
            
            # Envoyer l'email de vérification
            send_verification_email(user, request)
            
            return Response({
                "user": UserSerializer(user, context=self.get_serializer_context()).data,
                "message": "Utilisateur créé avec succès. Veuillez vérifier votre email pour activer votre compte."
            }, status=status.HTTP_201_CREATED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Mettre à jour la dernière connexion
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Générer les tokens JWT
            tokens = get_tokens_for_user(user)
            
            # Créer une session
            create_user_session(user, tokens['refresh'], request)
            
            # Enregistrer l'activité de connexion
            log_auth_activity(
                user=user,
                action='login',
                request=request
            )
            
            return Response({
                'user': UserSerializer(user).data,
                'tokens': tokens
            }, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        refresh_token = request.data.get('refresh', None)
        
        if refresh_token:
            try:
                # Invalider le token
                token = RefreshToken(refresh_token)
                token.blacklist()
                
                # Invalider la session associée
                UserSession.objects.filter(token=refresh_token).update(is_active=False)
                
                # Enregistrer l'activité
                log_auth_activity(
                    user=request.user,
                    action='logout',
                    request=request
                )
                
                return Response({"message": "Déconnexion réussie"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error": "Erreur lors de la déconnexion"}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"error": "Le token de rafraîchissement est requis"}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                send_password_reset_email(user, request)
                
                return Response({
                    "message": "Si un compte existe avec cette adresse email, un lien de réinitialisation de mot de passe a été envoyé."
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                # Ne pas indiquer que l'email n'existe pas pour des raisons de sécurité
                return Response({
                    "message": "Si un compte existe avec cette adresse email, un lien de réinitialisation de mot de passe a été envoyé."
                }, status=status.HTTP_200_OK)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        # Combine URL parameters with request data
        data = request.data.copy()
        data['uidb64'] = uidb64
        data['token'] = token
        
        serializer = PasswordResetConfirmSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "Password has been reset successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationRequestView(View):
    """Handles requests for email verification links"""
    def post(self, request):
        if not request.user.is_authenticated:
            return redirect('login')
        
        if send_verification_email(request.user, request):
            messages.success(request, "Un lien de vérification a été envoyé à votre adresse email.")
        else:
            messages.error(request, "Erreur lors de l'envoi du lien de vérification.")
        
        return redirect('profile')

class EmailVerificationView(View):
    """Handles email verification via GET request (clicking email link)"""
    def get(self, request, uidb64, token):
        success, user = verify_email(uidb64, token)
        
        if success:
            if request.user.is_authenticated:
                messages.success(request, "Votre adresse email a été vérifiée avec succès.")
                return redirect('profile')
            
            messages.success(request, "Votre adresse email a été vérifiée. Vous pouvez maintenant vous connecter.")
            return redirect('login')
        
        messages.error(request, "Le lien de vérification est invalide ou a expiré.")
        return redirect('login')

class EmailVerificationAPIView(APIView):
    """API endpoint for programmatic email verification"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data['token']
        uidb64 = serializer.validated_data['uidb64']
        success, user = verify_email(uidb64, token)
        
        if not success:
            return Response(
                {"error": "Le lien de vérification est invalide ou a expiré."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        return Response({
            "message": "Email vérifié avec succès.",
            "user_id": user.id,
            "email": user.email
        }, status=status.HTTP_200_OK)



# class EmailVerificationAPIView(APIView):
#     permission_classes = [AllowAny]
    
#     def post(self, request):
#         serializer = EmailVerificationSerializer(data=request.data)
#         if serializer.is_valid():
#             token = serializer.validated_data['token']
#             uidb64 = serializer.validated_data['uidb64']
            
#             success, user = verify_email(uidb64, token)
            
#             if success:
#                 return Response({
#                     "message": "Email vérifié avec succès."
#                 }, status=status.HTTP_200_OK)
            
#             return Response({
#                 "error": "Le lien de vérification est invalide ou a expiré."
#             }, status=status.HTTP_400_BAD_REQUEST)
            
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class EmailVerificationView(View):
#     def get(self, request, uidb64, token):
#         success, user = verify_email(uidb64, token)
#         if success:
#             # Si l'utilisateur est déjà connecté
#             if request.user.is_authenticated:
#                 messages.success(request, "Votre adresse email a été vérifiée avec succès.")
#                 return redirect('profile')
            
#             messages.success(request, "Votre adresse email a été vérifiée. Vous pouvez maintenant vous connecter.")
#             return redirect('login')
        
#         messages.error(request, "Le lien de vérification est invalide ou a expiré.")
#         return redirect('login')
    

class MFASetupAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        secret, uri = setup_mfa(request.user)
        
        return Response({
            "secret": secret,
            "uri": uri,
            "message": "Scannez le QR code avec votre application d'authentification, puis validez avec le code généré."
        })
    
    def post(self, request):
        serializer = MFASetupSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            enable_mfa(request.user)
            
            return Response({
                "message": "MFA activé avec succès."
            }, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MFAStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            "enabled": request.user.mfa_enabled
        })
    
    def post(self, request):
        serializer = MFAStatusSerializer(data=request.data)
        if serializer.is_valid():
            enabled = serializer.validated_data['enabled']
            
            if enabled and not request.user.mfa_enabled:
                # Si l'utilisateur veut activer MFA mais n'a pas encore configuré
                return Response({
                    "message": "Veuillez d'abord configurer MFA",
                    "setup_required": True
                }, status=status.HTTP_400_BAD_REQUEST)
            elif not enabled and request.user.mfa_enabled:
                # Désactiver MFA
                disable_mfa(request.user)
                return Response({
                    "message": "MFA désactivé avec succès."
                })
            
            return Response({
                "enabled": request.user.mfa_enabled
            })
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    def patch(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            log_auth_activity(
                user=request.user,
                action='profile_update',
                request=request
            )
            
            return Response(serializer.data)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Invalider toutes les sessions sauf la courante
            current_token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1] if 'HTTP_AUTHORIZATION' in request.META else None
            if current_token:
                UserSession.objects.filter(user=user).exclude(token=current_token).update(is_active=False)
            
            log_auth_activity(
                user=user,
                action='password_reset',
                request=request,
                details={'self_initiated': True}
            )
            
            return Response({"message": "Mot de passe modifié avec succès."}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserSessionsAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSessionSerializer
    
    def get_queryset(self):
        return UserSession.objects.filter(user=self.request.user, is_active=True)

class RevokeSessionAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, session_id):
        success = invalidate_user_session(session_id, request.user)
        
        if success:
            return Response({"message": "Session révoquée avec succès."}, status=status.HTTP_200_OK)
        
        return Response({"error": "Session non trouvée."}, status=status.HTTP_404_NOT_FOUND)

class RevokeAllSessionsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Obtenir le token actuel pour le préserver
        current_token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1] if 'HTTP_AUTHORIZATION' in request.META else None
        
        # Invalider toutes les autres sessions
        if current_token:
            count = UserSession.objects.filter(user=request.user).exclude(token=current_token).update(is_active=False)
        else:
            count = invalidate_all_sessions(request.user)
        
        return Response({
            "message": f"{count} sessions révoquées avec succès.",
            "current_session_preserved": bool(current_token)
        }, status=status.HTTP_200_OK)

class UserActivitiesAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AuthActivitySerializer
    
    def get_queryset(self):
        return AuthActivity.objects.filter(user=self.request.user)