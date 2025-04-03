import logging
import pyotp
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.urls import reverse
from .tokens import (
    email_verification_token_generator, 
    password_reset_token_generator,
    generate_mfa_secret,
    get_tokens_for_user
)
from .models import UserSession, AuthActivity

logger = logging.getLogger('authentication')
User = get_user_model()

def send_verification_email(user, request=None):
    """
    Sends email verification link to user
    Returns bool indicating success
    """
    try:
        token = email_verification_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        domain = request.get_host() if request else settings.DEFAULT_DOMAIN
        protocol = 'https' if request and request.is_secure() else 'http'
        
        verification_url = f"{protocol}://{domain}/verify-email/{uid}/{token}/"
        
        context = {
            'user': user,
            'verification_url': verification_url,
            'expiration_hours': 24
        }
        
        send_mail(
            subject="Vérification de votre adresse e-mail",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=render_to_string('authentication/email_verification.html', context),
            fail_silently=False
        )
        logger.info(f"Verification email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}", exc_info=True)
        return False

def verify_email(uidb64, token):
    """
    Verifies email token and activates account
    Returns tuple: (success: bool, user: User or None)
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        if not email_verification_token_generator.check_token(user, token):
            logger.warning(f"Invalid email verification token for user {user.email}")
            return False, None
            
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save()
            logger.info(f"Email verified for user {user.email}")
            
        return True, user
        
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f"Email verification error: {str(e)}", exc_info=True)
        return False, None

# def send_verification_email(user, request=None):
#     """
#     Envoie un email de vérification à l'utilisateur.
#     """
#     token = email_verification_token_generator.make_token(user)
#     uid = urlsafe_base64_encode(force_bytes(user.pk))
    
#     # Construire l'URL
#     if request:
#         domain = request.get_host()
#         protocol = 'https' if request.is_secure() else 'http'
#     else:
#         domain = settings.ALLOWED_HOSTS[0] or 'localhost:8000'
#         protocol = 'http'
    
#     verification_url = f"{protocol}://{domain}/api/verify-email/{uid}/{token}/"
    
#     # Créer le contenu de l'e-mail
#     subject = "Vérification de votre adresse e-mail"
#     message = f"""
#     Bonjour {user.get_short_name()},
    
#     Veuillez vérifier votre adresse e-mail en cliquant sur le lien suivant:
#     {verification_url}
    
#     Ce lien expirera dans 24 heures.
    
#     Cordialement,
#     L'équipe du service d'authentification
#     """
#     html_message = render_to_string('authentication/email_verification.html', {
#         'user': user,
#         'verification_url': verification_url
#     })
    
#     # Envoyer l'e-mail
#     try:
#         send_mail(
#             subject,
#             message,
#             settings.DEFAULT_FROM_EMAIL,
#             [user.email],
#             html_message=html_message,
#             fail_silently=False
#         )
#         logger.info(f"Email de vérification envoyé à {user.email}")
#         return True
#     except Exception as e:
#         logger.error(f"Erreur lors de l'envoi de l'email de vérification: {str(e)}")
#         return False

# def verify_email(uidb64, token):
#     """
#     Vérifie le token d'email et active le compte.
#     """
#     try:
#         uid = force_str(urlsafe_base64_decode(uidb64))
#         user = User.objects.get(pk=uid)
        
#         if email_verification_token_generator.check_token(user, token):
#             user.is_email_verified = True
#             user.save()
            
#             log_auth_activity(user=user, action='email_verify', details={'success': True})
#             logger.info(f"Email vérifié pour l'utilisateur {user.email}")
#             return True, user
        
#         log_auth_activity(user=user, action='email_verify', details={'success': False, 'reason': 'token_invalid'})
#         logger.warning(f"Token de vérification d'email invalide pour {user.email}")
#         return False, None
    
#     except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
#         logger.error(f"Erreur lors de la vérification d'email: {str(e)}")
#         return False, None

def send_password_reset_email(user, request=None):
    """
    Envoie un email de réinitialisation de mot de passe.
    """
    token = password_reset_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    
    # Construire l'URL
    if request:
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
    else:
        domain = settings.ALLOWED_HOSTS[0] or 'localhost:8000'
        protocol = 'http'
    
    reset_url = f"{protocol}://{domain}/api/password-reset-confirm/{uid}/{token}/"
    
    # Créer le contenu de l'e-mail
    subject = "Réinitialisation de votre mot de passe"
    message = f"""
    Bonjour {user.get_short_name()},
    
    Vous avez demandé la réinitialisation de votre mot de passe. Cliquez sur le lien suivant pour choisir un nouveau mot de passe:
    {reset_url}
    
    Ce lien expirera dans 24 heures.
    
    Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer cet e-mail.
    
    Cordialement,
    L'équipe du service d'authentification
    """
    html_message = render_to_string('authentication/password_reset_email.html', {
        'user': user,
        'reset_url': reset_url
    })
    
    # Envoyer l'e-mail
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False
        )
        log_auth_activity(user=user, action='password_reset', details={'requested': True})
        logger.info(f"Email de réinitialisation de mot de passe envoyé à {user.email}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email de réinitialisation: {str(e)}")
        return False

def reset_password(uidb64, token, new_password):
    """
    Réinitialise le mot de passe de l'utilisateur.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        if password_reset_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            
            # Invalider toutes les sessions existantes
            UserSession.objects.filter(user=user).update(is_active=False)
            
            log_auth_activity(user=user, action='password_reset', details={'success': True})
            logger.info(f"Mot de passe réinitialisé pour l'utilisateur {user.email}")
            return True, user
        
        log_auth_activity(user=user, action='password_reset', details={'success': False, 'reason': 'token_invalid'})
        logger.warning(f"Token de réinitialisation de mot de passe invalide pour {user.email}")
        return False, None
    
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f"Erreur lors de la réinitialisation du mot de passe: {str(e)}")
        return False, None

def setup_mfa(user):
    """
    Génère une clé secrète MFA pour l'utilisateur.
    """
    secret = generate_mfa_secret()
    user.mfa_secret = secret
    user.save(update_fields=['mfa_secret'])
    
    # Générer l'URI pour les applications TOTP
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(user.email, issuer_name="AuthMicroservice")
    
    log_auth_activity(user=user, action='mfa_setup', details={'provisioning_started': True})
    logger.info(f"Configuration MFA initiée pour {user.email}")
    
    return secret, provisioning_uri

def enable_mfa(user):
    """
    Active l'authentification MFA pour l'utilisateur.
    """
    user.mfa_enabled = True
    user.save(update_fields=['mfa_enabled'])
    
    log_auth_activity(user=user, action='mfa_setup', details={'enabled': True})
    logger.info(f"MFA activé pour {user.email}")
    
    return True

def disable_mfa(user):
    """
    Désactive l'authentification MFA pour l'utilisateur.
    """
    user.mfa_enabled = False
    user.mfa_secret = None
    user.save(update_fields=['mfa_enabled', 'mfa_secret'])
    
    log_auth_activity(user=user, action='mfa_setup', details={'enabled': False})
    logger.info(f"MFA désactivé pour {user.email}")
    
    return True

def create_user_session(user, token, request=None):
    """
    Crée une nouvelle session utilisateur.
    """
    expires_at = timezone.now() + timedelta(days=1)  # Durée de vie du token refresh
    
    device_info = None
    ip_address = None
    user_agent = None
    
    if request:
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT')
        
        # Essayer de déterminer le type d'appareil à partir de l'user agent
        device_info = "Navigateur web"
        if 'Mobile' in user_agent:
            device_info = "Mobile"
        elif 'Tablet' in user_agent:
            device_info = "Tablette"
    
    session = UserSession.objects.create(
        user=user,
        token=token,
        device_info=device_info,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at
    )
    
    logger.info(f"Nouvelle session créée pour {user.email}")
    return session

def invalidate_user_session(session_id, user):
    """
    Invalide une session utilisateur spécifique.
    """
    try:
        session = UserSession.objects.get(id=session_id, user=user)
        session.is_active = False
        session.save(update_fields=['is_active'])
        
        logger.info(f"Session {session_id} invalidée pour {user.email}")
        return True
    except UserSession.DoesNotExist:
        logger.warning(f"Session {session_id} non trouvée pour {user.email}")
        return False

def invalidate_all_sessions(user):
    """
    Invalide toutes les sessions d'un utilisateur.
    """
    count = UserSession.objects.filter(user=user, is_active=True).update(is_active=False)
    logger.info(f"{count} sessions invalidées pour {user.email}")
    return count

def log_auth_activity(user=None, action=None, request=None, ip_address=None, user_agent=None, details=None):
    """
    Enregistre une activité d'authentification.
    """
    if request and not ip_address:
        ip_address = request.META.get('REMOTE_ADDR')
    
    if request and not user_agent:
        user_agent = request.META.get('HTTP_USER_AGENT')
    
    activity = AuthActivity.objects.create(
        user=user,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )
    
    logger.debug(f"Activité enregistrée: {action} - {'Utilisateur: ' + user.email if user else 'Anonyme'}")
    return activity

def get_user_auth_activities(user, limit=None):
    """
    Récupère les activités d'authentification d'un utilisateur.
    """
    activities = AuthActivity.objects.filter(user=user)
    
    if limit:
        activities = activities[:limit]
    
    return activities