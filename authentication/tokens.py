import logging
import pyotp
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger('authentication')

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    """
    Génère un token unique pour la vérification d'email.
    """
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.is_email_verified)
        )

class PasswordResetTokenGeneratorCustom(PasswordResetTokenGenerator):
    """
    Génère un token unique pour la réinitialisation de mot de passe.
    """
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.password)
        )

def generate_mfa_secret():
    """
    Génère une clé secrète pour l'authentification multifacteur.
    """
    return pyotp.random_base32()

def verify_mfa_token(secret, token):
    """
    Vérifie un token MFA par rapport au secret.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def get_tokens_for_user(user):
    """
    Génère des tokens JWT pour un utilisateur.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

email_verification_token_generator = EmailVerificationTokenGenerator()
password_reset_token_generator = PasswordResetTokenGeneratorCustom()