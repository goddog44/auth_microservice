import logging
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import UserSession
from .services import log_auth_activity

logger = logging.getLogger('authentication')

class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware pour gérer l'authentification JWT et les sessions utilisateur.
    """
    def process_request(self, request):
        # Ne pas traiter les requêtes sans utilisateur ou pour les routes statiques/admin
        if (request.path.startswith('/static/') or 
            request.path.startswith('/media/') or 
            request.path.startswith('/admin/')):
            return None
        
        # Authentifier l'utilisateur si un token JWT est présent
        jwt_auth = JWTAuthentication()
        try:
            authenticated = jwt_auth.authenticate(request)
            if authenticated:
                user, token = authenticated
                
                # Mettre à jour la dernière connexion de l'utilisateur
                if user.is_authenticated:
                    # Trouver la session correspondante
                    try:
                        session = UserSession.objects.get(token=str(token), is_active=True)
                        
                        # Vérifier si la session a expiré
                        if session.expires_at < timezone.now():
                            session.is_active = False
                            session.save(update_fields=['is_active'])
                            return None
                        
                        # Mettre à jour last_used
                        session.last_used = timezone.now()
                        session.save(update_fields=['last_used'])
                        
                    except UserSession.DoesNotExist:
                        # La session n'existe plus ou a été invalidée
                        pass
        
        except Exception as e:
            # Ne pas bloquer la requête en cas d'erreur d'authentification
            logger.error(f"Erreur dans le middleware JWT: {str(e)}")
        
        return None
    
    def process_response(self, request, response):
        # Enregistrer les tentatives d'authentification échouées
        if (response.status_code == 401 and 
            not request.path.startswith('/api/login/') and 
            not request.path.startswith('/api/token/refresh/')):
            
            log_auth_activity(
                action='failed_login',
                request=request,
                details={'path': request.path}
            )
        
        return response