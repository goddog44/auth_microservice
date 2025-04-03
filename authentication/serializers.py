from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from .models import UserSession, AuthActivity

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'role', 'is_active', 
                  'is_email_verified', 'mfa_enabled', 'date_joined', 'last_login',
                  'profile_picture')
        read_only_fields = ('id', 'date_joined', 'last_login', 'is_active', 'is_email_verified')

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'profile_picture')
        read_only_fields = ('id', 'email')

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password', 'password_confirm')
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": _("Les mots de passe ne correspondent pas.")})
        
        validate_password(attrs['password'])
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)
    mfa_token = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        mfa_token = attrs.get('mfa_token', '')
        
        if email and password:
            user = authenticate(request=self.context.get('request'),
                              username=email, password=password)
            
            # L'authentification a échoué
            if not user:
                msg = _('Impossible de se connecter avec les identifiants fournis.')
                raise serializers.ValidationError(msg, code='authorization')
            
            # Vérification de l'email
            if not user.is_email_verified:
                msg = _('Veuillez vérifier votre adresse email avant de vous connecter.')
                raise serializers.ValidationError(msg, code='email_verification')
            
            # Vérification MFA si activé
            if user.mfa_enabled:
                if not mfa_token:
                    msg = _('MFA activé. Veuillez fournir un token MFA.')
                    raise serializers.ValidationError({'mfa_required': True}, code='mfa_required')
                
                from .tokens import verify_mfa_token
                if not verify_mfa_token(user.mfa_secret, mfa_token):
                    msg = _('Token MFA invalide.')
                    raise serializers.ValidationError(msg, code='mfa_invalid')
        else:
            msg = _('Veuillez fournir à la fois l\'email et le mot de passe.')
            raise serializers.ValidationError(msg, code='authorization')
            
        attrs['user'] = user
        return attrs

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="New password (minimum 8 characters)"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text="Confirm new password"
    )
    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        # Password confirmation check
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password_confirm": _("Passwords do not match.")
            })

        # Get user from uidb64
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uidb64']))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({
                "uidb64": _("Invalid user identifier.")
            })

        # Validate token
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise serializers.ValidationError({
                "token": _("Invalid or expired token.")
            })

        # Validate password strength
        try:
            validate_password(attrs['password'], self.user)
        except Exception as e:
            raise serializers.ValidationError({
                "password": list(e.messages)
            })

        return attrs

    def save(self):
        password = self.validated_data['password']
        self.user.set_password(password)
        self.user.save()
        return self.user

class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    uidb64 = serializers.CharField()

class MFASetupSerializer(serializers.Serializer):
    token = serializers.CharField()
    
    def validate_token(self, value):
        user = self.context['request'].user
        from .tokens import verify_mfa_token
        
        if not verify_mfa_token(user.mfa_secret, value):
            raise serializers.ValidationError(_("Token MFA invalide."))
        return value

class MFAStatusSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()

class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ('id', 'device_info', 'ip_address', 'created_at', 'expires_at', 'last_used', 'is_active')
        read_only_fields = fields

class AuthActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthActivity
        fields = ('id', 'action', 'ip_address', 'user_agent', 'timestamp', 'details')
        read_only_fields = fields

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": _("Les nouveaux mots de passe ne correspondent pas.")})
        
        validate_password(attrs['new_password'])
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Le mot de passe actuel est incorrect."))
        return value