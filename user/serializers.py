
from rest_framework import permissions, serializers
from rest_framework.exceptions import AuthenticationFailed
from user.models import UserProfile, UserPermission
import django.contrib.auth.password_validation as validators
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.password_validation import validate_password


class UserRetrieverByAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ['password','groups','user_permissions']

class UserRetrieverSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ['password','groups','user_permissions']
        read_only_fields = ('is_superuser','is_verified','is_staff','is_active','last_login','label','role','email','date_joined')


class UserRetrieverForExternalServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ['password','groups','user_permissions','last_login','is_staff']



# User Serializer
class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        model = UserProfile
        fields = ['email', 'password','first_name','last_name','role','bio','nationality','phone_number','avatar','label']


    # password validation
    def validate_password(self, data):
        validators.validate_password(password=data, user=UserProfile)
        return data
        
    # email validation
    def validate_email(self, value):
        norm_email = value.lower()
        if UserProfile.objects.filter(email=norm_email).exists():
            raise serializers.ValidationError("Email address already exists")
        return norm_email


# Translate user permission from a model instance to json and vice versa
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPermission
        fields = ['post','story','gallery','shelf','book','announcement','event','suggestion']

# Login serializer
class LoginSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserProfile
        fields = ['email', 'password']


# Login retriever serializer
class LoginRetrieverSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=255, write_only=True)
    first_name = serializers.CharField(max_length=255, read_only=True)
    last_name = serializers.CharField(max_length=255, read_only=True)
    phone_number = serializers.CharField(max_length=255, read_only=True)
    bio = serializers.CharField(max_length=255, read_only=True)
    nationality = serializers.CharField(max_length=255, read_only=True)
    role = serializers.CharField(max_length=255, read_only=True)
    avatar = serializers.CharField(max_length=255, read_only=True)
    is_superuser = serializers.BooleanField(read_only=True)
    userpermission = PermissionSerializer()

    class Meta:
        model = UserProfile
        fields = ['id','email', 'password', 'first_name','last_name','phone_number','label','nationality','bio','role', 'is_superuser','avatar','userpermission']


class LogoutSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['email']


# Get new access token to user based on refresh token validity
class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    # exp_access = serializers.CharField(write_only= True)
    access = serializers.ReadOnlyField()

    def validate(self, attrs):
        refresh = RefreshToken(attrs['refresh'])

        data = {'access': str(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()

            data['refresh'] = str(refresh)

        return data

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = UserProfile
        fields = ['token']


class ResetPasswordSerializer(serializers.Serializer):
    email=serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']

class ChangePasswordSerializer(serializers.Serializer):
    model = UserProfile

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    

