from django.shortcuts import get_object_or_404, render, redirect
from rest_framework import exceptions
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics, views
from rest_framework import filters  
from .serializers  import (UserSerializer, LoginSerializer,UserRetrieverSerializer,
                        UserRetrieverByAdminSerializer,TokenRefreshSerializer,
                         LoginRetrieverSerializer, EmailVerificationSerializer,
                          ResetPasswordSerializer,UserRetrieverForExternalServiceSerializer, ChangePasswordSerializer)
from user.models import UserProfile, DefaultPermission, UserPermission, CeleryTaskTracker
from user.authentication import UserServiceBackend
from django.http import Http404
from django.contrib.auth import login, authenticate, logout
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.core.cache import cache
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenViewBase
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from sit_user.settings import SIMPLE_JWT, TOKEN_LIFETIME
from datetime import datetime, timedelta
from .utils import Util, TaskType, MessengerData
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
import os
from user.tasks import MessengerToExternalServiceTask
import time





class UserList(generics.ListCreateAPIView):
    """
    List all users, or create a new user.
    """
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer
    # GET users all  non-admin
    queryset = UserProfile.objects.filter(is_superuser=False)
    filter_backends = [filters.SearchFilter]
    search_fields = ['first_name', 'last_name']

    def create(self, request, *args, **kwargs):
        with transaction.atomic():
            account_created_success_message = "Account created successfully. An activation link has been sent to your email address"
            default_permission_does_not_exist_message = "Sorry, there is no default permission for this type of user"
            #  Get default permission for user based on user resolve
            try:
                default_permission = DefaultPermission.objects.get(role = str(request.data['role']).upper())
            except:
                return Response({"result":default_permission_does_not_exist_message}, status=status.HTTP_400_BAD_REQUEST)

            serializer = UserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            instance = serializer.save()

            user_data= serializer.data
            user = UserProfile.objects.get(email=user_data['email'])
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLink=reverse('email-verify')
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            email_body = 'Hi '+ '' + user.email + '' + \
            ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

            # Add default user permission to permission model
            permission = UserPermission.objects.create(user = instance,
                                                    post = default_permission.post,
                                                    story = default_permission.story,
                                                    gallery = default_permission.gallery,
                                                    shelf = default_permission.shelf,
                                                    book = default_permission.book,
                                                    announcement = default_permission.announcement,
                                                    event = default_permission.event,
                                                    suggestion = default_permission.suggestion
            )
            # save user permission : transaction-2
            permission.save()
            # send verification email to user
            Util.send_email(data)
            user = UserRetrieverForExternalServiceSerializer(instance = instance).data
            # add job to job tracker model
            job_tracker = CeleryTaskTracker(instance_id= user['id'], taskType= TaskType.POST)
            job_tracker.save()
            # give task to celery to send user info to post service
            # send_user_data.delay(user)
            return Response({"result":account_created_success_message}, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        # check if user is an admin
        if request.user.is_superuser:
            # if yes use this user retriever serializer
            get_serializer = UserRetrieverByAdminSerializer
        else:
            get_serializer = UserRetrieverSerializer

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token=request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user=UserProfile.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified=True
                user.save()

            return redirect(os.environ.get("UI_URL")+"login?verified=True&result=success" )

        except jwt.ExpiredSignatureError as identifier:

            return redirect(os.environ.get("UI_URL")+"login?verified=False&result=expired")

        except jwt.exceptions.DecodeError as identifier:

            return redirect(os.environ.get("UI_URL")+"login?verified=False&result=invalid")


class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a user instance.
    """
    permission_classes = []
    queryset = UserProfile.objects.all()
    serializer_class = UserRetrieverSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        # if user is an admin
        if request.user.is_superuser:
            get_serializer = UserRetrieverByAdminSerializer
        else:
            get_serializer = UserRetrieverSerializer
        serializer = get_serializer(instance)
        return Response(serializer.data, status= status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        if request.user.is_superuser:
            get_serializer = UserRetrieverByAdminSerializer
        else:
            get_serializer = UserRetrieverSerializer
        serializer = get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        job_tracker = CeleryTaskTracker(instance_id= instance.id, taskType= TaskType.UPDATE)
        job_tracker.save()
        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        if self.request.user.is_superuser: # delete only when user is the admin
            instance = self.get_object()
            with transaction.atomic():
                # job_tracker = CeleryTaskTracker(instance_id= instance.id, taskType= TaskType.DELETE)  -- DO NOT REMOVE USER FROM EXTERNAL SERVICE DB AS THEY ONLY USED FOR REFERENCES IN POST, GALLERY, LIBRARY, ETC...
                # job_tracker.save()
                return super().destroy(self, request, *args, **kwargs)

        return Response(status= status.HTTP_401_UNAUTHORIZED)
    

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        with transaction.atomic():
            # if user is already authenticated
            if request.META.get('HTTP_AUTHORIZATION') is not None and cache.get(request.META.get('HTTP_AUTHORIZATION').split(' ')[1]) is not None:
                token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
                user_data = cache.get(token)
                return Response(user_data, status= status.HTTP_200_OK)

            # if user is not yet authenticated
            user = UserServiceBackend.authenticate( request, email= request.data['email'], password= request.data['password'])
            print("authentication status", request.user.is_authenticated)
            if not user:
                raise AuthenticationFailed('Invalid authentication')
            if not user.is_active:
                raise AuthenticationFailed('Account is disabled, contact the admin')
            if not user.is_verified:
                raise AuthenticationFailed('Email is not verified')

            # login user
            login(request, user)

            # serializer user data to client
            serializer = LoginRetrieverSerializer(instance = user)
            if serializer.is_valid:
                user_data ={}
                token = RefreshToken.for_user(user.id)
                user_data["user"] = serializer.data
                user_data["refresh"] = {"token": str(token), "exp": (datetime.now() + SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'])}
                user_data["access"] = {"token": str(token.access_token), "exp":(datetime.now() + SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'])}
                # cache user data into user cache
                print('timeout in cache',SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
                cache.add(user_data["access"]['token'], user_data, TOKEN_LIFETIME)
                cache_result = cache.get(user_data["access"]['token'])
                # return response to client if serializer is valid
                return Response(cache_result, status= status.HTTP_200_OK)
            # return response to client if serializer is not valid
            return Response(serializer.errors)


class LogoutAPIView(APIView):
    """
    Provides a view for logging out a user
    """
    permission_classes= [IsAuthenticated]

    def post(self, request):                                                                                                                                                                                                                                                                                                                                                            
        with transaction.atomic():
            # Ensure user is authenticated
            if request.META.get('HTTP_AUTHORIZATION') is not None and cache.get(request.META.get('HTTP_AUTHORIZATION').split(' ')[1]) is not None:
                # get token form request header
                token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
                # remove token from cache
                cache.delete(token)
                # logoutuser
                logout(request)
                data = {"code":204, "detail":"logout is successful"}
                return Response(data,status=status.HTTP_204_NO_CONTENT)
                # if user is not authenticated
            return Response(status=status.HTTP_400_BAD_REQUEST)


# update the expired token with the new access token obtained from refresh token view
def UpdateAccessTokenInCache(current_token, new_token):
    if cache.get(current_token) is not None:
        print("inside token in cache")
        user = cache.get(current_token)
        if user is not None:
            user["access"]["token"] = new_token
            cache.delete(current_token)
            cache.set(new_token,user)
            return user
    return None


class TokenRefreshAPIView(generics.GenericAPIView):
    """
    View for obtaining a new access token using refresh token
    """
    permission_classes = ()
    authentication_classes = ()
    serializer_class = TokenRefreshSerializer
    www_authenticate_realm = 'api'

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    # produce new access token
    def post(self, request, *args, **kwargs):
        with transaction.atomic():
            # ensure expired token is passed in the header
            if request.META.get('HTTP_AUTHORIZATION') is not None:
                expired_token =request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
                if cache.get(expired_token) is not None:
                    serializer = self.get_serializer(data=request.data)   
                    try:
                        serializer.is_valid(raise_exception=True)
                    except TokenError as e:
                        raise InvalidToken(e.args[0])
                    # update access token in the user cache
                    user = UpdateAccessTokenInCache(expired_token,serializer.validated_data['access'])
                    # if update is successful
                    if user is not None:
                        data={}
                        data['access'] = {"token":serializer.validated_data['access'],"exp":(datetime.now() + SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'])}
                        return Response(data, status=status.HTTP_200_OK)
                return Response({"detail":"User is not logged in"}, status = status.HTTP_400_BAD_REQUEST)
            return Response({"detail":"Please provide the expired access token in the header"}, status = status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(generics.UpdateAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email=request.data['email']
        if UserProfile.objects.filter(email=email).exists():

            user = UserProfile.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password' }, status=status.HTTP_200_OK)



class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        pass

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = UserProfile
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success', 
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def check_uncompleted_tasks():
    uncompleted_tasks = CeleryTaskTracker.objects.filter(isCompleted=False)
    if uncompleted_tasks is not None:
        for task in uncompleted_tasks:
            if task.taskType==TaskType.DELETE:
                user_data=task.instance_id
            else:
                user_data = UserRetrieverForExternalServiceSerializer(instance = task.get_instance()).data
            # msg = MessengerData(data=user_data, task_id=task.id, task_type=task.taskType)
            MessengerToExternalServiceTask.delay(data=user_data, task_id=task.id, task_type=task.taskType)
            time.sleep(30)
    return

