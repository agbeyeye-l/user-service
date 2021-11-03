from django.urls import path, include
from . import views
from user.views import UserList, UserDetail, VerifyEmail, PasswordTokenCheckAPI, ResetPasswordView, ChangePasswordView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt import views as jwt_views

router = DefaultRouter()
urlpatterns = [

    path('', include(router.urls)),
    path("users/", views.UserList.as_view(), name='users'),
    path("users/<int:pk>/", views.UserDetail.as_view(),name='user-detail'),
    path("api/auth/", include("rest_framework.urls", namespace='rest_framework')),
    path('token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', views.TokenRefreshAPIView.as_view(), name='token-refresh'),
    path('email-verify/', views.VerifyEmail.as_view(), name='email-verify'),
    path('request-reset-email/', views.ResetPasswordView.as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]