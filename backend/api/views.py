import json

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.middleware.csrf import get_token
from django.utils.encoding import force_bytes, force_str
from django.utils.http import (
    urlsafe_base64_encode,
    urlsafe_base64_decode
)
from django.views.decorators.csrf import (
    ensure_csrf_cookie,
    csrf_protect
)
from django.utils.decorators import method_decorator

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import (
    RegisterSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer
)


@method_decorator(ensure_csrf_cookie, name='dispatch')
class CSRFView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({
            "csrfToken": get_token(request)
        })


@method_decorator(csrf_protect, name='dispatch')
class RegisterView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            return Response({
                "message": "Registration successful",
                "username": user.username
            }, status=201)

        return Response(serializer.errors, status=400)


@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is None:
            return Response({
                "error": "Invalid username or password"
            }, status=401)

        login(request, user)

        return Response({
            "message": "Login successful",
            "username": user.username
        })


@method_decorator(csrf_protect, name='dispatch')
class LogoutView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)

        return Response({
            "message": "Logout successful"
        })


class CurrentUserView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "authenticated": True,
            "id": request.user.id,
            "username": request.user.username,
            "email": request.user.email
        })


@method_decorator(csrf_protect, name='dispatch')
class PasswordResetView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        email = serializer.validated_data['email']

        users = User.objects.filter(
            email__iexact=email,
            is_active=True
        )

        for user in users:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            reset_url = (
                f"http://localhost:5173/reset-password"
                f"?uid={uid}&token={token}"
            )

            send_mail(
                subject="Reset your password",
                message=(
                    f"Hello {user.username},\n\n"
                    f"Click the following link to reset your password:\n"
                    f"{reset_url}\n\n"
                    "If you did not request this, ignore this email."
                ),
                from_email=None,
                recipient_list=[user.email],
                fail_silently=False
            )

        return Response({
            "message": (
                "If an account exists with that email, "
                "a password reset link will be sent."
            )
        })


@method_decorator(csrf_protect, name='dispatch')
class PasswordResetConfirmView(APIView):

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(
            data=request.data
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        data = serializer.validated_data

        try:
            uid = force_str(urlsafe_base64_decode(data['uid']))
            user = User.objects.get(pk=uid, is_active=True)
        except (ValueError, TypeError, OverflowError, User.DoesNotExist):
            return Response({
                "error": "Invalid or expired reset link"
            }, status=400)

        if not default_token_generator.check_token(
            user,
            data['token']
        ):
            return Response({
                "error": "Invalid or expired reset link"
            }, status=400)

        user.set_password(data['new_password'])
        user.save()

        return Response({
            "message": "Password changed successfully"
        })