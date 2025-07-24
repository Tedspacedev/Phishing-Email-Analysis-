from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
import logging

from .models import UserProfile, ActivityLog, UserSession, APIKey
from .serializers import (
    UserProfileSerializer, ActivityLogSerializer, UserSessionSerializer,
    APIKeySerializer, UserRegistrationSerializer, LoginSerializer,
    PasswordChangeSerializer, UserStatsSerializer
)

logger = logging.getLogger(__name__)


class UserProfileViewSet(viewsets.ModelViewSet):
    """ViewSet for managing user profiles"""
    
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['role', 'department', 'two_factor_enabled']
    search_fields = ['user__username', 'user__first_name', 'user__last_name', 'user__email']
    ordering = ['user__username']
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.has_permission('manage_users'):
            return UserProfile.objects.all()
        else:
            # Users can only see their own profile
            return UserProfile.objects.filter(user=user)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user's profile"""
        try:
            profile = request.user.profile
            serializer = self.get_serializer(profile)
            return Response(serializer.data)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """Change user password"""
        serializer = PasswordChangeSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        if not user.check_password(old_password):
            return Response(
                {'error': 'Invalid old password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.set_password(new_password)
        user.save()
        
        # Update profile
        if hasattr(user, 'profile'):
            user.profile.last_password_change = timezone.now()
            user.profile.save()
        
        ActivityLog.log_activity(
            user=user,
            activity_type='USER_UPDATE',
            description='Password changed',
            ip_address=self.get_client_ip()
        )
        
        return Response({'message': 'Password changed successfully'})
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get user statistics"""
        if not request.user.profile.has_permission('manage_users'):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        now = timezone.now()
        today = now.date()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        # Basic counts
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        
        # Role breakdown
        role_counts = dict(
            UserProfile.objects.values('role').annotate(
                count=Count('id')
            ).values_list('role', 'count')
        )
        
        # Department breakdown
        department_counts = dict(
            UserProfile.objects.values('department').annotate(
                count=Count('id')
            ).values_list('department', 'count')
        )
        
        # Recent activity
        new_users_today = User.objects.filter(date_joined__date=today).count()
        new_users_week = User.objects.filter(date_joined__gte=week_ago).count()
        new_users_month = User.objects.filter(date_joined__gte=month_ago).count()
        
        # Login activity
        recent_logins = ActivityLog.objects.filter(
            activity_type='LOGIN',
            timestamp__gte=week_ago
        ).count()
        
        # Security stats
        users_with_2fa = UserProfile.objects.filter(two_factor_enabled=True).count()
        locked_accounts = UserProfile.objects.filter(
            account_locked_until__gt=now
        ).count()
        
        stats_data = {
            'total_users': total_users,
            'active_users': active_users,
            'role_counts': role_counts,
            'department_counts': department_counts,
            'new_users_today': new_users_today,
            'new_users_week': new_users_week,
            'new_users_month': new_users_month,
            'recent_logins': recent_logins,
            'users_with_2fa': users_with_2fa,
            'locked_accounts': locked_accounts
        }
        
        serializer = UserStatsSerializer(stats_data)
        return Response(serializer.data)
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing activity logs"""
    
    queryset = ActivityLog.objects.all()
    serializer_class = ActivityLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['activity_type', 'severity', 'success', 'user']
    search_fields = ['description', 'user__username']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.has_permission('view_all_analyses'):
            return ActivityLog.objects.all()
        else:
            # Users can only see their own activity logs
            return ActivityLog.objects.filter(user=user)


class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing user sessions"""
    
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['is_active', 'is_suspicious', 'user']
    search_fields = ['ip_address', 'user__username', 'country', 'city']
    ordering = ['-last_activity']
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.has_permission('manage_users'):
            return UserSession.objects.all()
        else:
            # Users can only see their own sessions
            return UserSession.objects.filter(user=user)
    
    @action(detail=True, methods=['post'])
    def terminate(self, request, pk=None):
        """Terminate a user session"""
        session = self.get_object()
        
        # Check if user can terminate this session
        if session.user != request.user and not request.user.profile.has_permission('manage_users'):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        session.is_active = False
        session.save()
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='SECURITY_ALERT',
            description=f'Terminated session {session.session_key}',
            ip_address=self.get_client_ip(),
            additional_data={'terminated_session': session.session_key}
        )
        
        return Response({'message': 'Session terminated successfully'})
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class APIKeyViewSet(viewsets.ModelViewSet):
    """ViewSet for managing API keys"""
    
    queryset = APIKey.objects.all()
    serializer_class = APIKeySerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['key_type', 'is_active', 'user']
    search_fields = ['name', 'user__username']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        user = self.request.user
        
        if hasattr(user, 'profile') and user.profile.has_permission('manage_users'):
            return APIKey.objects.all()
        else:
            # Users can only see their own API keys
            return APIKey.objects.filter(user=user)
    
    def perform_create(self, serializer):
        """Create API key"""
        import secrets
        
        # Generate secure API key
        api_key = secrets.token_urlsafe(48)
        
        key_obj = serializer.save(user=self.request.user, key=api_key)
        
        ActivityLog.log_activity(
            user=self.request.user,
            activity_type='API_ACCESS',
            description=f'Created API key: {key_obj.name}',
            content_object=key_obj,
            ip_address=self.get_client_ip()
        )
    
    @action(detail=True, methods=['post'])
    def regenerate(self, request, pk=None):
        """Regenerate API key"""
        api_key_obj = self.get_object()
        
        # Check permissions
        if api_key_obj.user != request.user and not request.user.profile.has_permission('manage_users'):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        import secrets
        new_key = secrets.token_urlsafe(48)
        
        api_key_obj.key = new_key
        api_key_obj.save()
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='API_ACCESS',
            description=f'Regenerated API key: {api_key_obj.name}',
            content_object=api_key_obj,
            ip_address=self.get_client_ip()
        )
        
        serializer = self.get_serializer(api_key_obj)
        return Response(serializer.data)
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class AuthViewSet(viewsets.ViewSet):
    """ViewSet for authentication operations"""
    
    permission_classes = [permissions.AllowAny]
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        """User login"""
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        
        if user is None:
            # Log failed login attempt
            try:
                user_obj = User.objects.get(username=username)
                if hasattr(user_obj, 'profile'):
                    user_obj.profile.increment_failed_attempts()
            except User.DoesNotExist:
                pass
            
            ActivityLog.log_activity(
                user=None,
                activity_type='LOGIN',
                description=f'Failed login attempt for {username}',
                ip_address=self.get_client_ip(),
                success=False,
                error_message='Invalid credentials'
            )
            
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {'error': 'Account is disabled'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if account is locked
        if hasattr(user, 'profile') and user.profile.is_account_locked:
            return Response(
                {'error': 'Account is temporarily locked'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Reset failed attempts on successful login
        if hasattr(user, 'profile'):
            user.profile.reset_failed_attempts()
            user.profile.last_login_ip = self.get_client_ip()
            user.profile.last_activity = timezone.now()
            user.profile.save()
        
        # Generate or get token
        token, created = Token.objects.get_or_create(user=user)
        
        # Log successful login
        ActivityLog.log_activity(
            user=user,
            activity_type='LOGIN',
            description='User logged in',
            ip_address=self.get_client_ip(),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'token': token.key,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.profile.role if hasattr(user, 'profile') else 'GENERAL_USER'
            }
        })
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        """User logout"""
        if request.user.is_authenticated:
            # Delete token
            try:
                request.user.auth_token.delete()
            except:
                pass
            
            ActivityLog.log_activity(
                user=request.user,
                activity_type='LOGOUT',
                description='User logged out',
                ip_address=self.get_client_ip()
            )
        
        return Response({'message': 'Logged out successfully'})
    
    @action(detail=False, methods=['post'])
    def register(self, request):
        """User registration"""
        serializer = UserRegistrationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Create user
        user = User.objects.create_user(
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password'],
            first_name=serializer.validated_data.get('first_name', ''),
            last_name=serializer.validated_data.get('last_name', '')
        )
        
        # Create profile
        UserProfile.objects.create(
            user=user,
            role=serializer.validated_data.get('role', 'GENERAL_USER'),
            department=serializer.validated_data.get('department', 'OTHER'),
            phone_number=serializer.validated_data.get('phone_number', ''),
            employee_id=serializer.validated_data.get('employee_id', '')
        )
        
        ActivityLog.log_activity(
            user=user,
            activity_type='USER_CREATE',
            description=f'User registered: {user.username}',
            ip_address=self.get_client_ip()
        )
        
        return Response({
            'message': 'User registered successfully',
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


# Traditional Django views for web interface
def login_view(request):
    """Login page"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            
            ActivityLog.log_activity(
                user=user,
                activity_type='LOGIN',
                description='User logged in via web interface',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return redirect('email_analysis:dashboard')
        else:
            return render(request, 'user_management/login.html', {
                'error': 'Invalid username or password'
            })
    
    return render(request, 'user_management/login.html')


@login_required
def logout_view(request):
    """Logout"""
    ActivityLog.log_activity(
        user=request.user,
        activity_type='LOGOUT',
        description='User logged out via web interface',
        ip_address=get_client_ip(request)
    )
    
    logout(request)
    return redirect('user_management:user_login')


@login_required
def profile_view(request):
    """User profile page"""
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        # Create profile if it doesn't exist
        profile = UserProfile.objects.create(user=request.user)
    
    if request.method == 'POST':
        # Update profile
        profile.phone_number = request.POST.get('phone_number', '')
        profile.email_notifications = request.POST.get('email_notifications') == 'on'
        profile.timezone = request.POST.get('timezone', 'UTC')
        profile.save()
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='USER_UPDATE',
            description='Updated profile',
            ip_address=get_client_ip(request)
        )
        
        return render(request, 'user_management/profile.html', {
            'profile': profile,
            'message': 'Profile updated successfully'
        })
    
    return render(request, 'user_management/profile.html', {'profile': profile})


def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')
