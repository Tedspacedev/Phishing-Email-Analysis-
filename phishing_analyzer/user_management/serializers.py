from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile, ActivityLog, UserSession, APIKey


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined']
        read_only_fields = ['id', 'date_joined']


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model"""
    
    user = UserSerializer(read_only=True)
    full_name = serializers.ReadOnlyField()
    is_account_locked = serializers.ReadOnlyField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 'user', 'role', 'department', 'phone_number', 'employee_id',
            'email_notifications', 'dashboard_layout', 'timezone',
            'two_factor_enabled', 'last_password_change', 'failed_login_attempts',
            'account_locked_until', 'last_login_ip', 'last_activity',
            'created_at', 'updated_at', 'full_name', 'is_account_locked'
        ]
        read_only_fields = [
            'id', 'failed_login_attempts', 'account_locked_until',
            'last_login_ip', 'last_activity', 'created_at', 'updated_at',
            'full_name', 'is_account_locked'
        ]


class ActivityLogSerializer(serializers.ModelSerializer):
    """Serializer for ActivityLog model"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = ActivityLog
        fields = [
            'id', 'user', 'user_username', 'activity_type', 'description',
            'ip_address', 'user_agent', 'session_key', 'content_type',
            'object_id', 'additional_data', 'severity', 'success',
            'error_message', 'timestamp'
        ]
        read_only_fields = '__all__'


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for UserSession model"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_username', 'session_key', 'ip_address',
            'user_agent', 'country', 'city', 'is_active', 'last_activity',
            'is_suspicious', 'risk_score', 'created_at', 'expires_at',
            'is_expired'
        ]
        read_only_fields = [
            'id', 'user_username', 'is_expired', 'created_at'
        ]


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for APIKey model"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'user', 'user_username', 'name', 'key', 'key_type',
            'allowed_ips', 'rate_limit', 'total_requests', 'last_used',
            'is_active', 'expires_at', 'created_at', 'updated_at', 'is_expired'
        ]
        read_only_fields = [
            'id', 'user_username', 'key', 'total_requests', 'last_used',
            'created_at', 'updated_at', 'is_expired'
        ]
        extra_kwargs = {
            'key': {'write_only': True}
        }


class UserRegistrationSerializer(serializers.Serializer):
    """Serializer for user registration"""
    
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    first_name = serializers.CharField(max_length=30, required=False)
    last_name = serializers.CharField(max_length=30, required=False)
    
    # Profile fields
    role = serializers.ChoiceField(
        choices=UserProfile.USER_ROLES,
        default='GENERAL_USER',
        required=False
    )
    department = serializers.ChoiceField(
        choices=UserProfile.DEPARTMENTS,
        default='OTHER',
        required=False
    )
    phone_number = serializers.CharField(max_length=20, required=False)
    employee_id = serializers.CharField(max_length=50, required=False)
    
    def validate_username(self, value):
        """Validate username uniqueness"""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value
    
    def validate(self, data):
        """Validate password confirmation"""
        if data.get('password') != data.get('password_confirm'):
            raise serializers.ValidationError("Passwords do not match")
        return data


class LoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change"""
    
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, data):
        """Validate new password confirmation"""
        if data.get('new_password') != data.get('new_password_confirm'):
            raise serializers.ValidationError("New passwords do not match")
        return data


class UserStatsSerializer(serializers.Serializer):
    """Serializer for user statistics"""
    
    total_users = serializers.IntegerField()
    active_users = serializers.IntegerField()
    
    # Role breakdown
    role_counts = serializers.DictField()
    
    # Department breakdown
    department_counts = serializers.DictField()
    
    # Recent activity
    new_users_today = serializers.IntegerField()
    new_users_week = serializers.IntegerField()
    new_users_month = serializers.IntegerField()
    recent_logins = serializers.IntegerField()
    
    # Security stats
    users_with_2fa = serializers.IntegerField()
    locked_accounts = serializers.IntegerField()


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""
    
    class Meta:
        model = UserProfile
        fields = [
            'phone_number', 'email_notifications', 'dashboard_layout',
            'timezone', 'two_factor_enabled'
        ]


class BulkUserActionSerializer(serializers.Serializer):
    """Serializer for bulk user actions"""
    
    ACTION_CHOICES = [
        ('ACTIVATE', 'Activate Users'),
        ('DEACTIVATE', 'Deactivate Users'),
        ('DELETE', 'Delete Users'),
        ('RESET_PASSWORD', 'Reset Passwords'),
        ('UNLOCK_ACCOUNTS', 'Unlock Accounts'),
    ]
    
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1,
        help_text="List of user IDs to perform action on"
    )
    
    action = serializers.ChoiceField(choices=ACTION_CHOICES)
    
    # Optional parameters for specific actions
    new_role = serializers.ChoiceField(
        choices=UserProfile.USER_ROLES,
        required=False,
        help_text="New role for users (for role change action)"
    )
    
    send_notification = serializers.BooleanField(
        default=True,
        help_text="Send email notification to affected users"
    )
    
    def validate_user_ids(self, value):
        """Validate that all user IDs exist"""
        existing_ids = set(User.objects.filter(id__in=value).values_list('id', flat=True))
        missing_ids = set(value) - existing_ids
        
        if missing_ids:
            raise serializers.ValidationError(
                f"User IDs not found: {', '.join(map(str, missing_ids))}"
            )
        
        return value


class UserExportSerializer(serializers.Serializer):
    """Serializer for user data export"""
    
    EXPORT_FORMATS = [
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
        ('XLSX', 'Excel'),
    ]
    
    format = serializers.ChoiceField(choices=EXPORT_FORMATS, default='CSV')
    
    include_profiles = serializers.BooleanField(
        default=True,
        help_text="Include user profile data in export"
    )
    
    include_activity = serializers.BooleanField(
        default=False,
        help_text="Include user activity logs in export"
    )
    
    roles = serializers.ListField(
        child=serializers.ChoiceField(choices=UserProfile.USER_ROLES),
        required=False,
        help_text="Filter by user roles"
    )
    
    departments = serializers.ListField(
        child=serializers.ChoiceField(choices=UserProfile.DEPARTMENTS),
        required=False,
        help_text="Filter by departments"
    )
    
    active_only = serializers.BooleanField(
        default=True,
        help_text="Export only active users"
    )
    
    date_from = serializers.DateField(
        required=False,
        help_text="Include users created from this date"
    )
    
    date_to = serializers.DateField(
        required=False,
        help_text="Include users created up to this date"
    )
    
    def validate(self, data):
        """Validate date range"""
        if data.get('date_from') and data.get('date_to'):
            if data['date_from'] > data['date_to']:
                raise serializers.ValidationError(
                    "date_from must be earlier than date_to"
                )
        return data


class ActivityLogFilterSerializer(serializers.Serializer):
    """Serializer for activity log filtering"""
    
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Filter by specific user IDs"
    )
    
    activity_types = serializers.ListField(
        child=serializers.ChoiceField(choices=ActivityLog.ACTIVITY_TYPES),
        required=False,
        help_text="Filter by activity types"
    )
    
    severity_levels = serializers.ListField(
        child=serializers.ChoiceField(choices=ActivityLog.SEVERITY_LEVELS),
        required=False,
        help_text="Filter by severity levels"
    )
    
    success_only = serializers.BooleanField(
        required=False,
        help_text="Show only successful activities"
    )
    
    date_from = serializers.DateTimeField(
        required=False,
        help_text="Show activities from this date/time"
    )
    
    date_to = serializers.DateTimeField(
        required=False,
        help_text="Show activities up to this date/time"
    )
    
    ip_address = serializers.IPAddressField(
        required=False,
        help_text="Filter by IP address"
    )
    
    limit = serializers.IntegerField(
        default=1000,
        max_value=10000,
        help_text="Maximum number of records to return"
    )
    
    def validate(self, data):
        """Validate date range"""
        if data.get('date_from') and data.get('date_to'):
            if data['date_from'] >= data['date_to']:
                raise serializers.ValidationError(
                    "date_from must be earlier than date_to"
                )
        return data


class SessionManagementSerializer(serializers.Serializer):
    """Serializer for session management operations"""
    
    ACTION_CHOICES = [
        ('TERMINATE_ALL', 'Terminate All Sessions'),
        ('TERMINATE_USER', 'Terminate User Sessions'),
        ('TERMINATE_SUSPICIOUS', 'Terminate Suspicious Sessions'),
        ('MARK_SUSPICIOUS', 'Mark Sessions as Suspicious'),
    ]
    
    action = serializers.ChoiceField(choices=ACTION_CHOICES)
    
    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Specific user IDs (for user-specific actions)"
    )
    
    session_ids = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Specific session keys to act on"
    )
    
    exclude_current = serializers.BooleanField(
        default=True,
        help_text="Exclude current user's session from bulk actions"
    )
    
    reason = serializers.CharField(
        required=False,
        help_text="Reason for the action (for audit purposes)"
    )