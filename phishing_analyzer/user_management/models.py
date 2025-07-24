from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey


class UserProfile(models.Model):
    """Extended user profile for role-based access control"""
    
    USER_ROLES = [
        ('ADMIN', 'Administrator'),
        ('SECURITY_ANALYST', 'Security Analyst'),
        ('IT_STAFF', 'IT Staff'),
        ('GENERAL_USER', 'General User'),
        ('VIEWER', 'Viewer'),
    ]
    
    DEPARTMENTS = [
        ('IT', 'Information Technology'),
        ('SECURITY', 'Cybersecurity'),
        ('OPERATIONS', 'Operations'),
        ('MANAGEMENT', 'Management'),
        ('OTHER', 'Other'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Role and Permissions
    role = models.CharField(max_length=20, choices=USER_ROLES, default='GENERAL_USER')
    department = models.CharField(max_length=15, choices=DEPARTMENTS, default='OTHER')
    
    # Contact Information
    phone_number = models.CharField(max_length=20, blank=True)
    employee_id = models.CharField(max_length=50, blank=True)
    
    # Preferences
    email_notifications = models.BooleanField(default=True)
    dashboard_layout = models.JSONField(default=dict, help_text="User dashboard preferences")
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Security Settings
    two_factor_enabled = models.BooleanField(default=False)
    last_password_change = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    
    # Activity Tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"
    
    @property
    def full_name(self):
        """Get user's full name"""
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username
    
    def has_permission(self, permission):
        """Check if user has specific permission based on role"""
        role_permissions = {
            'ADMIN': [
                'view_all_analyses', 'create_analysis', 'edit_analysis', 'delete_analysis',
                'manage_users', 'manage_threat_feeds', 'export_reports', 'system_config'
            ],
            'SECURITY_ANALYST': [
                'view_all_analyses', 'create_analysis', 'edit_analysis',
                'manage_threat_feeds', 'export_reports'
            ],
            'IT_STAFF': [
                'view_own_analyses', 'create_analysis', 'edit_own_analysis', 'export_reports'
            ],
            'GENERAL_USER': [
                'view_own_analyses', 'create_analysis'
            ],
            'VIEWER': [
                'view_own_analyses'
            ]
        }
        
        return permission in role_permissions.get(self.role, [])
    
    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock account if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            from django.utils import timezone
            from datetime import timedelta
            self.account_locked_until = timezone.now() + timedelta(hours=1)
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    @property
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            from django.utils import timezone
            return timezone.now() < self.account_locked_until
        return False


class ActivityLog(models.Model):
    """Model for logging user activities and system events"""
    
    ACTIVITY_TYPES = [
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('ANALYSIS_CREATE', 'Analysis Created'),
        ('ANALYSIS_VIEW', 'Analysis Viewed'),
        ('ANALYSIS_UPDATE', 'Analysis Updated'),
        ('ANALYSIS_DELETE', 'Analysis Deleted'),
        ('REPORT_GENERATE', 'Report Generated'),
        ('REPORT_EXPORT', 'Report Exported'),
        ('THREAT_FEED_UPDATE', 'Threat Feed Updated'),
        ('USER_CREATE', 'User Created'),
        ('USER_UPDATE', 'User Updated'),
        ('USER_DELETE', 'User Deleted'),
        ('PERMISSION_CHANGE', 'Permission Changed'),
        ('SYSTEM_CONFIG', 'System Configuration Changed'),
        ('API_ACCESS', 'API Access'),
        ('FILE_UPLOAD', 'File Uploaded'),
        ('FILE_DOWNLOAD', 'File Downloaded'),
        ('SECURITY_ALERT', 'Security Alert'),
        ('ERROR', 'System Error'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Basic Information
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    activity_type = models.CharField(max_length=25, choices=ACTIVITY_TYPES)
    description = models.TextField()
    
    # Context Information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_key = models.CharField(max_length=40, blank=True)
    
    # Related Object (Generic Foreign Key)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Additional Data
    additional_data = models.JSONField(default=dict, help_text="Additional context data")
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='LOW')
    
    # Success/Failure
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Timestamp
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Activity Log"
        verbose_name_plural = "Activity Logs"
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['activity_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
    
    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{user_str} - {self.activity_type} at {self.timestamp}"
    
    @classmethod
    def log_activity(cls, user, activity_type, description, ip_address=None, 
                    user_agent=None, content_object=None, additional_data=None, 
                    severity='LOW', success=True, error_message=''):
        """Convenience method to log activities"""
        return cls.objects.create(
            user=user,
            activity_type=activity_type,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent or '',
            content_object=content_object,
            additional_data=additional_data or {},
            severity=severity,
            success=success,
            error_message=error_message
        )


class UserSession(models.Model):
    """Model for tracking active user sessions"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='active_sessions')
    session_key = models.CharField(max_length=40, unique=True)
    
    # Session Information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Geographic Information
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Session Status
    is_active = models.BooleanField(default=True)
    last_activity = models.DateTimeField(auto_now=True)
    
    # Security Flags
    is_suspicious = models.BooleanField(default=False)
    risk_score = models.FloatField(default=0.0, help_text="Risk score from 0-100")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        ordering = ['-last_activity']
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address} ({self.created_at})"
    
    @property
    def is_expired(self):
        """Check if session is expired"""
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def mark_suspicious(self, reason=''):
        """Mark session as suspicious"""
        self.is_suspicious = True
        self.risk_score = min(self.risk_score + 25, 100)
        self.save(update_fields=['is_suspicious', 'risk_score'])
        
        # Log the suspicious activity
        ActivityLog.log_activity(
            user=self.user,
            activity_type='SECURITY_ALERT',
            description=f"Suspicious session activity detected: {reason}",
            ip_address=self.ip_address,
            severity='HIGH',
            additional_data={'session_id': self.session_key, 'reason': reason}
        )


class APIKey(models.Model):
    """Model for managing API keys for programmatic access"""
    
    KEY_TYPES = [
        ('FULL_ACCESS', 'Full Access'),
        ('READ_ONLY', 'Read Only'),
        ('ANALYSIS_ONLY', 'Analysis Only'),
        ('REPORTING_ONLY', 'Reporting Only'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    
    # Key Information
    name = models.CharField(max_length=255, help_text="Descriptive name for the API key")
    key = models.CharField(max_length=64, unique=True)
    key_type = models.CharField(max_length=20, choices=KEY_TYPES, default='READ_only')
    
    # Permissions and Restrictions
    allowed_ips = models.JSONField(default=list, help_text="List of allowed IP addresses")
    rate_limit = models.IntegerField(default=100, help_text="Requests per hour")
    
    # Usage Statistics
    total_requests = models.IntegerField(default=0)
    last_used = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
    
    def __str__(self):
        return f"{self.user.username} - {self.name} ({self.key_type})"
    
    def increment_usage(self):
        """Increment usage counter and update last used timestamp"""
        from django.utils import timezone
        self.total_requests += 1
        self.last_used = timezone.now()
        self.save(update_fields=['total_requests', 'last_used'])
    
    @property
    def is_expired(self):
        """Check if API key is expired"""
        if self.expires_at:
            from django.utils import timezone
            return timezone.now() > self.expires_at
        return False
    
    def is_ip_allowed(self, ip_address):
        """Check if IP address is allowed to use this key"""
        if not self.allowed_ips:
            return True  # No restrictions
        return ip_address in self.allowed_ips
