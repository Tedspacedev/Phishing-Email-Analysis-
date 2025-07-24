from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile, ActivityLog, UserSession, APIKey


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    
    fieldsets = (
        ('Role & Department', {
            'fields': ('role', 'department', 'employee_id')
        }),
        ('Contact Information', {
            'fields': ('phone_number',)
        }),
        ('Preferences', {
            'fields': ('email_notifications', 'dashboard_layout', 'timezone')
        }),
        ('Security', {
            'fields': ('two_factor_enabled',),
            'classes': ('collapse',)
        })
    )


class UserAdmin(BaseUserAdmin):
    """Extended User admin with profile"""
    inlines = (UserProfileInline,)
    
    list_display = BaseUserAdmin.list_display + ('get_role', 'get_department', 'get_last_activity')
    list_filter = BaseUserAdmin.list_filter + ('profile__role', 'profile__department')
    
    def get_role(self, obj):
        try:
            return obj.profile.get_role_display()
        except UserProfile.DoesNotExist:
            return 'No Profile'
    get_role.short_description = 'Role'
    
    def get_department(self, obj):
        try:
            return obj.profile.get_department_display()
        except UserProfile.DoesNotExist:
            return 'No Profile'
    get_department.short_description = 'Department'
    
    def get_last_activity(self, obj):
        try:
            return obj.profile.last_activity
        except UserProfile.DoesNotExist:
            return None
    get_last_activity.short_description = 'Last Activity'


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin configuration for UserProfile model"""
    
    list_display = [
        'user', 'role', 'department', 'phone_number',
        'two_factor_enabled', 'failed_login_attempts',
        'is_account_locked', 'last_activity'
    ]
    
    list_filter = [
        'role', 'department', 'two_factor_enabled',
        'email_notifications', 'created_at'
    ]
    
    search_fields = [
        'user__username', 'user__first_name', 'user__last_name',
        'user__email', 'phone_number', 'employee_id'
    ]
    
    readonly_fields = [
        'id', 'failed_login_attempts', 'account_locked_until',
        'last_login_ip', 'last_activity', 'created_at', 'updated_at',
        'is_account_locked', 'full_name'
    ]
    
    fieldsets = (
        ('User Information', {
            'fields': ('id', 'user', 'full_name')
        }),
        ('Role & Department', {
            'fields': ('role', 'department', 'employee_id')
        }),
        ('Contact Information', {
            'fields': ('phone_number',)
        }),
        ('Preferences', {
            'fields': ('email_notifications', 'dashboard_layout', 'timezone')
        }),
        ('Security', {
            'fields': (
                'two_factor_enabled', 'last_password_change',
                'failed_login_attempts', 'account_locked_until',
                'is_account_locked'
            ),
            'classes': ('collapse',)
        }),
        ('Activity Tracking', {
            'fields': ('last_login_ip', 'last_activity'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['user__username']


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    """Admin configuration for ActivityLog model"""
    
    list_display = [
        'id', 'user', 'activity_type', 'description',
        'severity', 'success', 'ip_address', 'timestamp'
    ]
    
    list_filter = [
        'activity_type', 'severity', 'success',
        'timestamp', 'user'
    ]
    
    search_fields = [
        'user__username', 'description', 'ip_address',
        'user_agent', 'error_message'
    ]
    
    readonly_fields = [
        'id', 'user', 'activity_type', 'description', 'ip_address',
        'user_agent', 'session_key', 'content_type', 'object_id',
        'additional_data', 'severity', 'success', 'error_message', 'timestamp'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'user', 'activity_type', 'description',
                'severity', 'success'
            )
        }),
        ('Request Information', {
            'fields': ('ip_address', 'user_agent', 'session_key')
        }),
        ('Content Object', {
            'fields': ('content_type', 'object_id'),
            'classes': ('collapse',)
        }),
        ('Additional Data', {
            'fields': ('additional_data', 'error_message'),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('timestamp',)
        })
    )
    
    ordering = ['-timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin configuration for UserSession model"""
    
    list_display = [
        'id', 'user', 'ip_address', 'country', 'city',
        'is_active', 'is_suspicious', 'risk_score',
        'last_activity', 'is_expired'
    ]
    
    list_filter = [
        'is_active', 'is_suspicious', 'country',
        'created_at', 'last_activity'
    ]
    
    search_fields = [
        'user__username', 'ip_address', 'user_agent',
        'country', 'city', 'session_key'
    ]
    
    readonly_fields = [
        'id', 'session_key', 'created_at', 'is_expired'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'user', 'session_key', 'ip_address',
                'is_active', 'last_activity'
            )
        }),
        ('Geolocation', {
            'fields': ('country', 'city')
        }),
        ('Security Analysis', {
            'fields': ('is_suspicious', 'risk_score'),
            'classes': ('collapse',)
        }),
        ('Technical Details', {
            'fields': ('user_agent',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'expires_at', 'is_expired'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-last_activity']
    date_hierarchy = 'last_activity'
    
    actions = ['terminate_sessions', 'mark_suspicious']
    
    def terminate_sessions(self, request, queryset):
        """Terminate selected sessions"""
        count = queryset.update(is_active=False)
        self.message_user(
            request,
            f'Successfully terminated {count} sessions.'
        )
    terminate_sessions.short_description = "Terminate selected sessions"
    
    def mark_suspicious(self, request, queryset):
        """Mark selected sessions as suspicious"""
        count = queryset.update(is_suspicious=True)
        self.message_user(
            request,
            f'Successfully marked {count} sessions as suspicious.'
        )
    mark_suspicious.short_description = "Mark selected sessions as suspicious"


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """Admin configuration for APIKey model"""
    
    list_display = [
        'id', 'user', 'name', 'key_type', 'is_active',
        'total_requests', 'last_used', 'is_expired'
    ]
    
    list_filter = [
        'key_type', 'is_active', 'created_at', 'expires_at'
    ]
    
    search_fields = [
        'user__username', 'name', 'key'
    ]
    
    readonly_fields = [
        'id', 'key', 'total_requests', 'last_used',
        'created_at', 'updated_at', 'is_expired'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'user', 'name', 'key_type', 'is_active')
        }),
        ('API Key', {
            'fields': ('key',),
            'classes': ('collapse',)
        }),
        ('Configuration', {
            'fields': ('allowed_ips', 'rate_limit', 'expires_at')
        }),
        ('Usage Statistics', {
            'fields': ('total_requests', 'last_used'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'is_expired'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']
    
    actions = ['regenerate_keys', 'deactivate_keys']
    
    def regenerate_keys(self, request, queryset):
        """Regenerate selected API keys"""
        import secrets
        
        count = 0
        for api_key in queryset:
            api_key.key = secrets.token_urlsafe(48)
            api_key.save()
            count += 1
        
        self.message_user(
            request,
            f'Successfully regenerated {count} API keys.'
        )
    regenerate_keys.short_description = "Regenerate selected API keys"
    
    def deactivate_keys(self, request, queryset):
        """Deactivate selected API keys"""
        count = queryset.update(is_active=False)
        self.message_user(
            request,
            f'Successfully deactivated {count} API keys.'
        )
    deactivate_keys.short_description = "Deactivate selected API keys"
