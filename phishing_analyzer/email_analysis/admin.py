from django.contrib import admin
from .models import (
    EmailAnalysis, EmailHeader, URLAnalysis, 
    AttachmentAnalysis, PhishingTechnique
)


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):
    """Admin configuration for EmailAnalysis model"""
    
    list_display = [
        'id', 'sender_email', 'recipient_email', 'email_subject',
        'risk_level', 'phishing_score', 'is_phishing', 'status',
        'analyzed_by', 'created_at'
    ]
    
    list_filter = [
        'risk_level', 'is_phishing', 'status', 'analyzed_by',
        'created_at', 'updated_at'
    ]
    
    search_fields = [
        'sender_email', 'recipient_email', 'email_subject',
        'analyzed_by__username'
    ]
    
    readonly_fields = [
        'id', 'phishing_score', 'is_phishing', 'threat_count',
        'analysis_duration', 'created_at', 'updated_at'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'email_subject', 'sender_email', 'recipient_email',
                'analyzed_by', 'status'
            )
        }),
        ('Analysis Results', {
            'fields': (
                'risk_level', 'phishing_score', 'is_phishing',
                'threat_count', 'analysis_duration'
            )
        }),
        ('Content', {
            'fields': ('email_body', 'raw_email'),
            'classes': ('collapse',)
        }),
        ('Analysis Details', {
            'fields': ('threat_indicators', 'analysis_summary', 'recommendations'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']
    date_hierarchy = 'created_at'


@admin.register(EmailHeader)
class EmailHeaderAdmin(admin.ModelAdmin):
    """Admin configuration for EmailHeader model"""
    
    list_display = [
        'id', 'email_analysis', 'message_id', 'originating_ip',
        'spf_result', 'dkim_result', 'dmarc_result', 'sender_country'
    ]
    
    list_filter = [
        'spf_result', 'dkim_result', 'dmarc_result',
        'sender_country', 'created_at'
    ]
    
    search_fields = [
        'message_id', 'originating_ip', 'sender_country',
        'email_analysis__sender_email'
    ]
    
    readonly_fields = ['id', 'created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'email_analysis', 'message_id', 'return_path')
        }),
        ('Authentication Results', {
            'fields': ('spf_result', 'dkim_result', 'dmarc_result')
        }),
        ('Routing Information', {
            'fields': ('originating_ip', 'mail_servers', 'received_headers')
        }),
        ('Geolocation', {
            'fields': ('sender_country', 'sender_region')
        }),
        ('Suspicious Indicators', {
            'fields': ('header_inconsistencies', 'spoofing_indicators'),
            'classes': ('collapse',)
        }),
        ('Raw Data', {
            'fields': ('raw_headers',),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']


@admin.register(URLAnalysis)
class URLAnalysisAdmin(admin.ModelAdmin):
    """Admin configuration for URLAnalysis model"""
    
    list_display = [
        'id', 'email_analysis', 'domain', 'threat_level',
        'is_shortened', 'virustotal_detected', 'redirect_count'
    ]
    
    list_filter = [
        'threat_level', 'is_shortened', 'virustotal_detected',
        'is_typosquatting', 'created_at'
    ]
    
    search_fields = [
        'original_url', 'final_url', 'domain',
        'email_analysis__sender_email'
    ]
    
    readonly_fields = ['id', 'created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'email_analysis', 'original_url', 'final_url', 'domain')
        }),
        ('Analysis Results', {
            'fields': (
                'threat_level', 'is_shortened', 'redirect_count',
                'is_typosquatting', 'http_status_code', 'response_time'
            )
        }),
        ('Domain Information', {
            'fields': ('domain_age', 'domain_registrar')
        }),
        ('VirusTotal Results', {
            'fields': ('virustotal_detected', 'virustotal_score'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']


@admin.register(AttachmentAnalysis)
class AttachmentAnalysisAdmin(admin.ModelAdmin):
    """Admin configuration for AttachmentAnalysis model"""
    
    list_display = [
        'id', 'email_analysis', 'filename', 'file_type',
        'threat_level', 'is_executable', 'has_macros', 'virustotal_detected'
    ]
    
    list_filter = [
        'threat_level', 'file_type', 'is_executable',
        'has_macros', 'virustotal_detected', 'created_at'
    ]
    
    search_fields = [
        'filename', 'file_type', 'mime_type',
        'email_analysis__sender_email'
    ]
    
    readonly_fields = ['id', 'created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'email_analysis', 'filename', 'file_size',
                'file_type', 'mime_type'
            )
        }),
        ('Hash Analysis', {
            'fields': ('md5_hash', 'sha1_hash', 'sha256_hash')
        }),
        ('Analysis Results', {
            'fields': ('threat_level', 'is_executable', 'has_macros')
        }),
        ('VirusTotal Results', {
            'fields': ('virustotal_detected', 'virustotal_score', 'detection_engines'),
            'classes': ('collapse',)
        }),
        ('Content Analysis', {
            'fields': ('embedded_urls', 'suspicious_strings'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']


@admin.register(PhishingTechnique)
class PhishingTechniqueAdmin(admin.ModelAdmin):
    """Admin configuration for PhishingTechnique model"""
    
    list_display = [
        'id', 'email_analysis', 'technique_type', 'technique_name',
        'confidence_score', 'created_at'
    ]
    
    list_filter = [
        'technique_type', 'created_at'
    ]
    
    search_fields = [
        'technique_name', 'description',
        'email_analysis__sender_email'
    ]
    
    readonly_fields = ['id', 'created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'email_analysis', 'technique_type',
                'technique_name', 'confidence_score'
            )
        }),
        ('Details', {
            'fields': ('description', 'evidence')
        })
    )
    
    ordering = ['-confidence_score', '-created_at']
