from django.contrib import admin
from .models import (
    ThreatIndicator, IPReputation, DomainReputation,
    ThreatFeed, ThreatAttribution, ThreatIntelligenceReport
)


@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    """Admin configuration for ThreatIndicator model"""
    
    list_display = [
        'id', 'indicator_type', 'indicator_value', 'threat_level',
        'source_type', 'confidence_score', 'times_seen', 'is_active',
        'last_seen'
    ]
    
    list_filter = [
        'indicator_type', 'threat_level', 'source_type',
        'is_active', 'first_seen', 'last_seen'
    ]
    
    search_fields = [
        'indicator_value', 'description', 'threat_category',
        'source_name'
    ]
    
    readonly_fields = ['id', 'first_seen', 'last_seen', 'times_seen']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'indicator_type', 'indicator_value', 'threat_level',
                'threat_category', 'is_active'
            )
        }),
        ('Source Information', {
            'fields': ('source_type', 'source_name', 'source_url')
        }),
        ('Analysis', {
            'fields': ('description', 'confidence_score', 'additional_data')
        }),
        ('Statistics', {
            'fields': ('first_seen', 'last_seen', 'times_seen'),
            'classes': ('collapse',)
        }),
        ('Attribution', {
            'fields': ('created_by',),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-last_seen']
    date_hierarchy = 'last_seen'


@admin.register(IPReputation)
class IPReputationAdmin(admin.ModelAdmin):
    """Admin configuration for IPReputation model"""
    
    list_display = [
        'id', 'ip_address', 'reputation', 'country', 'isp',
        'is_tor_exit_node', 'is_proxy', 'is_vpn', 'last_updated'
    ]
    
    list_filter = [
        'reputation', 'country', 'is_tor_exit_node',
        'is_proxy', 'is_vpn', 'is_malware_c2', 'last_updated'
    ]
    
    search_fields = ['ip_address', 'isp', 'organization', 'asn']
    
    readonly_fields = ['id', 'first_seen', 'last_updated']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'ip_address', 'reputation')
        }),
        ('Geolocation', {
            'fields': (
                'country', 'region', 'city',
                'latitude', 'longitude'
            )
        }),
        ('ISP Information', {
            'fields': ('isp', 'organization', 'asn')
        }),
        ('Threat Intelligence', {
            'fields': (
                'is_tor_exit_node', 'is_proxy', 'is_vpn', 'is_malware_c2'
            )
        }),
        ('VirusTotal Data', {
            'fields': ('virustotal_score', 'virustotal_last_check'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': (
                'abuse_reports', 'spam_reports', 'malware_reports',
                'first_seen', 'last_updated'
            ),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-last_updated']


@admin.register(DomainReputation)
class DomainReputationAdmin(admin.ModelAdmin):
    """Admin configuration for DomainReputation model"""
    
    list_display = [
        'id', 'domain_name', 'reputation', 'registrar',
        'is_dga', 'is_typosquatting', 'domain_age_days', 'reputation_updated'
    ]
    
    list_filter = [
        'reputation', 'is_dga', 'is_typosquatting',
        'is_parked', 'is_sinkholed', 'reputation_updated'
    ]
    
    search_fields = [
        'domain_name', 'registrar', 'registrant_name',
        'registrant_email'
    ]
    
    readonly_fields = ['id', 'domain_age_days', 'first_seen', 'reputation_updated']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'domain_name', 'reputation')
        }),
        ('Registration Data', {
            'fields': (
                'registrar', 'creation_date', 'expiration_date',
                'last_updated', 'domain_age_days'
            )
        }),
        ('DNS Information', {
            'fields': ('name_servers', 'mx_records', 'a_records'),
            'classes': ('collapse',)
        }),
        ('WHOIS Data', {
            'fields': (
                'registrant_name', 'registrant_email', 'registrant_country'
            ),
            'classes': ('collapse',)
        }),
        ('Threat Intelligence', {
            'fields': (
                'is_dga', 'is_typosquatting', 'is_parked', 'is_sinkholed'
            )
        }),
        ('VirusTotal Data', {
            'fields': ('virustotal_score', 'virustotal_last_check'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': (
                'phishing_reports', 'malware_reports', 'spam_reports',
                'first_seen', 'reputation_updated'
            ),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-reputation_updated']


@admin.register(ThreatFeed)
class ThreatFeedAdmin(admin.ModelAdmin):
    """Admin configuration for ThreatFeed model"""
    
    list_display = [
        'id', 'name', 'feed_type', 'feed_format', 'is_active',
        'total_indicators', 'last_successful_update', 'update_errors'
    ]
    
    list_filter = [
        'feed_type', 'feed_format', 'is_active',
        'auto_import', 'created_at'
    ]
    
    search_fields = ['name', 'description', 'feed_url']
    
    readonly_fields = [
        'id', 'total_indicators', 'last_update',
        'last_successful_update', 'update_errors', 'created_at'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'name', 'description', 'feed_type', 'feed_format')
        }),
        ('Configuration', {
            'fields': (
                'feed_url', 'api_key', 'headers',
                'update_frequency', 'is_active', 'auto_import'
            )
        }),
        ('Statistics', {
            'fields': (
                'total_indicators', 'last_update',
                'last_successful_update', 'update_errors'
            ),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by'),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['name']


@admin.register(ThreatAttribution)
class ThreatAttributionAdmin(admin.ModelAdmin):
    """Admin configuration for ThreatAttribution model"""
    
    list_display = [
        'id', 'actor_name', 'actor_type', 'suspected_country',
        'confidence_level', 'first_observed', 'last_activity'
    ]
    
    list_filter = [
        'actor_type', 'suspected_country',
        'first_observed', 'last_activity'
    ]
    
    search_fields = [
        'actor_name', 'aliases', 'motivation',
        'suspected_country'
    ]
    
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'actor_name', 'actor_type', 'aliases',
                'suspected_country'
            )
        }),
        ('Geographic Information', {
            'fields': ('operating_regions',)
        }),
        ('TTPs', {
            'fields': (
                'attack_patterns', 'malware_families', 'infrastructure'
            ),
            'classes': ('collapse',)
        }),
        ('Targeting', {
            'fields': ('motivation', 'target_sectors', 'target_countries'),
            'classes': ('collapse',)
        }),
        ('Analysis', {
            'fields': ('confidence_level', 'sources')
        }),
        ('Timeline', {
            'fields': (
                'first_observed', 'last_activity',
                'created_at', 'updated_at'
            ),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-last_activity']


@admin.register(ThreatIntelligenceReport)
class ThreatIntelligenceReportAdmin(admin.ModelAdmin):
    """Admin configuration for ThreatIntelligenceReport model"""
    
    list_display = [
        'id', 'title', 'report_type', 'severity',
        'author', 'is_published', 'created_at'
    ]
    
    list_filter = [
        'report_type', 'severity', 'is_published',
        'tlp_classification', 'created_at'
    ]
    
    search_fields = [
        'title', 'executive_summary', 'tags',
        'author__username'
    ]
    
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'published_at'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'id', 'title', 'report_type', 'severity',
                'tlp_classification', 'tags'
            )
        }),
        ('Content', {
            'fields': (
                'executive_summary', 'detailed_analysis', 'recommendations'
            )
        }),
        ('Associated Data', {
            'fields': ('threat_indicators', 'attribution'),
            'classes': ('collapse',)
        }),
        ('Publication', {
            'fields': (
                'author', 'is_published', 'published_at',
                'created_at', 'updated_at'
            ),
            'classes': ('collapse',)
        })
    )
    
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
