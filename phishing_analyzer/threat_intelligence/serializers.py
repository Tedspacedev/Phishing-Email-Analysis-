from rest_framework import serializers
from .models import (
    ThreatIndicator, IPReputation, DomainReputation,
    ThreatFeed, ThreatAttribution, ThreatIntelligenceReport
)


class ThreatIndicatorSerializer(serializers.ModelSerializer):
    """Serializer for threat indicators"""
    
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = ThreatIndicator
        fields = [
            'id', 'indicator_type', 'indicator_value', 'threat_level',
            'source_type', 'source_name', 'source_url', 'threat_category',
            'description', 'confidence_score', 'first_seen', 'last_seen',
            'times_seen', 'is_active', 'additional_data', 'created_by',
            'created_by_username'
        ]
        read_only_fields = ['id', 'first_seen', 'last_seen', 'times_seen', 'created_by_username']


class IPReputationSerializer(serializers.ModelSerializer):
    """Serializer for IP reputation data"""
    
    class Meta:
        model = IPReputation
        fields = [
            'id', 'ip_address', 'reputation', 'country', 'region', 'city',
            'latitude', 'longitude', 'isp', 'organization', 'asn',
            'is_tor_exit_node', 'is_proxy', 'is_vpn', 'is_malware_c2',
            'virustotal_score', 'virustotal_last_check', 'abuse_reports',
            'spam_reports', 'malware_reports', 'first_seen', 'last_updated'
        ]
        read_only_fields = ['id', 'first_seen', 'last_updated']


class DomainReputationSerializer(serializers.ModelSerializer):
    """Serializer for domain reputation data"""
    
    domain_age_days = serializers.ReadOnlyField()
    
    class Meta:
        model = DomainReputation
        fields = [
            'id', 'domain_name', 'reputation', 'registrar', 'creation_date',
            'expiration_date', 'last_updated', 'name_servers', 'mx_records',
            'a_records', 'registrant_name', 'registrant_email', 'registrant_country',
            'is_dga', 'is_typosquatting', 'is_parked', 'is_sinkholed',
            'virustotal_score', 'virustotal_last_check', 'phishing_reports',
            'malware_reports', 'spam_reports', 'first_seen', 'reputation_updated',
            'domain_age_days'
        ]
        read_only_fields = ['id', 'first_seen', 'reputation_updated', 'domain_age_days']


class ThreatFeedSerializer(serializers.ModelSerializer):
    """Serializer for threat feeds"""
    
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = ThreatFeed
        fields = [
            'id', 'name', 'description', 'feed_type', 'feed_format',
            'feed_url', 'api_key', 'headers', 'update_frequency',
            'is_active', 'auto_import', 'total_indicators', 'last_update',
            'last_successful_update', 'update_errors', 'created_at',
            'created_by', 'created_by_username'
        ]
        read_only_fields = [
            'id', 'total_indicators', 'last_update', 'last_successful_update',
            'update_errors', 'created_at', 'created_by_username'
        ]
        extra_kwargs = {
            'api_key': {'write_only': True}
        }


class ThreatAttributionSerializer(serializers.ModelSerializer):
    """Serializer for threat attribution data"""
    
    class Meta:
        model = ThreatAttribution
        fields = [
            'id', 'actor_name', 'actor_type', 'aliases', 'suspected_country',
            'operating_regions', 'attack_patterns', 'malware_families',
            'infrastructure', 'motivation', 'target_sectors', 'target_countries',
            'confidence_level', 'sources', 'first_observed', 'last_activity',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ThreatIntelligenceReportSerializer(serializers.ModelSerializer):
    """Serializer for threat intelligence reports"""
    
    author_username = serializers.CharField(source='author.username', read_only=True)
    threat_indicators_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatIntelligenceReport
        fields = [
            'id', 'title', 'report_type', 'severity', 'executive_summary',
            'detailed_analysis', 'recommendations', 'threat_indicators',
            'threat_indicators_count', 'attribution', 'tlp_classification',
            'tags', 'author', 'author_username', 'created_at', 'updated_at',
            'published_at', 'is_published'
        ]
        read_only_fields = [
            'id', 'author_username', 'threat_indicators_count', 'created_at',
            'updated_at', 'published_at'
        ]
    
    def get_threat_indicators_count(self, obj):
        return obj.threat_indicators.count()


class ThreatFeedUpdateSerializer(serializers.Serializer):
    """Serializer for threat feed update operations"""
    
    feed_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of feed IDs to update. If empty, all active feeds will be updated."
    )
    
    force_update = serializers.BooleanField(
        default=False,
        help_text="Force update even if last update was recent"
    )


class ThreatAnalysisSerializer(serializers.Serializer):
    """Serializer for threat analysis requests"""
    
    ANALYSIS_TYPES = [
        ('DOMAIN', 'Domain Analysis'),
        ('IP', 'IP Analysis'),
        ('URL', 'URL Analysis'),
        ('HASH', 'File Hash Analysis'),
    ]
    
    analysis_type = serializers.ChoiceField(choices=ANALYSIS_TYPES)
    target = serializers.CharField(max_length=2000, help_text="Target to analyze (domain, IP, URL, or hash)")
    include_virustotal = serializers.BooleanField(default=True)
    include_whois = serializers.BooleanField(default=True)
    include_dns = serializers.BooleanField(default=True)
    
    def validate_target(self, value):
        """Validate target based on analysis type"""
        analysis_type = self.initial_data.get('analysis_type')
        
        if analysis_type == 'IP':
            import ipaddress
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise serializers.ValidationError("Invalid IP address format")
        
        elif analysis_type == 'DOMAIN':
            if not value or '.' not in value:
                raise serializers.ValidationError("Invalid domain format")
        
        elif analysis_type == 'URL':
            from django.core.validators import URLValidator
            validator = URLValidator()
            try:
                validator(value)
            except:
                raise serializers.ValidationError("Invalid URL format")
        
        elif analysis_type == 'HASH':
            if not value or len(value) not in [32, 40, 64]:  # MD5, SHA1, SHA256
                raise serializers.ValidationError("Invalid hash format")
        
        return value


class ThreatSearchSerializer(serializers.Serializer):
    """Serializer for threat intelligence search"""
    
    query = serializers.CharField(max_length=500, help_text="Search query")
    indicator_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by indicator types"
    )
    threat_levels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by threat levels"
    )
    source_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by source types"
    )
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)
    limit = serializers.IntegerField(default=100, max_value=1000)


class ThreatStatsSerializer(serializers.Serializer):
    """Serializer for threat intelligence statistics"""
    
    total_indicators = serializers.IntegerField()
    active_indicators = serializers.IntegerField()
    
    # By type
    indicators_by_type = serializers.DictField()
    
    # By threat level
    indicators_by_threat_level = serializers.DictField()
    
    # By source
    indicators_by_source = serializers.DictField()
    
    # Recent activity
    new_indicators_today = serializers.IntegerField()
    new_indicators_week = serializers.IntegerField()
    new_indicators_month = serializers.IntegerField()
    
    # Top threats
    top_domains = serializers.ListField(child=serializers.DictField())
    top_ips = serializers.ListField(child=serializers.DictField())
    
    # Feed statistics
    active_feeds = serializers.IntegerField()
    total_feeds = serializers.IntegerField()
    feeds_with_errors = serializers.IntegerField()


class IOCExportSerializer(serializers.Serializer):
    """Serializer for IOC export functionality"""
    
    EXPORT_FORMATS = [
        ('JSON', 'JSON'),
        ('CSV', 'CSV'),
        ('STIX', 'STIX 2.0'),
        ('YARA', 'YARA Rules'),
        ('MISP', 'MISP Format'),
    ]
    
    format = serializers.ChoiceField(choices=EXPORT_FORMATS, default='JSON')
    indicator_types = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by indicator types"
    )
    threat_levels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by threat levels"
    )
    date_from = serializers.DateTimeField(required=False)
    date_to = serializers.DateTimeField(required=False)
    include_inactive = serializers.BooleanField(default=False)
    
    def validate(self, data):
        """Validate export parameters"""
        if data.get('date_from') and data.get('date_to'):
            if data['date_from'] >= data['date_to']:
                raise serializers.ValidationError(
                    "date_from must be earlier than date_to"
                )
        return data