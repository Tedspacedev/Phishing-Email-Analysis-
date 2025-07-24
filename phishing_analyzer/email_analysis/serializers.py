from rest_framework import serializers
from .models import (
    EmailAnalysis, EmailHeader, URLAnalysis, 
    AttachmentAnalysis, PhishingTechnique
)


class URLAnalysisSerializer(serializers.ModelSerializer):
    """Serializer for URL analysis results"""
    
    class Meta:
        model = URLAnalysis
        fields = [
            'id', 'original_url', 'final_url', 'domain', 'threat_level',
            'is_shortened', 'redirect_count', 'virustotal_score',
            'virustotal_detected', 'domain_age', 'domain_registrar',
            'is_typosquatting', 'http_status_code', 'response_time',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class AttachmentAnalysisSerializer(serializers.ModelSerializer):
    """Serializer for attachment analysis results"""
    
    class Meta:
        model = AttachmentAnalysis
        fields = [
            'id', 'filename', 'file_size', 'file_type', 'mime_type',
            'md5_hash', 'sha1_hash', 'sha256_hash', 'threat_level',
            'is_executable', 'has_macros', 'virustotal_score',
            'virustotal_detected', 'detection_engines', 'embedded_urls',
            'suspicious_strings', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class PhishingTechniqueSerializer(serializers.ModelSerializer):
    """Serializer for phishing technique detection results"""
    
    class Meta:
        model = PhishingTechnique
        fields = [
            'id', 'technique_type', 'technique_name', 'description',
            'confidence_score', 'evidence', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class EmailHeaderSerializer(serializers.ModelSerializer):
    """Serializer for email header analysis"""
    
    class Meta:
        model = EmailHeader
        fields = [
            'id', 'raw_headers', 'message_id', 'return_path',
            'received_headers', 'spf_result', 'dkim_result', 'dmarc_result',
            'originating_ip', 'mail_servers', 'header_inconsistencies',
            'spoofing_indicators', 'sender_country', 'sender_region',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class EmailAnalysisSerializer(serializers.ModelSerializer):
    """Serializer for email analysis results"""
    
    # Nested serializers for related objects
    url_analyses = URLAnalysisSerializer(many=True, read_only=True)
    attachment_analyses = AttachmentAnalysisSerializer(many=True, read_only=True)
    phishing_techniques = PhishingTechniqueSerializer(many=True, read_only=True)
    header_analysis = EmailHeaderSerializer(read_only=True)
    
    # Additional computed fields
    threat_count = serializers.ReadOnlyField()
    analyzed_by_username = serializers.CharField(source='analyzed_by.username', read_only=True)
    
    class Meta:
        model = EmailAnalysis
        fields = [
            'id', 'email_subject', 'sender_email', 'recipient_email',
            'email_body', 'raw_email', 'risk_level', 'phishing_score',
            'is_phishing', 'status', 'analyzed_by', 'analyzed_by_username',
            'created_at', 'updated_at', 'analysis_duration',
            'threat_indicators', 'threat_count', 'analysis_summary',
            'recommendations', 'url_analyses', 'attachment_analyses',
            'phishing_techniques', 'header_analysis'
        ]
        read_only_fields = [
            'id', 'risk_level', 'phishing_score', 'is_phishing',
            'status', 'analyzed_by', 'analyzed_by_username', 'created_at',
            'updated_at', 'analysis_duration', 'threat_indicators',
            'threat_count', 'analysis_summary', 'recommendations'
        ]
        extra_kwargs = {
            'raw_email': {'write_only': True},
            'email_body': {'write_only': True}
        }
    
    def validate_raw_email(self, value):
        """Validate that the raw email is properly formatted"""
        if not value or len(value.strip()) == 0:
            raise serializers.ValidationError("Raw email content cannot be empty")
        
        # Basic validation for email format
        if 'From:' not in value or 'To:' not in value:
            raise serializers.ValidationError("Invalid email format - missing required headers")
        
        return value
    
    def validate_sender_email(self, value):
        """Validate sender email format"""
        if not value or '@' not in value:
            raise serializers.ValidationError("Invalid sender email format")
        return value.lower()
    
    def validate_recipient_email(self, value):
        """Validate recipient email format"""
        if not value or '@' not in value:
            raise serializers.ValidationError("Invalid recipient email format")
        return value.lower()


class EmailAnalysisCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new email analysis"""
    
    class Meta:
        model = EmailAnalysis
        fields = [
            'email_subject', 'sender_email', 'recipient_email',
            'email_body', 'raw_email'
        ]
    
    def create(self, validated_data):
        """Create new email analysis and set initial status"""
        validated_data['status'] = 'PENDING'
        validated_data['analyzed_by'] = self.context['request'].user
        return super().create(validated_data)


class EmailAnalysisListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for email analysis list view"""
    
    analyzed_by_username = serializers.CharField(source='analyzed_by.username', read_only=True)
    threat_count = serializers.ReadOnlyField()
    
    class Meta:
        model = EmailAnalysis
        fields = [
            'id', 'email_subject', 'sender_email', 'recipient_email',
            'risk_level', 'phishing_score', 'is_phishing', 'status',
            'analyzed_by_username', 'threat_count', 'created_at',
            'updated_at', 'analysis_duration'
        ]
        read_only_fields = [
            'id', 'risk_level', 'phishing_score', 'is_phishing', 'status',
            'analyzed_by_username', 'threat_count', 'created_at',
            'updated_at', 'analysis_duration'
        ]


class EmailAnalysisStatsSerializer(serializers.Serializer):
    """Serializer for email analysis statistics"""
    
    total_analyses = serializers.IntegerField()
    pending_analyses = serializers.IntegerField()
    completed_analyses = serializers.IntegerField()
    failed_analyses = serializers.IntegerField()
    phishing_detected = serializers.IntegerField()
    
    # Risk level breakdown
    low_risk = serializers.IntegerField()
    medium_risk = serializers.IntegerField()
    high_risk = serializers.IntegerField()
    critical_risk = serializers.IntegerField()
    
    # Time-based stats
    analyses_today = serializers.IntegerField()
    analyses_this_week = serializers.IntegerField()
    analyses_this_month = serializers.IntegerField()
    
    # Average metrics
    avg_phishing_score = serializers.FloatField()
    avg_analysis_duration = serializers.FloatField()
    
    # Top threats
    top_threat_indicators = serializers.ListField(child=serializers.DictField())
    top_malicious_domains = serializers.ListField(child=serializers.DictField())


class BulkEmailAnalysisSerializer(serializers.Serializer):
    """Serializer for bulk email analysis upload"""
    
    emails = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        max_length=100,
        help_text="List of email objects to analyze"
    )
    
    def validate_emails(self, value):
        """Validate each email in the bulk upload"""
        required_fields = ['sender_email', 'recipient_email', 'raw_email']
        
        for i, email_data in enumerate(value):
            for field in required_fields:
                if field not in email_data:
                    raise serializers.ValidationError(
                        f"Email {i+1}: Missing required field '{field}'"
                    )
            
            # Validate email addresses
            for email_field in ['sender_email', 'recipient_email']:
                email_addr = email_data.get(email_field, '')
                if not email_addr or '@' not in email_addr:
                    raise serializers.ValidationError(
                        f"Email {i+1}: Invalid {email_field} format"
                    )
        
        return value


class EmailAnalysisReportSerializer(serializers.Serializer):
    """Serializer for generating analysis reports"""
    
    REPORT_FORMATS = [
        ('JSON', 'JSON'),
        ('PDF', 'PDF'),
        ('CSV', 'CSV'),
        ('XML', 'XML')
    ]
    
    REPORT_TYPES = [
        ('SUMMARY', 'Summary Report'),
        ('DETAILED', 'Detailed Analysis'),
        ('THREATS', 'Threat Intelligence'),
        ('STATISTICS', 'Statistical Analysis')
    ]
    
    analysis_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of analysis IDs to include in report"
    )
    
    date_from = serializers.DateTimeField(
        required=False,
        help_text="Start date for report data"
    )
    
    date_to = serializers.DateTimeField(
        required=False,
        help_text="End date for report data"
    )
    
    report_format = serializers.ChoiceField(
        choices=REPORT_FORMATS,
        default='JSON',
        help_text="Output format for the report"
    )
    
    report_type = serializers.ChoiceField(
        choices=REPORT_TYPES,
        default='SUMMARY',
        help_text="Type of report to generate"
    )
    
    include_attachments = serializers.BooleanField(
        default=False,
        help_text="Include attachment analysis in report"
    )
    
    include_urls = serializers.BooleanField(
        default=True,
        help_text="Include URL analysis in report"
    )
    
    include_headers = serializers.BooleanField(
        default=False,
        help_text="Include header analysis in report"
    )
    
    def validate(self, data):
        """Validate report parameters"""
        if not data.get('analysis_ids') and not (data.get('date_from') and data.get('date_to')):
            raise serializers.ValidationError(
                "Either analysis_ids or date range (date_from and date_to) must be provided"
            )
        
        if data.get('date_from') and data.get('date_to'):
            if data['date_from'] >= data['date_to']:
                raise serializers.ValidationError(
                    "date_from must be earlier than date_to"
                )
        
        return data