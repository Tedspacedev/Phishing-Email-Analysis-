from django.db import models
from django.core.validators import URLValidator
from django.contrib.auth.models import User
import json


class ThreatIndicator(models.Model):
    """Model for storing threat indicators from various sources"""
    
    INDICATOR_TYPES = [
        ('IP', 'IP Address'),
        ('DOMAIN', 'Domain Name'),
        ('URL', 'URL'),
        ('EMAIL', 'Email Address'),
        ('HASH', 'File Hash'),
        ('EMAIL_SUBJECT', 'Email Subject Pattern'),
    ]
    
    THREAT_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    SOURCE_TYPES = [
        ('VIRUSTOTAL', 'VirusTotal'),
        ('WHOIS', 'WHOIS'),
        ('INTERNAL', 'Internal Analysis'),
        ('THREAT_FEED', 'Threat Feed'),
        ('MANUAL', 'Manual Entry'),
    ]
    
    # Basic Information
    indicator_type = models.CharField(max_length=20, choices=INDICATOR_TYPES)
    indicator_value = models.CharField(max_length=2000)
    threat_level = models.CharField(max_length=10, choices=THREAT_LEVELS)
    
    # Source Information
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    source_name = models.CharField(max_length=255, blank=True)
    source_url = models.URLField(blank=True)
    
    # Threat Details
    threat_category = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    confidence_score = models.FloatField(default=0.0, help_text="Confidence score from 0-100")
    
    # Metadata
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    times_seen = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)
    
    # Additional Data
    additional_data = models.JSONField(default=dict, help_text="Additional threat intelligence data")
    
    # Attribution
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-last_seen']
        unique_together = ['indicator_type', 'indicator_value', 'source_type']
        verbose_name = "Threat Indicator"
        verbose_name_plural = "Threat Indicators"
    
    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value} ({self.threat_level})"
    
    def increment_seen_count(self):
        """Increment the times_seen counter and update last_seen"""
        self.times_seen += 1
        self.save(update_fields=['times_seen', 'last_seen'])


class IPReputation(models.Model):
    """Model for storing IP address reputation data"""
    
    REPUTATION_LEVELS = [
        ('TRUSTED', 'Trusted'),
        ('NEUTRAL', 'Neutral'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True)
    reputation = models.CharField(max_length=15, choices=REPUTATION_LEVELS, default='NEUTRAL')
    
    # Geolocation
    country = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    
    # ISP Information
    isp = models.CharField(max_length=255, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    asn = models.CharField(max_length=50, blank=True, help_text="Autonomous System Number")
    
    # Threat Intelligence
    is_tor_exit_node = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    is_vpn = models.BooleanField(default=False)
    is_malware_c2 = models.BooleanField(default=False)
    
    # VirusTotal Data
    virustotal_score = models.JSONField(null=True, blank=True)
    virustotal_last_check = models.DateTimeField(null=True, blank=True)
    
    # Statistics
    abuse_reports = models.IntegerField(default=0)
    spam_reports = models.IntegerField(default=0)
    malware_reports = models.IntegerField(default=0)
    
    # Metadata
    first_seen = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-last_updated']
        verbose_name = "IP Reputation"
        verbose_name_plural = "IP Reputations"
    
    def __str__(self):
        return f"{self.ip_address} ({self.reputation})"


class DomainReputation(models.Model):
    """Model for storing domain reputation data"""
    
    REPUTATION_LEVELS = [
        ('TRUSTED', 'Trusted'),
        ('NEUTRAL', 'Neutral'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
    ]
    
    domain_name = models.CharField(max_length=255, unique=True)
    reputation = models.CharField(max_length=15, choices=REPUTATION_LEVELS, default='NEUTRAL')
    
    # Domain Information
    registrar = models.CharField(max_length=255, blank=True)
    creation_date = models.DateTimeField(null=True, blank=True)
    expiration_date = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    
    # DNS Information
    name_servers = models.JSONField(default=list)
    mx_records = models.JSONField(default=list)
    a_records = models.JSONField(default=list)
    
    # WHOIS Data
    registrant_name = models.CharField(max_length=255, blank=True)
    registrant_email = models.EmailField(blank=True)
    registrant_country = models.CharField(max_length=100, blank=True)
    
    # Threat Intelligence
    is_dga = models.BooleanField(default=False, help_text="Domain Generation Algorithm")
    is_typosquatting = models.BooleanField(default=False)
    is_parked = models.BooleanField(default=False)
    is_sinkholed = models.BooleanField(default=False)
    
    # VirusTotal Data
    virustotal_score = models.JSONField(null=True, blank=True)
    virustotal_last_check = models.DateTimeField(null=True, blank=True)
    
    # Statistics
    phishing_reports = models.IntegerField(default=0)
    malware_reports = models.IntegerField(default=0)
    spam_reports = models.IntegerField(default=0)
    
    # Metadata
    first_seen = models.DateTimeField(auto_now_add=True)
    reputation_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-reputation_updated']
        verbose_name = "Domain Reputation"
        verbose_name_plural = "Domain Reputations"
    
    def __str__(self):
        return f"{self.domain_name} ({self.reputation})"
    
    @property
    def domain_age_days(self):
        """Calculate domain age in days"""
        if self.creation_date:
            from django.utils import timezone
            return (timezone.now() - self.creation_date).days
        return None


class ThreatFeed(models.Model):
    """Model for managing threat intelligence feeds"""
    
    FEED_TYPES = [
        ('IOC', 'Indicators of Compromise'),
        ('MALWARE', 'Malware Signatures'),
        ('PHISHING', 'Phishing URLs'),
        ('SPAM', 'Spam Sources'),
        ('BOTNET', 'Botnet C&C'),
    ]
    
    FEED_FORMATS = [
        ('JSON', 'JSON'),
        ('CSV', 'CSV'),
        ('XML', 'XML'),
        ('STIX', 'STIX/TAXII'),
        ('TEXT', 'Plain Text'),
    ]
    
    # Feed Information
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    feed_type = models.CharField(max_length=20, choices=FEED_TYPES)
    feed_format = models.CharField(max_length=10, choices=FEED_FORMATS)
    
    # Source Configuration
    feed_url = models.URLField()
    api_key = models.CharField(max_length=255, blank=True)
    headers = models.JSONField(default=dict, help_text="HTTP headers for feed requests")
    
    # Update Configuration
    update_frequency = models.IntegerField(default=3600, help_text="Update frequency in seconds")
    is_active = models.BooleanField(default=True)
    auto_import = models.BooleanField(default=False)
    
    # Statistics
    total_indicators = models.IntegerField(default=0)
    last_update = models.DateTimeField(null=True, blank=True)
    last_successful_update = models.DateTimeField(null=True, blank=True)
    update_errors = models.IntegerField(default=0)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = "Threat Feed"
        verbose_name_plural = "Threat Feeds"
    
    def __str__(self):
        return f"{self.name} ({self.feed_type})"


class ThreatAttribution(models.Model):
    """Model for storing threat attribution data"""
    
    ACTOR_TYPES = [
        ('INDIVIDUAL', 'Individual'),
        ('GROUP', 'Criminal Group'),
        ('APT', 'Advanced Persistent Threat'),
        ('NATION_STATE', 'Nation State'),
        ('HACKTIVIST', 'Hacktivist'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    # Attribution Information
    actor_name = models.CharField(max_length=255)
    actor_type = models.CharField(max_length=20, choices=ACTOR_TYPES)
    aliases = models.JSONField(default=list, help_text="Known aliases for the threat actor")
    
    # Geographic Information
    suspected_country = models.CharField(max_length=100, blank=True)
    operating_regions = models.JSONField(default=list)
    
    # Tactics, Techniques, and Procedures (TTPs)
    attack_patterns = models.JSONField(default=list)
    malware_families = models.JSONField(default=list)
    infrastructure = models.JSONField(default=list)
    
    # Motivation and Targeting
    motivation = models.TextField(blank=True)
    target_sectors = models.JSONField(default=list)
    target_countries = models.JSONField(default=list)
    
    # Confidence and Sources
    confidence_level = models.FloatField(default=0.0, help_text="Confidence level from 0-100")
    sources = models.JSONField(default=list, help_text="Attribution sources and references")
    
    # Metadata
    first_observed = models.DateTimeField()
    last_activity = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-last_activity']
        verbose_name = "Threat Attribution"
        verbose_name_plural = "Threat Attributions"
    
    def __str__(self):
        return f"{self.actor_name} ({self.actor_type})"


class ThreatIntelligenceReport(models.Model):
    """Model for storing threat intelligence reports"""
    
    REPORT_TYPES = [
        ('INCIDENT', 'Incident Report'),
        ('CAMPAIGN', 'Campaign Analysis'),
        ('IOC', 'Indicators Report'),
        ('ATTRIBUTION', 'Attribution Report'),
        ('TREND', 'Trend Analysis'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Report Information
    title = models.CharField(max_length=500)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    
    # Content
    executive_summary = models.TextField()
    detailed_analysis = models.TextField()
    recommendations = models.TextField(blank=True)
    
    # Associated Data
    threat_indicators = models.ManyToManyField(ThreatIndicator, blank=True)
    attribution = models.ForeignKey(ThreatAttribution, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Classification
    tlp_classification = models.CharField(max_length=10, default='WHITE', help_text="Traffic Light Protocol")
    tags = models.JSONField(default=list)
    
    # Metadata
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)
    is_published = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Threat Intelligence Report"
        verbose_name_plural = "Threat Intelligence Reports"
    
    def __str__(self):
        return f"{self.title} ({self.severity})"
