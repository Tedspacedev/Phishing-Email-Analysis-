from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator
import json


class EmailAnalysis(models.Model):
    """Main model for storing email analysis results"""
    
    RISK_LEVELS = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending Analysis'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Analysis Completed'),
        ('FAILED', 'Analysis Failed'),
    ]
    
    # Basic Information
    email_subject = models.CharField(max_length=500, blank=True)
    sender_email = models.EmailField()
    recipient_email = models.EmailField()
    email_body = models.TextField()
    raw_email = models.TextField(blank=True, null=True, help_text="Raw email content")
    
    # Analysis Results
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='LOW')
    phishing_score = models.FloatField(default=0.0, help_text="Score from 0-100")
    is_phishing = models.BooleanField(default=False)
    
    # Status and Metadata
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    analyzed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    analysis_duration = models.FloatField(null=True, blank=True, help_text="Analysis time in seconds")
    
    # Analysis Summary
    threat_indicators = models.JSONField(default=list, help_text="List of detected threat indicators")
    analysis_summary = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Email Analysis"
        verbose_name_plural = "Email Analyses"
    
    def __str__(self):
        return f"Analysis #{self.id} - {self.sender_email} ({self.risk_level})"
    
    @property
    def threat_count(self):
        """Count of threat indicators found"""
        return len(self.threat_indicators) if self.threat_indicators else 0
    
    def add_threat_indicator(self, indicator_type, description, severity='MEDIUM'):
        """Add a threat indicator to the analysis"""
        if not self.threat_indicators:
            self.threat_indicators = []
        
        self.threat_indicators.append({
            'type': indicator_type,
            'description': description,
            'severity': severity,
            'detected_at': models.DateTimeField.auto_now_add
        })
        self.save()


class EmailHeader(models.Model):
    """Model for storing detailed email header analysis"""
    
    email_analysis = models.OneToOneField(EmailAnalysis, on_delete=models.CASCADE, related_name='header_analysis')
    
    # Original Headers
    raw_headers = models.TextField()
    
    # Parsed Header Fields
    message_id = models.CharField(max_length=255, blank=True)
    return_path = models.EmailField(blank=True)
    received_headers = models.JSONField(default=list, help_text="List of Received headers")
    
    # Authentication Results
    spf_result = models.CharField(max_length=50, blank=True)
    dkim_result = models.CharField(max_length=50, blank=True)
    dmarc_result = models.CharField(max_length=50, blank=True)
    
    # Routing Analysis
    originating_ip = models.GenericIPAddressField(null=True, blank=True)
    mail_servers = models.JSONField(default=list, help_text="List of mail servers in delivery path")
    
    # Suspicious Indicators
    header_inconsistencies = models.JSONField(default=list)
    spoofing_indicators = models.JSONField(default=list)
    
    # Geolocation Data
    sender_country = models.CharField(max_length=100, blank=True)
    sender_region = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Email Header Analysis"
        verbose_name_plural = "Email Header Analyses"
    
    def __str__(self):
        return f"Header Analysis for {self.email_analysis.sender_email}"


class URLAnalysis(models.Model):
    """Model for analyzing URLs found in emails"""
    
    THREAT_LEVELS = [
        ('SAFE', 'Safe'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    email_analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='url_analyses')
    
    # URL Information
    original_url = models.URLField(max_length=2000)
    final_url = models.URLField(max_length=2000, blank=True, help_text="URL after following redirects")
    domain = models.CharField(max_length=255)
    
    # Analysis Results
    threat_level = models.CharField(max_length=15, choices=THREAT_LEVELS, default='UNKNOWN')
    is_shortened = models.BooleanField(default=False)
    redirect_count = models.IntegerField(default=0)
    
    # VirusTotal Results
    virustotal_score = models.JSONField(null=True, blank=True)
    virustotal_detected = models.BooleanField(default=False)
    
    # Domain Analysis
    domain_age = models.IntegerField(null=True, blank=True, help_text="Domain age in days")
    domain_registrar = models.CharField(max_length=255, blank=True)
    is_typosquatting = models.BooleanField(default=False)
    
    # Response Analysis
    http_status_code = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True, help_text="Response time in seconds")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "URL Analysis"
        verbose_name_plural = "URL Analyses"
    
    def __str__(self):
        return f"URL Analysis: {self.domain} ({self.threat_level})"


class AttachmentAnalysis(models.Model):
    """Model for analyzing email attachments"""
    
    THREAT_LEVELS = [
        ('SAFE', 'Safe'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    email_analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='attachment_analyses')
    
    # File Information
    filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(help_text="File size in bytes")
    file_type = models.CharField(max_length=100)
    mime_type = models.CharField(max_length=100)
    
    # Hash Analysis
    md5_hash = models.CharField(max_length=32, blank=True)
    sha1_hash = models.CharField(max_length=40, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True)
    
    # Analysis Results
    threat_level = models.CharField(max_length=15, choices=THREAT_LEVELS, default='UNKNOWN')
    is_executable = models.BooleanField(default=False)
    has_macros = models.BooleanField(default=False)
    
    # VirusTotal Results
    virustotal_score = models.JSONField(null=True, blank=True)
    virustotal_detected = models.BooleanField(default=False)
    detection_engines = models.JSONField(default=list, help_text="List of engines that detected threats")
    
    # File Content Analysis
    embedded_urls = models.JSONField(default=list, help_text="URLs found in the attachment")
    suspicious_strings = models.JSONField(default=list, help_text="Suspicious strings found in the file")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Attachment Analysis"
        verbose_name_plural = "Attachment Analyses"
    
    def __str__(self):
        return f"Attachment: {self.filename} ({self.threat_level})"


class PhishingTechnique(models.Model):
    """Model for cataloging different phishing techniques detected"""
    
    TECHNIQUE_CATEGORIES = [
        ('SPOOFING', 'Email Spoofing'),
        ('SOCIAL_ENGINEERING', 'Social Engineering'),
        ('MALICIOUS_LINKS', 'Malicious Links'),
        ('MALWARE', 'Malware Distribution'),
        ('CREDENTIAL_HARVESTING', 'Credential Harvesting'),
        ('BUSINESS_EMAIL_COMPROMISE', 'Business Email Compromise'),
        ('TYPOSQUATTING', 'Typosquatting'),
        ('HOMOGRAPH_ATTACK', 'Homograph Attack'),
    ]
    
    email_analysis = models.ForeignKey(EmailAnalysis, on_delete=models.CASCADE, related_name='phishing_techniques')
    
    technique_type = models.CharField(max_length=30, choices=TECHNIQUE_CATEGORIES)
    technique_name = models.CharField(max_length=255)
    description = models.TextField()
    confidence_score = models.FloatField(help_text="Confidence score from 0-100")
    
    # Evidence
    evidence = models.JSONField(default=dict, help_text="Supporting evidence for the detection")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-confidence_score']
        verbose_name = "Phishing Technique"
        verbose_name_plural = "Phishing Techniques"
    
    def __str__(self):
        return f"{self.technique_name} - {self.confidence_score}%"
