import email
import re
import hashlib
import requests
import dns.resolver
import whois
from email.header import decode_header
from email.utils import parseaddr
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import logging
import time
import json

from django.conf import settings
from django.utils import timezone as django_timezone
from .models import EmailAnalysis, EmailHeader, URLAnalysis, AttachmentAnalysis, PhishingTechnique

logger = logging.getLogger(__name__)


class EmailParser:
    """Service for parsing email content and extracting metadata"""
    
    def __init__(self, raw_email):
        self.raw_email = raw_email
        self.email_obj = email.message_from_string(raw_email)
        
    def parse_email(self):
        """Parse email and extract all relevant information"""
        try:
            parsed_data = {
                'subject': self._get_subject(),
                'sender': self._get_sender(),
                'recipient': self._get_recipient(),
                'body': self._get_body(),
                'headers': self._get_headers(),
                'urls': self._extract_urls(),
                'attachments': self._extract_attachments(),
                'message_id': self._get_message_id(),
                'date': self._get_date(),
                'received_headers': self._get_received_headers(),
            }
            return parsed_data
        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            raise
    
    def _get_subject(self):
        """Extract and decode email subject"""
        subject = self.email_obj.get('Subject', '')
        if subject:
            decoded_parts = decode_header(subject)
            subject = ''.join([
                part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part
                for part, encoding in decoded_parts
            ])
        return subject
    
    def _get_sender(self):
        """Extract sender email address"""
        from_header = self.email_obj.get('From', '')
        name, email_addr = parseaddr(from_header)
        return email_addr
    
    def _get_recipient(self):
        """Extract recipient email address"""
        to_header = self.email_obj.get('To', '')
        name, email_addr = parseaddr(to_header)
        return email_addr
    
    def _get_body(self):
        """Extract email body content"""
        body = ""
        if self.email_obj.is_multipart():
            for part in self.email_obj.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='ignore')
                elif part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='ignore')
        else:
            payload = self.email_obj.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
        return body
    
    def _get_headers(self):
        """Extract all email headers"""
        headers = {}
        for key, value in self.email_obj.items():
            headers[key] = value
        return headers
    
    def _extract_urls(self):
        """Extract URLs from email body"""
        body = self._get_body()
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body)
        return list(set(urls))  # Remove duplicates
    
    def _extract_attachments(self):
        """Extract attachment information"""
        attachments = []
        if self.email_obj.is_multipart():
            for part in self.email_obj.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(payload) if payload else 0,
                            'content': payload
                        })
        return attachments
    
    def _get_message_id(self):
        """Extract message ID"""
        return self.email_obj.get('Message-ID', '')
    
    def _get_date(self):
        """Extract and parse email date"""
        date_str = self.email_obj.get('Date', '')
        if date_str:
            try:
                return email.utils.parsedate_to_datetime(date_str)
            except:
                pass
        return None
    
    def _get_received_headers(self):
        """Extract all Received headers for routing analysis"""
        received_headers = []
        for header in self.email_obj.get_all('Received', []):
            received_headers.append(header)
        return received_headers


class PhishingAnalyzer:
    """Service for analyzing emails for phishing indicators"""
    
    def __init__(self, email_analysis):
        self.email_analysis = email_analysis
        self.threat_indicators = []
        self.phishing_score = 0.0
        
    def analyze(self):
        """Perform comprehensive phishing analysis"""
        try:
            start_time = time.time()
            
            # Run various analysis checks
            self._analyze_sender_reputation()
            self._analyze_subject_patterns()
            self._analyze_body_content()
            self._analyze_urls()
            self._analyze_attachments()
            self._analyze_headers()
            self._analyze_authentication()
            self._check_typosquatting()
            self._analyze_social_engineering()
            
            # Calculate final risk assessment
            self._calculate_risk_level()
            
            # Update analysis duration
            analysis_duration = time.time() - start_time
            self.email_analysis.analysis_duration = analysis_duration
            self.email_analysis.phishing_score = self.phishing_score
            self.email_analysis.threat_indicators = self.threat_indicators
            self.email_analysis.status = 'COMPLETED'
            self.email_analysis.save()
            
            logger.info(f"Analysis completed for email {self.email_analysis.id} in {analysis_duration:.2f}s")
            
        except Exception as e:
            logger.error(f"Error during phishing analysis: {str(e)}")
            self.email_analysis.status = 'FAILED'
            self.email_analysis.save()
            raise
    
    def _analyze_sender_reputation(self):
        """Analyze sender reputation and domain"""
        sender_domain = self.email_analysis.sender_email.split('@')[1]
        
        # Check if sender domain is suspicious
        suspicious_domains = [
            'tempmail.org', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com'
        ]
        
        if sender_domain.lower() in suspicious_domains:
            self._add_threat_indicator(
                'SUSPICIOUS_SENDER_DOMAIN',
                f'Sender uses temporary email service: {sender_domain}',
                'HIGH'
            )
            self.phishing_score += 30
    
    def _analyze_subject_patterns(self):
        """Analyze subject line for phishing patterns"""
        subject = self.email_analysis.email_subject.lower()
        
        # Common phishing subject patterns
        phishing_keywords = [
            'urgent', 'immediate action', 'verify account', 'suspended',
            'click here', 'act now', 'limited time', 'expire',
            'congratulations', 'winner', 'prize', 'refund',
            'security alert', 'unusual activity'
        ]
        
        found_keywords = [keyword for keyword in phishing_keywords if keyword in subject]
        
        if found_keywords:
            self._add_threat_indicator(
                'SUSPICIOUS_SUBJECT',
                f'Subject contains phishing keywords: {", ".join(found_keywords)}',
                'MEDIUM'
            )
            self.phishing_score += len(found_keywords) * 5
        
        # Check for excessive punctuation or caps
        if subject.count('!') > 2 or subject.isupper():
            self._add_threat_indicator(
                'SUSPICIOUS_SUBJECT_FORMAT',
                'Subject uses excessive punctuation or all caps',
                'LOW'
            )
            self.phishing_score += 10
    
    def _analyze_body_content(self):
        """Analyze email body for suspicious content"""
        body = self.email_analysis.email_body.lower()
        
        # Social engineering indicators
        urgency_phrases = [
            'act immediately', 'expires today', 'last chance',
            'urgent response required', 'time sensitive'
        ]
        
        found_urgency = [phrase for phrase in urgency_phrases if phrase in body]
        if found_urgency:
            self._add_threat_indicator(
                'URGENCY_TACTICS',
                f'Body contains urgency tactics: {", ".join(found_urgency)}',
                'MEDIUM'
            )
            self.phishing_score += 15
        
        # Credential harvesting indicators
        credential_phrases = [
            'verify your password', 'update payment information',
            'confirm your identity', 'validate account'
        ]
        
        found_credential = [phrase for phrase in credential_phrases if phrase in body]
        if found_credential:
            self._add_threat_indicator(
                'CREDENTIAL_HARVESTING',
                f'Body requests credential information: {", ".join(found_credential)}',
                'HIGH'
            )
            self.phishing_score += 25
    
    def _analyze_urls(self):
        """Analyze URLs in the email"""
        parser = EmailParser(self.email_analysis.raw_email)
        urls = parser._extract_urls()
        
        for url in urls:
            url_analyzer = URLThreatAnalyzer(url)
            analysis_result = url_analyzer.analyze()
            
            # Create URL analysis record
            URLAnalysis.objects.create(
                email_analysis=self.email_analysis,
                original_url=url,
                final_url=analysis_result.get('final_url', url),
                domain=analysis_result.get('domain', ''),
                threat_level=analysis_result.get('threat_level', 'UNKNOWN'),
                is_shortened=analysis_result.get('is_shortened', False),
                redirect_count=analysis_result.get('redirect_count', 0),
                virustotal_score=analysis_result.get('virustotal_score'),
                virustotal_detected=analysis_result.get('virustotal_detected', False)
            )
            
            # Add to threat indicators if suspicious
            if analysis_result.get('threat_level') in ['SUSPICIOUS', 'MALICIOUS']:
                self._add_threat_indicator(
                    'MALICIOUS_URL',
                    f'Suspicious URL detected: {url}',
                    'HIGH' if analysis_result.get('threat_level') == 'MALICIOUS' else 'MEDIUM'
                )
                self.phishing_score += 20 if analysis_result.get('threat_level') == 'MALICIOUS' else 10
    
    def _analyze_attachments(self):
        """Analyze email attachments"""
        parser = EmailParser(self.email_analysis.raw_email)
        attachments = parser._extract_attachments()
        
        for attachment in attachments:
            attachment_analyzer = AttachmentThreatAnalyzer(attachment)
            analysis_result = attachment_analyzer.analyze()
            
            # Create attachment analysis record
            AttachmentAnalysis.objects.create(
                email_analysis=self.email_analysis,
                filename=attachment['filename'],
                file_size=attachment['size'],
                file_type=analysis_result.get('file_type', ''),
                mime_type=attachment['content_type'],
                md5_hash=analysis_result.get('md5_hash', ''),
                sha256_hash=analysis_result.get('sha256_hash', ''),
                threat_level=analysis_result.get('threat_level', 'UNKNOWN'),
                is_executable=analysis_result.get('is_executable', False),
                has_macros=analysis_result.get('has_macros', False),
                virustotal_score=analysis_result.get('virustotal_score'),
                virustotal_detected=analysis_result.get('virustotal_detected', False)
            )
            
            # Add to threat indicators if suspicious
            if analysis_result.get('threat_level') in ['SUSPICIOUS', 'MALICIOUS']:
                self._add_threat_indicator(
                    'MALICIOUS_ATTACHMENT',
                    f'Suspicious attachment: {attachment["filename"]}',
                    'HIGH' if analysis_result.get('threat_level') == 'MALICIOUS' else 'MEDIUM'
                )
                self.phishing_score += 30
    
    def _analyze_headers(self):
        """Analyze email headers for suspicious patterns"""
        parser = EmailParser(self.email_analysis.raw_email)
        headers = parser._get_headers()
        
        # Check for missing or suspicious headers
        required_headers = ['From', 'To', 'Date', 'Message-ID']
        missing_headers = [h for h in required_headers if h not in headers]
        
        if missing_headers:
            self._add_threat_indicator(
                'MISSING_HEADERS',
                f'Missing required headers: {", ".join(missing_headers)}',
                'MEDIUM'
            )
            self.phishing_score += 15
        
        # Analyze Received headers
        received_headers = parser._get_received_headers()
        if len(received_headers) < 2:
            self._add_threat_indicator(
                'SUSPICIOUS_ROUTING',
                'Insufficient Received headers - possible direct injection',
                'HIGH'
            )
            self.phishing_score += 25
    
    def _analyze_authentication(self):
        """Analyze email authentication (SPF, DKIM, DMARC)"""
        # This would typically involve checking authentication results
        # For now, we'll simulate the analysis
        
        # In a real implementation, you would:
        # 1. Check SPF records
        # 2. Verify DKIM signatures
        # 3. Check DMARC policy compliance
        
        # Placeholder for authentication analysis
        pass
    
    def _check_typosquatting(self):
        """Check for typosquatting in sender domain"""
        sender_domain = self.email_analysis.sender_email.split('@')[1]
        
        # Common legitimate domains to check against
        legitimate_domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'amazon.com', 'paypal.com', 'microsoft.com', 'google.com',
            'apple.com', 'facebook.com', 'twitter.com'
        ]
        
        for legit_domain in legitimate_domains:
            similarity = self._calculate_domain_similarity(sender_domain, legit_domain)
            if 0.7 <= similarity < 1.0:  # Similar but not identical
                self._add_threat_indicator(
                    'TYPOSQUATTING',
                    f'Domain {sender_domain} appears to be typosquatting {legit_domain}',
                    'HIGH'
                )
                self.phishing_score += 35
                break
    
    def _analyze_social_engineering(self):
        """Analyze for social engineering tactics"""
        body = self.email_analysis.email_body.lower()
        
        # Authority impersonation
        authority_terms = [
            'ceo', 'manager', 'director', 'admin', 'support team',
            'security team', 'it department', 'bank', 'government'
        ]
        
        found_authority = [term for term in authority_terms if term in body]
        if found_authority:
            self._add_threat_indicator(
                'AUTHORITY_IMPERSONATION',
                f'Email impersonates authority figures: {", ".join(found_authority)}',
                'MEDIUM'
            )
            self.phishing_score += 15
    
    def _calculate_domain_similarity(self, domain1, domain2):
        """Calculate similarity between two domains using Levenshtein distance"""
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        distance = levenshtein_distance(domain1, domain2)
        max_len = max(len(domain1), len(domain2))
        return 1 - (distance / max_len)
    
    def _calculate_risk_level(self):
        """Calculate overall risk level based on phishing score"""
        if self.phishing_score >= 70:
            self.email_analysis.risk_level = 'CRITICAL'
            self.email_analysis.is_phishing = True
        elif self.phishing_score >= 50:
            self.email_analysis.risk_level = 'HIGH'
            self.email_analysis.is_phishing = True
        elif self.phishing_score >= 30:
            self.email_analysis.risk_level = 'MEDIUM'
        else:
            self.email_analysis.risk_level = 'LOW'
    
    def _add_threat_indicator(self, indicator_type, description, severity):
        """Add a threat indicator to the analysis"""
        self.threat_indicators.append({
            'type': indicator_type,
            'description': description,
            'severity': severity,
            'detected_at': django_timezone.now().isoformat()
        })


class URLThreatAnalyzer:
    """Service for analyzing URLs for threats"""
    
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        
    def analyze(self):
        """Analyze URL for threats"""
        result = {
            'original_url': self.url,
            'domain': self.parsed_url.netloc,
            'threat_level': 'UNKNOWN',
            'is_shortened': False,
            'redirect_count': 0,
            'final_url': self.url,
            'virustotal_score': None,
            'virustotal_detected': False
        }
        
        try:
            # Check if URL is shortened
            result['is_shortened'] = self._is_shortened_url()
            
            # Follow redirects
            final_url, redirect_count = self._follow_redirects()
            result['final_url'] = final_url
            result['redirect_count'] = redirect_count
            
            # Check with VirusTotal (if API key is available)
            if settings.VIRUSTOTAL_API_KEY:
                vt_result = self._check_virustotal()
                result['virustotal_score'] = vt_result
                result['virustotal_detected'] = any(vt_result.values()) if vt_result else False
            
            # Determine threat level
            result['threat_level'] = self._determine_threat_level(result)
            
        except Exception as e:
            logger.error(f"Error analyzing URL {self.url}: {str(e)}")
        
        return result
    
    def _is_shortened_url(self):
        """Check if URL is from a URL shortening service"""
        shortening_services = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
            'ow.ly', 'buff.ly', 'is.gd', 'tiny.cc'
        ]
        return self.parsed_url.netloc.lower() in shortening_services
    
    def _follow_redirects(self):
        """Follow URL redirects and return final URL"""
        try:
            response = requests.head(self.url, allow_redirects=True, timeout=10)
            return response.url, len(response.history)
        except:
            return self.url, 0
    
    def _check_virustotal(self):
        """Check URL with VirusTotal API"""
        try:
            headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
            response = requests.get(
                f'https://www.virustotal.com/vtapi/v2/url/report',
                params={'apikey': settings.VIRUSTOTAL_API_KEY, 'resource': self.url},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('scans', {})
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
        
        return None
    
    def _determine_threat_level(self, analysis_result):
        """Determine threat level based on analysis results"""
        if analysis_result['virustotal_detected']:
            return 'MALICIOUS'
        elif analysis_result['is_shortened'] and analysis_result['redirect_count'] > 2:
            return 'SUSPICIOUS'
        elif analysis_result['redirect_count'] > 5:
            return 'SUSPICIOUS'
        else:
            return 'SAFE'


class AttachmentThreatAnalyzer:
    """Service for analyzing email attachments"""
    
    def __init__(self, attachment):
        self.attachment = attachment
        
    def analyze(self):
        """Analyze attachment for threats"""
        result = {
            'file_type': self._get_file_type(),
            'md5_hash': self._calculate_md5(),
            'sha256_hash': self._calculate_sha256(),
            'threat_level': 'UNKNOWN',
            'is_executable': False,
            'has_macros': False,
            'virustotal_score': None,
            'virustotal_detected': False
        }
        
        try:
            # Check if file is executable
            result['is_executable'] = self._is_executable()
            
            # Check for macros (basic check)
            result['has_macros'] = self._has_macros()
            
            # Check with VirusTotal (if API key is available)
            if settings.VIRUSTOTAL_API_KEY:
                vt_result = self._check_virustotal(result['sha256_hash'])
                result['virustotal_score'] = vt_result
                result['virustotal_detected'] = any(vt_result.values()) if vt_result else False
            
            # Determine threat level
            result['threat_level'] = self._determine_threat_level(result)
            
        except Exception as e:
            logger.error(f"Error analyzing attachment {self.attachment['filename']}: {str(e)}")
        
        return result
    
    def _get_file_type(self):
        """Get file type from filename extension"""
        filename = self.attachment['filename']
        return filename.split('.')[-1].lower() if '.' in filename else 'unknown'
    
    def _calculate_md5(self):
        """Calculate MD5 hash of the attachment"""
        if self.attachment.get('content'):
            return hashlib.md5(self.attachment['content']).hexdigest()
        return ''
    
    def _calculate_sha256(self):
        """Calculate SHA256 hash of the attachment"""
        if self.attachment.get('content'):
            return hashlib.sha256(self.attachment['content']).hexdigest()
        return ''
    
    def _is_executable(self):
        """Check if file is executable"""
        executable_extensions = [
            'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js',
            'jar', 'app', 'deb', 'pkg', 'dmg'
        ]
        file_type = self._get_file_type()
        return file_type in executable_extensions
    
    def _has_macros(self):
        """Basic check for macro-enabled files"""
        macro_extensions = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm']
        file_type = self._get_file_type()
        return file_type in macro_extensions
    
    def _check_virustotal(self, file_hash):
        """Check file hash with VirusTotal API"""
        try:
            headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
            response = requests.get(
                f'https://www.virustotal.com/vtapi/v2/file/report',
                params={'apikey': settings.VIRUSTOTAL_API_KEY, 'resource': file_hash},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('scans', {})
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
        
        return None
    
    def _determine_threat_level(self, analysis_result):
        """Determine threat level based on analysis results"""
        if analysis_result['virustotal_detected']:
            return 'MALICIOUS'
        elif analysis_result['is_executable']:
            return 'SUSPICIOUS'
        elif analysis_result['has_macros']:
            return 'SUSPICIOUS'
        else:
            return 'SAFE'