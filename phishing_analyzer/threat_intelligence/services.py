import requests
import whois
import dns.resolver
import json
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from .models import (
    ThreatIndicator, IPReputation, DomainReputation, 
    ThreatFeed, ThreatAttribution
)

logger = logging.getLogger(__name__)


class VirusTotalService:
    """Service for VirusTotal API integration"""
    
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        
    def check_url(self, url):
        """Check URL reputation with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
            
        try:
            params = {
                'apikey': self.api_key,
                'resource': url
            }
            
            response = requests.get(
                f"{self.base_url}/url/report",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'scan_date': data.get('scan_date'),
                    'permalink': data.get('permalink'),
                    'scans': data.get('scans', {})
                }
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {str(e)}")
            
        return None
    
    def check_file_hash(self, file_hash):
        """Check file hash reputation with VirusTotal"""
        if not self.api_key:
            return None
            
        try:
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(
                f"{self.base_url}/file/report",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'scan_date': data.get('scan_date'),
                    'permalink': data.get('permalink'),
                    'scans': data.get('scans', {})
                }
        except Exception as e:
            logger.error(f"VirusTotal file check failed: {str(e)}")
            
        return None
    
    def check_ip(self, ip_address):
        """Check IP address reputation with VirusTotal"""
        if not self.api_key:
            return None
            
        try:
            params = {
                'apikey': self.api_key,
                'ip': ip_address
            }
            
            response = requests.get(
                f"{self.base_url}/ip-address/report",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'detected_urls': data.get('detected_urls', []),
                    'detected_downloaded_samples': data.get('detected_downloaded_samples', []),
                    'detected_communicating_samples': data.get('detected_communicating_samples', []),
                    'country': data.get('country'),
                    'asn': data.get('asn')
                }
        except Exception as e:
            logger.error(f"VirusTotal IP check failed: {str(e)}")
            
        return None


class WHOISService:
    """Service for WHOIS domain lookups"""
    
    def lookup_domain(self, domain):
        """Perform WHOIS lookup for domain"""
        try:
            w = whois.whois(domain)
            
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'country': w.country,
                'registrant_name': w.get('registrant_name'),
                'registrant_email': w.get('registrant_email')
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
            return None


class DNSService:
    """Service for DNS lookups and analysis"""
    
    def resolve_domain(self, domain):
        """Resolve domain to IP addresses"""
        try:
            result = dns.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in result]
        except Exception as e:
            logger.error(f"DNS resolution failed for {domain}: {str(e)}")
            return []
    
    def get_mx_records(self, domain):
        """Get MX records for domain"""
        try:
            result = dns.resolver.resolve(domain, 'MX')
            return [{'preference': rdata.preference, 'exchange': str(rdata.exchange)} 
                   for rdata in result]
        except Exception as e:
            logger.error(f"MX lookup failed for {domain}: {str(e)}")
            return []
    
    def get_txt_records(self, domain):
        """Get TXT records for domain (SPF, DMARC, etc.)"""
        try:
            result = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in result]
        except Exception as e:
            logger.error(f"TXT lookup failed for {domain}: {str(e)}")
            return []


class ThreatIntelligenceService:
    """Main service for threat intelligence operations"""
    
    def __init__(self):
        self.virustotal = VirusTotalService()
        self.whois_service = WHOISService()
        self.dns_service = DNSService()
    
    def analyze_domain(self, domain):
        """Comprehensive domain analysis"""
        try:
            # Get or create domain reputation record
            domain_rep, created = DomainReputation.objects.get_or_create(
                domain_name=domain,
                defaults={'reputation': 'NEUTRAL'}
            )
            
            # WHOIS lookup
            whois_data = self.whois_service.lookup_domain(domain)
            if whois_data:
                domain_rep.registrar = whois_data.get('registrar', '')
                domain_rep.creation_date = self._parse_date(whois_data.get('creation_date'))
                domain_rep.expiration_date = self._parse_date(whois_data.get('expiration_date'))
                domain_rep.registrant_name = whois_data.get('registrant_name', '')
                domain_rep.registrant_email = whois_data.get('registrant_email', '')
                domain_rep.registrant_country = whois_data.get('country', '')
                
                if whois_data.get('name_servers'):
                    domain_rep.name_servers = list(whois_data['name_servers'])
            
            # DNS lookups
            a_records = self.dns_service.resolve_domain(domain)
            mx_records = self.dns_service.get_mx_records(domain)
            
            domain_rep.a_records = a_records
            domain_rep.mx_records = mx_records
            
            # Check for suspicious patterns
            self._analyze_domain_patterns(domain_rep)
            
            domain_rep.save()
            
            return domain_rep
            
        except Exception as e:
            logger.error(f"Domain analysis failed for {domain}: {str(e)}")
            return None
    
    def analyze_ip(self, ip_address):
        """Comprehensive IP address analysis"""
        try:
            # Get or create IP reputation record
            ip_rep, created = IPReputation.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reputation': 'NEUTRAL'}
            )
            
            # VirusTotal check
            vt_data = self.virustotal.check_ip(ip_address)
            if vt_data:
                ip_rep.virustotal_score = vt_data
                ip_rep.virustotal_last_check = timezone.now()
                
                # Update reputation based on VirusTotal data
                if vt_data.get('detected_urls') or vt_data.get('detected_downloaded_samples'):
                    ip_rep.reputation = 'SUSPICIOUS'
                    ip_rep.malware_reports += len(vt_data.get('detected_downloaded_samples', []))
                
                # Update geolocation
                if vt_data.get('country'):
                    ip_rep.country = vt_data['country']
                if vt_data.get('asn'):
                    ip_rep.asn = str(vt_data['asn'])
            
            # Additional IP analysis could be added here
            # (GeoIP lookup, blacklist checks, etc.)
            
            ip_rep.save()
            
            return ip_rep
            
        except Exception as e:
            logger.error(f"IP analysis failed for {ip_address}: {str(e)}")
            return None
    
    def create_threat_indicator(self, indicator_type, indicator_value, 
                              threat_level='MEDIUM', source_type='INTERNAL',
                              description='', confidence_score=50.0):
        """Create or update threat indicator"""
        try:
            indicator, created = ThreatIndicator.objects.get_or_create(
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                source_type=source_type,
                defaults={
                    'threat_level': threat_level,
                    'description': description,
                    'confidence_score': confidence_score
                }
            )
            
            if not created:
                # Update existing indicator
                indicator.threat_level = threat_level
                indicator.confidence_score = max(indicator.confidence_score, confidence_score)
                indicator.increment_seen_count()
            
            return indicator
            
        except Exception as e:
            logger.error(f"Failed to create threat indicator: {str(e)}")
            return None
    
    def update_threat_feeds(self):
        """Update all active threat feeds"""
        active_feeds = ThreatFeed.objects.filter(is_active=True)
        
        for feed in active_feeds:
            try:
                self._update_single_feed(feed)
            except Exception as e:
                logger.error(f"Failed to update feed {feed.name}: {str(e)}")
                feed.update_errors += 1
                feed.save()
    
    def _update_single_feed(self, feed):
        """Update a single threat feed"""
        try:
            headers = feed.headers.copy() if feed.headers else {}
            if feed.api_key:
                headers['Authorization'] = f'Bearer {feed.api_key}'
            
            response = requests.get(
                feed.feed_url,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                indicators_created = 0
                
                if feed.feed_format == 'JSON':
                    data = response.json()
                    indicators_created = self._process_json_feed(data, feed)
                elif feed.feed_format == 'CSV':
                    indicators_created = self._process_csv_feed(response.text, feed)
                # Add other format handlers as needed
                
                feed.total_indicators = indicators_created
                feed.last_successful_update = timezone.now()
                feed.update_errors = 0
                
            feed.last_update = timezone.now()
            feed.save()
            
        except Exception as e:
            logger.error(f"Feed update failed for {feed.name}: {str(e)}")
            raise
    
    def _process_json_feed(self, data, feed):
        """Process JSON format threat feed"""
        indicators_created = 0
        
        # This is a simplified example - actual implementation would depend on feed format
        if isinstance(data, list):
            for item in data:
                if self._create_indicator_from_feed_item(item, feed):
                    indicators_created += 1
        elif isinstance(data, dict) and 'indicators' in data:
            for item in data['indicators']:
                if self._create_indicator_from_feed_item(item, feed):
                    indicators_created += 1
        
        return indicators_created
    
    def _process_csv_feed(self, csv_data, feed):
        """Process CSV format threat feed"""
        import csv
        import io
        
        indicators_created = 0
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        
        for row in csv_reader:
            if self._create_indicator_from_feed_item(row, feed):
                indicators_created += 1
        
        return indicators_created
    
    def _create_indicator_from_feed_item(self, item, feed):
        """Create threat indicator from feed item"""
        try:
            # Extract indicator data based on feed type and format
            # This is a simplified example
            indicator_value = item.get('indicator') or item.get('value')
            indicator_type = item.get('type', 'URL').upper()
            threat_level = item.get('threat_level', 'MEDIUM').upper()
            
            if indicator_value:
                self.create_threat_indicator(
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    threat_level=threat_level,
                    source_type='THREAT_FEED',
                    description=f'From feed: {feed.name}',
                    confidence_score=float(item.get('confidence', 50.0))
                )
                return True
                
        except Exception as e:
            logger.error(f"Failed to create indicator from feed item: {str(e)}")
        
        return False
    
    def _analyze_domain_patterns(self, domain_rep):
        """Analyze domain for suspicious patterns"""
        domain = domain_rep.domain_name.lower()
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            domain_rep.reputation = 'SUSPICIOUS'
        
        # Check domain age
        if domain_rep.creation_date:
            age_days = (timezone.now().date() - domain_rep.creation_date.date()).days
            if age_days < 30:  # Very new domain
                if domain_rep.reputation == 'NEUTRAL':
                    domain_rep.reputation = 'SUSPICIOUS'
        
        # Check for DGA patterns (simplified)
        if self._looks_like_dga(domain):
            domain_rep.is_dga = True
            domain_rep.reputation = 'SUSPICIOUS'
    
    def _looks_like_dga(self, domain):
        """Simple DGA detection based on domain characteristics"""
        # Remove TLD for analysis
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False
        
        domain_name = domain_parts[0]
        
        # Check for random-looking strings
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        if len(domain_name) > 12:  # Long domain names
            vowel_count = sum(1 for c in domain_name if c in vowels)
            consonant_count = sum(1 for c in domain_name if c in consonants)
            
            # High consonant to vowel ratio might indicate DGA
            if consonant_count > 0 and vowel_count / consonant_count < 0.3:
                return True
        
        return False
    
    def _parse_date(self, date_value):
        """Parse date from WHOIS data"""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value
        
        # Add date parsing logic as needed
        return None


class ThreatAttributionService:
    """Service for threat attribution analysis"""
    
    def analyze_attribution(self, email_analysis):
        """Analyze email for threat attribution indicators"""
        try:
            # Extract attribution indicators
            attribution_indicators = []
            
            # Analyze sender patterns
            sender_domain = email_analysis.sender_email.split('@')[1]
            attribution_indicators.extend(self._analyze_sender_patterns(sender_domain))
            
            # Analyze infrastructure patterns
            if hasattr(email_analysis, 'header_analysis'):
                attribution_indicators.extend(
                    self._analyze_infrastructure_patterns(email_analysis.header_analysis)
                )
            
            # Analyze attack patterns
            attribution_indicators.extend(self._analyze_attack_patterns(email_analysis))
            
            # Try to match against known threat actors
            potential_actors = self._match_threat_actors(attribution_indicators)
            
            return {
                'attribution_indicators': attribution_indicators,
                'potential_actors': potential_actors,
                'confidence_level': self._calculate_attribution_confidence(
                    attribution_indicators, potential_actors
                )
            }
            
        except Exception as e:
            logger.error(f"Attribution analysis failed: {str(e)}")
            return None
    
    def _analyze_sender_patterns(self, domain):
        """Analyze sender domain patterns for attribution"""
        indicators = []
        
        # Check against known APT domains
        apt_domains = [
            'apt1-example.com', 'lazarus-group.org'  # Example domains
        ]
        
        if domain in apt_domains:
            indicators.append({
                'type': 'INFRASTRUCTURE',
                'value': domain,
                'description': f'Known APT domain: {domain}',
                'confidence': 90.0
            })
        
        return indicators
    
    def _analyze_infrastructure_patterns(self, header_analysis):
        """Analyze email infrastructure for attribution"""
        indicators = []
        
        # Analyze originating IP patterns
        if header_analysis.originating_ip:
            # Check against known APT IP ranges
            # This would be more sophisticated in practice
            pass
        
        return indicators
    
    def _analyze_attack_patterns(self, email_analysis):
        """Analyze attack patterns for attribution"""
        indicators = []
        
        # Analyze phishing techniques used
        for technique in email_analysis.phishing_techniques.all():
            if technique.technique_type == 'SPEAR_PHISHING':
                indicators.append({
                    'type': 'TTP',
                    'value': 'SPEAR_PHISHING',
                    'description': 'Spear phishing technique used',
                    'confidence': 70.0
                })
        
        return indicators
    
    def _match_threat_actors(self, indicators):
        """Match indicators against known threat actors"""
        # Query threat attribution database
        potential_actors = []
        
        for actor in ThreatAttribution.objects.all():
            match_score = self._calculate_actor_match_score(actor, indicators)
            if match_score > 0.5:
                potential_actors.append({
                    'actor': actor,
                    'match_score': match_score
                })
        
        return sorted(potential_actors, key=lambda x: x['match_score'], reverse=True)
    
    def _calculate_actor_match_score(self, actor, indicators):
        """Calculate how well indicators match a threat actor"""
        # Simplified matching logic
        matches = 0
        total_indicators = len(indicators)
        
        if total_indicators == 0:
            return 0.0
        
        for indicator in indicators:
            # Check if indicator matches actor's known patterns
            if indicator['type'] in actor.attack_patterns:
                matches += indicator['confidence'] / 100.0
        
        return matches / total_indicators
    
    def _calculate_attribution_confidence(self, indicators, potential_actors):
        """Calculate overall attribution confidence"""
        if not indicators or not potential_actors:
            return 0.0
        
        # Use highest matching actor's score
        max_score = max(actor['match_score'] for actor in potential_actors)
        
        # Factor in number and quality of indicators
        indicator_quality = sum(ind['confidence'] for ind in indicators) / len(indicators)
        
        return min(max_score * (indicator_quality / 100.0), 1.0) * 100