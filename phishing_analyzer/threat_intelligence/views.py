from django.shortcuts import render
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
import logging

from .models import (
    ThreatIndicator, IPReputation, DomainReputation,
    ThreatFeed, ThreatAttribution, ThreatIntelligenceReport
)
from .serializers import (
    ThreatIndicatorSerializer, IPReputationSerializer, DomainReputationSerializer,
    ThreatFeedSerializer, ThreatAttributionSerializer, ThreatIntelligenceReportSerializer,
    ThreatFeedUpdateSerializer, ThreatAnalysisSerializer, ThreatSearchSerializer,
    ThreatStatsSerializer, IOCExportSerializer
)
from .services import ThreatIntelligenceService, ThreatAttributionService
from user_management.models import ActivityLog

logger = logging.getLogger(__name__)


class ThreatIndicatorViewSet(viewsets.ModelViewSet):
    """ViewSet for managing threat indicators"""
    
    queryset = ThreatIndicator.objects.all()
    serializer_class = ThreatIndicatorSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['indicator_type', 'threat_level', 'source_type', 'is_active']
    search_fields = ['indicator_value', 'description', 'threat_category']
    ordering_fields = ['last_seen', 'confidence_score', 'times_seen']
    ordering = ['-last_seen']
    
    def perform_create(self, serializer):
        """Create threat indicator"""
        indicator = serializer.save(created_by=self.request.user)
        
        ActivityLog.log_activity(
            user=self.request.user,
            activity_type='THREAT_FEED_UPDATE',
            description=f'Created threat indicator: {indicator.indicator_value}',
            content_object=indicator,
            ip_address=self.get_client_ip()
        )
    
    @action(detail=False, methods=['post'])
    def search(self, request):
        """Advanced threat intelligence search"""
        serializer = ThreatSearchSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        queryset = self.get_queryset()
        
        # Apply filters
        if data.get('query'):
            queryset = queryset.filter(
                Q(indicator_value__icontains=data['query']) |
                Q(description__icontains=data['query']) |
                Q(threat_category__icontains=data['query'])
            )
        
        if data.get('indicator_types'):
            queryset = queryset.filter(indicator_type__in=data['indicator_types'])
        
        if data.get('threat_levels'):
            queryset = queryset.filter(threat_level__in=data['threat_levels'])
        
        if data.get('source_types'):
            queryset = queryset.filter(source_type__in=data['source_types'])
        
        if data.get('date_from'):
            queryset = queryset.filter(first_seen__gte=data['date_from'])
        
        if data.get('date_to'):
            queryset = queryset.filter(first_seen__lte=data['date_to'])
        
        # Limit results
        queryset = queryset[:data.get('limit', 100)]
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get threat intelligence statistics"""
        now = timezone.now()
        today = now.date()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        queryset = self.get_queryset()
        
        # Basic counts
        total_indicators = queryset.count()
        active_indicators = queryset.filter(is_active=True).count()
        
        # By type
        indicators_by_type = dict(
            queryset.values('indicator_type').annotate(
                count=Count('id')
            ).values_list('indicator_type', 'count')
        )
        
        # By threat level
        indicators_by_threat_level = dict(
            queryset.values('threat_level').annotate(
                count=Count('id')
            ).values_list('threat_level', 'count')
        )
        
        # By source
        indicators_by_source = dict(
            queryset.values('source_type').annotate(
                count=Count('id')
            ).values_list('source_type', 'count')
        )
        
        # Recent activity
        new_indicators_today = queryset.filter(first_seen__date=today).count()
        new_indicators_week = queryset.filter(first_seen__gte=week_ago).count()
        new_indicators_month = queryset.filter(first_seen__gte=month_ago).count()
        
        # Top domains and IPs
        top_domains = list(
            queryset.filter(indicator_type='DOMAIN')
            .values('indicator_value')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        top_ips = list(
            queryset.filter(indicator_type='IP')
            .values('indicator_value')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        
        # Feed statistics
        feeds_queryset = ThreatFeed.objects.all()
        active_feeds = feeds_queryset.filter(is_active=True).count()
        total_feeds = feeds_queryset.count()
        feeds_with_errors = feeds_queryset.filter(update_errors__gt=0).count()
        
        stats_data = {
            'total_indicators': total_indicators,
            'active_indicators': active_indicators,
            'indicators_by_type': indicators_by_type,
            'indicators_by_threat_level': indicators_by_threat_level,
            'indicators_by_source': indicators_by_source,
            'new_indicators_today': new_indicators_today,
            'new_indicators_week': new_indicators_week,
            'new_indicators_month': new_indicators_month,
            'top_domains': top_domains,
            'top_ips': top_ips,
            'active_feeds': active_feeds,
            'total_feeds': total_feeds,
            'feeds_with_errors': feeds_with_errors
        }
        
        serializer = ThreatStatsSerializer(stats_data)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def export_iocs(self, request):
        """Export IOCs in various formats"""
        serializer = IOCExportSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        queryset = self.get_queryset()
        
        # Apply filters
        if data.get('indicator_types'):
            queryset = queryset.filter(indicator_type__in=data['indicator_types'])
        
        if data.get('threat_levels'):
            queryset = queryset.filter(threat_level__in=data['threat_levels'])
        
        if data.get('date_from'):
            queryset = queryset.filter(first_seen__gte=data['date_from'])
        
        if data.get('date_to'):
            queryset = queryset.filter(first_seen__lte=data['date_to'])
        
        if not data.get('include_inactive'):
            queryset = queryset.filter(is_active=True)
        
        # Generate export based on format
        export_format = data['format']
        
        if export_format == 'JSON':
            export_data = self.get_serializer(queryset, many=True).data
        elif export_format == 'CSV':
            export_data = self._export_csv(queryset)
        elif export_format == 'STIX':
            export_data = self._export_stix(queryset)
        else:
            return Response(
                {'error': f'Export format {export_format} not yet implemented'},
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='REPORT_EXPORT',
            description=f'Exported {queryset.count()} IOCs in {export_format} format',
            ip_address=self.get_client_ip(),
            additional_data={'format': export_format, 'count': queryset.count()}
        )
        
        return Response({
            'format': export_format,
            'count': queryset.count(),
            'data': export_data
        })
    
    def _export_csv(self, queryset):
        """Export IOCs as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Indicator Type', 'Indicator Value', 'Threat Level',
            'Source Type', 'Description', 'Confidence Score',
            'First Seen', 'Last Seen', 'Times Seen'
        ])
        
        # Write data
        for indicator in queryset:
            writer.writerow([
                indicator.indicator_type,
                indicator.indicator_value,
                indicator.threat_level,
                indicator.source_type,
                indicator.description,
                indicator.confidence_score,
                indicator.first_seen,
                indicator.last_seen,
                indicator.times_seen
            ])
        
        return output.getvalue()
    
    def _export_stix(self, queryset):
        """Export IOCs as STIX 2.0 format"""
        # Simplified STIX export - in practice, you'd use a proper STIX library
        stix_objects = []
        
        for indicator in queryset:
            stix_indicator = {
                "type": "indicator",
                "id": f"indicator--{indicator.id}",
                "created": indicator.first_seen.isoformat(),
                "modified": indicator.last_seen.isoformat(),
                "pattern": f"[{self._get_stix_pattern(indicator)}]",
                "labels": [indicator.threat_level.lower()],
                "confidence": int(indicator.confidence_score)
            }
            stix_objects.append(stix_indicator)
        
        return {
            "type": "bundle",
            "id": f"bundle--{timezone.now().isoformat()}",
            "objects": stix_objects
        }
    
    def _get_stix_pattern(self, indicator):
        """Convert indicator to STIX pattern"""
        if indicator.indicator_type == 'DOMAIN':
            return f"domain-name:value = '{indicator.indicator_value}'"
        elif indicator.indicator_type == 'IP':
            return f"ipv4-addr:value = '{indicator.indicator_value}'"
        elif indicator.indicator_type == 'URL':
            return f"url:value = '{indicator.indicator_value}'"
        elif indicator.indicator_type == 'HASH':
            return f"file:hashes.MD5 = '{indicator.indicator_value}'"
        else:
            return f"artifact:payload_bin = '{indicator.indicator_value}'"
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class IPReputationViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for IP reputation data"""
    
    queryset = IPReputation.objects.all()
    serializer_class = IPReputationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['reputation', 'country', 'is_tor_exit_node', 'is_proxy', 'is_vpn']
    search_fields = ['ip_address', 'isp', 'organization']
    ordering = ['-last_updated']


class DomainReputationViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for domain reputation data"""
    
    queryset = DomainReputation.objects.all()
    serializer_class = DomainReputationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['reputation', 'is_dga', 'is_typosquatting', 'is_parked']
    search_fields = ['domain_name', 'registrar', 'registrant_name']
    ordering = ['-reputation_updated']


class ThreatFeedViewSet(viewsets.ModelViewSet):
    """ViewSet for managing threat feeds"""
    
    queryset = ThreatFeed.objects.all()
    serializer_class = ThreatFeedSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['feed_type', 'feed_format', 'is_active']
    search_fields = ['name', 'description']
    ordering = ['name']
    
    def perform_create(self, serializer):
        """Create threat feed"""
        feed = serializer.save(created_by=self.request.user)
        
        ActivityLog.log_activity(
            user=self.request.user,
            activity_type='THREAT_FEED_UPDATE',
            description=f'Created threat feed: {feed.name}',
            content_object=feed,
            ip_address=self.get_client_ip()
        )
    
    @action(detail=False, methods=['post'])
    def update_feeds(self, request):
        """Update threat feeds"""
        serializer = ThreatFeedUpdateSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        feed_ids = data.get('feed_ids', [])
        force_update = data.get('force_update', False)
        
        if feed_ids:
            feeds = ThreatFeed.objects.filter(id__in=feed_ids, is_active=True)
        else:
            feeds = ThreatFeed.objects.filter(is_active=True)
        
        updated_feeds = []
        errors = []
        
        threat_service = ThreatIntelligenceService()
        
        for feed in feeds:
            try:
                # Check if update is needed
                if not force_update and feed.last_update:
                    time_since_update = timezone.now() - feed.last_update
                    if time_since_update.seconds < feed.update_frequency:
                        continue
                
                threat_service._update_single_feed(feed)
                updated_feeds.append({
                    'id': feed.id,
                    'name': feed.name,
                    'status': 'updated'
                })
                
            except Exception as e:
                errors.append({
                    'id': feed.id,
                    'name': feed.name,
                    'error': str(e)
                })
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='THREAT_FEED_UPDATE',
            description=f'Updated {len(updated_feeds)} threat feeds',
            ip_address=self.get_client_ip(),
            additional_data={
                'updated_feeds': len(updated_feeds),
                'errors': len(errors)
            }
        )
        
        return Response({
            'updated_feeds': updated_feeds,
            'errors': errors,
            'total_processed': len(feeds),
            'successful': len(updated_feeds),
            'failed': len(errors)
        })
    
    @action(detail=True, methods=['post'])
    def test_feed(self, request, pk=None):
        """Test a threat feed connection"""
        feed = self.get_object()
        
        try:
            threat_service = ThreatIntelligenceService()
            threat_service._update_single_feed(feed)
            
            return Response({
                'status': 'success',
                'message': f'Feed {feed.name} tested successfully',
                'last_update': feed.last_update,
                'total_indicators': feed.total_indicators
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Feed test failed: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class ThreatAttributionViewSet(viewsets.ModelViewSet):
    """ViewSet for threat attribution data"""
    
    queryset = ThreatAttribution.objects.all()
    serializer_class = ThreatAttributionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['actor_type', 'suspected_country']
    search_fields = ['actor_name', 'aliases', 'motivation']
    ordering = ['-last_activity']


class ThreatIntelligenceReportViewSet(viewsets.ModelViewSet):
    """ViewSet for threat intelligence reports"""
    
    queryset = ThreatIntelligenceReport.objects.all()
    serializer_class = ThreatIntelligenceReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['report_type', 'severity', 'is_published', 'tlp_classification']
    search_fields = ['title', 'executive_summary', 'tags']
    ordering = ['-created_at']
    
    def perform_create(self, serializer):
        """Create threat intelligence report"""
        report = serializer.save(author=self.request.user)
        
        ActivityLog.log_activity(
            user=self.request.user,
            activity_type='REPORT_GENERATE',
            description=f'Created threat intelligence report: {report.title}',
            content_object=report,
            ip_address=self.get_client_ip()
        )
    
    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish a threat intelligence report"""
        report = self.get_object()
        
        if report.author != request.user and not request.user.profile.has_permission('manage_threat_feeds'):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        report.is_published = True
        report.published_at = timezone.now()
        report.save()
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='REPORT_GENERATE',
            description=f'Published threat intelligence report: {report.title}',
            content_object=report,
            ip_address=self.get_client_ip()
        )
        
        serializer = self.get_serializer(report)
        return Response(serializer.data)
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class ThreatAnalysisViewSet(viewsets.ViewSet):
    """ViewSet for threat analysis operations"""
    
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def analyze(self, request):
        """Perform threat analysis on a target"""
        serializer = ThreatAnalysisSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        analysis_type = data['analysis_type']
        target = data['target']
        
        threat_service = ThreatIntelligenceService()
        
        try:
            if analysis_type == 'DOMAIN':
                result = threat_service.analyze_domain(target)
                if result:
                    serializer = DomainReputationSerializer(result)
                    analysis_data = serializer.data
                else:
                    analysis_data = {'error': 'Domain analysis failed'}
                    
            elif analysis_type == 'IP':
                result = threat_service.analyze_ip(target)
                if result:
                    serializer = IPReputationSerializer(result)
                    analysis_data = serializer.data
                else:
                    analysis_data = {'error': 'IP analysis failed'}
                    
            elif analysis_type == 'URL':
                # URL analysis would be implemented here
                analysis_data = {'message': 'URL analysis not yet implemented'}
                
            elif analysis_type == 'HASH':
                # Hash analysis would be implemented here
                analysis_data = {'message': 'Hash analysis not yet implemented'}
            
            ActivityLog.log_activity(
                user=request.user,
                activity_type='ANALYSIS_CREATE',
                description=f'Performed {analysis_type} analysis on {target}',
                ip_address=self.get_client_ip(),
                additional_data={
                    'analysis_type': analysis_type,
                    'target': target
                }
            )
            
            return Response({
                'analysis_type': analysis_type,
                'target': target,
                'result': analysis_data
            })
            
        except Exception as e:
            logger.error(f"Threat analysis failed: {str(e)}")
            return Response(
                {'error': f'Analysis failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self):
        """Get client IP address"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')
