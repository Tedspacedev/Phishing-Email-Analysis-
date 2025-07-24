from django.shortcuts import render, redirect
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, JSONParser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
import logging
from django.http import HttpResponse, JsonResponse
import csv
import io
try:
    from reportlab.pdfgen import canvas
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

from .models import (
    EmailAnalysis, EmailHeader, URLAnalysis, 
    AttachmentAnalysis, PhishingTechnique
)
from .serializers import (
    EmailAnalysisSerializer, EmailAnalysisCreateSerializer,
    EmailAnalysisListSerializer, EmailAnalysisStatsSerializer,
    BulkEmailAnalysisSerializer, EmailAnalysisReportSerializer,
    URLAnalysisSerializer, AttachmentAnalysisSerializer,
    PhishingTechniqueSerializer, EmailHeaderSerializer
)
from .services import EmailParser, PhishingAnalyzer
from user_management.models import ActivityLog

logger = logging.getLogger(__name__)


class EmailAnalysisViewSet(viewsets.ModelViewSet):
    """ViewSet for managing email analyses"""
    
    queryset = EmailAnalysis.objects.all()
    parser_classes = [JSONParser, MultiPartParser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['risk_level', 'is_phishing', 'status', 'analyzed_by']
    search_fields = ['email_subject', 'sender_email', 'recipient_email']
    ordering_fields = ['created_at', 'updated_at', 'phishing_score', 'risk_level']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return EmailAnalysisCreateSerializer
        elif self.action == 'list':
            return EmailAnalysisListSerializer
        elif self.action in ['bulk_analyze', 'bulk_upload']:
            return BulkEmailAnalysisSerializer
        elif self.action == 'generate_report':
            return EmailAnalysisReportSerializer
        elif self.action == 'statistics':
            return EmailAnalysisStatsSerializer
        return EmailAnalysisSerializer
    
    def get_permissions(self):
        """Set permissions based on user role"""
        if self.action in ['create', 'bulk_analyze']:
            permission_classes = [permissions.IsAuthenticated]
        elif self.action in ['destroy', 'bulk_delete']:
            permission_classes = [permissions.IsAuthenticated]  # Add custom permission check
        else:
            permission_classes = [permissions.IsAuthenticated]
        
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        user = self.request.user
        
        # Check user role and filter accordingly
        if hasattr(user, 'profile'):
            if user.profile.has_permission('view_all_analyses'):
                return EmailAnalysis.objects.all()
            else:
                return EmailAnalysis.objects.filter(analyzed_by=user)
        
        return EmailAnalysis.objects.filter(analyzed_by=user)
    
    def perform_create(self, serializer):
        """Create email analysis and trigger analysis process"""
        email_analysis = serializer.save(analyzed_by=self.request.user)
        
        # Log the activity
        ActivityLog.log_activity(
            user=self.request.user,
            activity_type='ANALYSIS_CREATE',
            description=f'Created email analysis for {email_analysis.sender_email}',
            content_object=email_analysis,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Trigger analysis process (could be moved to a background task)
        try:
            self.trigger_analysis(email_analysis)
        except Exception as e:
            logger.error(f"Error triggering analysis for {email_analysis.id}: {str(e)}")
            email_analysis.status = 'FAILED'
            email_analysis.save()
    
    def trigger_analysis(self, email_analysis):
        """Trigger the phishing analysis process"""
        try:
            # Parse email content
            parser = EmailParser(email_analysis.raw_email)
            parsed_data = parser.parse_email()
            
            # Update email analysis with parsed data
            email_analysis.email_subject = parsed_data.get('subject', email_analysis.email_subject)
            email_analysis.sender_email = parsed_data.get('sender', email_analysis.sender_email)
            email_analysis.recipient_email = parsed_data.get('recipient', email_analysis.recipient_email)
            email_analysis.email_body = parsed_data.get('body', email_analysis.email_body)
            email_analysis.status = 'PROCESSING'
            email_analysis.save()
            
            # Create header analysis record
            EmailHeader.objects.create(
                email_analysis=email_analysis,
                raw_headers=str(parsed_data.get('headers', {})),
                message_id=parsed_data.get('message_id', ''),
                received_headers=parsed_data.get('received_headers', [])
            )
            
            # Run phishing analysis
            analyzer = PhishingAnalyzer(email_analysis)
            analyzer.analyze()
            
        except Exception as e:
            logger.error(f"Analysis failed for email {email_analysis.id}: {str(e)}")
            email_analysis.status = 'FAILED'
            email_analysis.save()
            raise
    
    @action(detail=True, methods=['post'])
    def reanalyze(self, request, pk=None):
        """Rerun analysis on an existing email"""
        email_analysis = self.get_object()
        
        if not request.user.profile.has_permission('edit_analysis'):
            return Response(
                {'error': 'Permission denied'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            email_analysis.status = 'PENDING'
            email_analysis.save()
            
            self.trigger_analysis(email_analysis)
            
            ActivityLog.log_activity(
                user=request.user,
                activity_type='ANALYSIS_UPDATE',
                description=f'Reanalyzed email {email_analysis.id}',
                content_object=email_analysis,
                ip_address=self.get_client_ip()
            )
            
            serializer = self.get_serializer(email_analysis)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {'error': f'Reanalysis failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def bulk_analyze(self, request):
        """Bulk analyze multiple emails"""
        serializer = BulkEmailAnalysisSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        emails_data = serializer.validated_data['emails']
        created_analyses = []
        errors = []
        
        for i, email_data in enumerate(emails_data):
            try:
                # Create email analysis
                analysis_serializer = EmailAnalysisCreateSerializer(
                    data=email_data, 
                    context={'request': request}
                )
                
                if analysis_serializer.is_valid():
                    email_analysis = analysis_serializer.save()
                    created_analyses.append(email_analysis.id)
                    
                    # Trigger analysis
                    self.trigger_analysis(email_analysis)
                else:
                    errors.append({
                        'email_index': i + 1,
                        'errors': analysis_serializer.errors
                    })
                    
            except Exception as e:
                errors.append({
                    'email_index': i + 1,
                    'error': str(e)
                })
        
        ActivityLog.log_activity(
            user=request.user,
            activity_type='ANALYSIS_CREATE',
            description=f'Bulk analyzed {len(created_analyses)} emails',
            ip_address=self.get_client_ip(),
            additional_data={
                'created_analyses': created_analyses,
                'errors_count': len(errors)
            }
        )
        
        return Response({
            'created_analyses': created_analyses,
            'errors': errors,
            'total_processed': len(emails_data),
            'successful': len(created_analyses),
            'failed': len(errors)
        })
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get email analysis statistics"""
        now = timezone.now()
        today = now.date()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        queryset = self.get_queryset()
        
        # Basic counts
        total_analyses = queryset.count()
        pending_analyses = queryset.filter(status='PENDING').count()
        completed_analyses = queryset.filter(status='COMPLETED').count()
        failed_analyses = queryset.filter(status='FAILED').count()
        phishing_detected = queryset.filter(is_phishing=True).count()
        
        # Risk level breakdown
        risk_counts = queryset.values('risk_level').annotate(count=Count('id'))
        risk_breakdown = {item['risk_level'].lower() + '_risk': item['count'] for item in risk_counts}
        
        # Time-based stats
        analyses_today = queryset.filter(created_at__date=today).count()
        analyses_this_week = queryset.filter(created_at__gte=week_ago).count()
        analyses_this_month = queryset.filter(created_at__gte=month_ago).count()
        
        # Average metrics
        completed_queryset = queryset.filter(status='COMPLETED')
        avg_phishing_score = completed_queryset.aggregate(
            avg_score=Avg('phishing_score')
        )['avg_score'] or 0.0
        
        avg_analysis_duration = completed_queryset.aggregate(
            avg_duration=Avg('analysis_duration')
        )['avg_duration'] or 0.0
        
        # Top threat indicators (simplified)
        top_threat_indicators = [
            {'type': 'SUSPICIOUS_SUBJECT', 'count': 15},
            {'type': 'MALICIOUS_URL', 'count': 12},
            {'type': 'CREDENTIAL_HARVESTING', 'count': 8}
        ]
        
        # Top malicious domains (simplified)
        top_malicious_domains = [
            {'domain': 'suspicious-site.com', 'count': 5},
            {'domain': 'phishing-example.org', 'count': 3}
        ]
        
        stats_data = {
            'total_analyses': total_analyses,
            'pending_analyses': pending_analyses,
            'completed_analyses': completed_analyses,
            'failed_analyses': failed_analyses,
            'phishing_detected': phishing_detected,
            'low_risk': risk_breakdown.get('low_risk', 0),
            'medium_risk': risk_breakdown.get('medium_risk', 0),
            'high_risk': risk_breakdown.get('high_risk', 0),
            'critical_risk': risk_breakdown.get('critical_risk', 0),
            'analyses_today': analyses_today,
            'analyses_this_week': analyses_this_week,
            'analyses_this_month': analyses_this_month,
            'avg_phishing_score': avg_phishing_score,
            'avg_analysis_duration': avg_analysis_duration,
            'top_threat_indicators': top_threat_indicators,
            'top_malicious_domains': top_malicious_domains
        }
        
        serializer = EmailAnalysisStatsSerializer(stats_data)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def generate_report(self, request):
        """Generate analysis report (CSV, JSON, PDF)"""
        serializer = EmailAnalysisReportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        validated_data = serializer.validated_data

        # Get analyses
        if validated_data.get('analysis_ids'):
            analyses = EmailAnalysis.objects.filter(id__in=validated_data['analysis_ids'])
        else:
            analyses = EmailAnalysis.objects.filter(
                created_at__gte=validated_data['date_from'],
                created_at__lte=validated_data['date_to']
            )

        # CSV Export
        if validated_data['report_format'] == 'CSV':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="email_analysis_report.csv"'
            writer = csv.writer(response)
            writer.writerow(['ID', 'Subject', 'Sender', 'Recipient', 'Risk Level', 'Phishing Score', 'Status', 'Created At'])
            for a in analyses:
                writer.writerow([a.id, a.email_subject, a.sender_email, a.recipient_email, a.risk_level, a.phishing_score, a.status, a.created_at])
            return response

        # JSON Export
        if validated_data['report_format'] == 'JSON':
            data = []
            for a in analyses:
                data.append({
                    'id': a.id,
                    'email_subject': a.email_subject,
                    'sender_email': a.sender_email,
                    'recipient_email': a.recipient_email,
                    'risk_level': a.risk_level,
                    'phishing_score': a.phishing_score,
                    'status': a.status,
                    'created_at': a.created_at,
                })
            return JsonResponse({'analyses': data}, safe=False)

        # PDF Export (simple placeholder)
        if validated_data['report_format'] == 'PDF':
            if not PDF_AVAILABLE:
                return Response({'error': 'PDF export requires reportlab. Please install it.'}, status=501)
            buffer = io.BytesIO()
            p = canvas.Canvas(buffer)
            p.drawString(100, 800, "Email Analysis Report")
            y = 780
            for a in analyses:
                p.drawString(100, y, f"ID: {a.id} | Subject: {a.email_subject} | Risk: {a.risk_level}")
                y -= 20
                if y < 50:
                    p.showPage()
                    y = 800
            p.save()
            buffer.seek(0)
            response = HttpResponse(buffer, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="email_analysis_report.pdf"'
            return response

        # Not implemented
        return Response({'error': f"Format {validated_data['report_format']} not implemented."}, status=501)
    
    def get_client_ip(self):
        """Get client IP address from request"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')


class URLAnalysisViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for URL analysis results"""
    
    queryset = URLAnalysis.objects.all()
    serializer_class = URLAnalysisSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['threat_level', 'is_shortened', 'virustotal_detected']
    search_fields = ['original_url', 'domain']
    ordering = ['-created_at']


class AttachmentAnalysisViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for attachment analysis results"""
    
    queryset = AttachmentAnalysis.objects.all()
    serializer_class = AttachmentAnalysisSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['threat_level', 'is_executable', 'has_macros', 'virustotal_detected']
    search_fields = ['filename', 'file_type']
    ordering = ['-created_at']


class PhishingTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for phishing technique detection results"""
    
    queryset = PhishingTechnique.objects.all()
    serializer_class = PhishingTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['technique_type']
    search_fields = ['technique_name', 'description']
    ordering = ['-confidence_score']


class EmailHeaderViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for email header analysis results"""
    
    queryset = EmailHeader.objects.all()
    serializer_class = EmailHeaderSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['spf_result', 'dkim_result', 'dmarc_result']
    search_fields = ['message_id', 'sender_country']
    ordering = ['-created_at']


# Traditional Django views for web interface
def dashboard(request):
    """Dashboard view showing analysis overview"""
    if not request.user.is_authenticated:
        return redirect('user_management:user_login')
    
    # Get recent analyses
    recent_analyses = EmailAnalysis.objects.filter(
        analyzed_by=request.user
    ).order_by('-created_at')[:10]
    
    # Get statistics
    total_analyses = EmailAnalysis.objects.filter(analyzed_by=request.user).count()
    phishing_detected = EmailAnalysis.objects.filter(
        analyzed_by=request.user, 
        is_phishing=True
    ).count()
    
    # Accurate risk counts
    high_risk_count = EmailAnalysis.objects.filter(analyzed_by=request.user, risk_level='HIGH').count()
    medium_risk_count = EmailAnalysis.objects.filter(analyzed_by=request.user, risk_level='MEDIUM').count()
    low_risk_count = EmailAnalysis.objects.filter(analyzed_by=request.user, risk_level='LOW').count()
    
    # Trend data for the last 6 months
    from django.utils import timezone
    from collections import OrderedDict
    import calendar
    now = timezone.now()
    months = [(now.replace(day=1) - timezone.timedelta(days=30*i)).strftime('%b %Y') for i in reversed(range(6))]
    month_labels = [m.split()[0] for m in months]
    month_years = [m for m in months]
    month_counts = OrderedDict((m, 0) for m in month_years)
    high_risk_trend = OrderedDict((m, 0) for m in month_years)
    analyses = EmailAnalysis.objects.filter(analyzed_by=request.user, created_at__gte=now - timezone.timedelta(days=180))
    for a in analyses:
        m = a.created_at.strftime('%b %Y')
        if m in month_counts:
            month_counts[m] += 1
            if a.risk_level == 'HIGH':
                high_risk_trend[m] += 1
    
    context = {
        'recent_analyses': recent_analyses,
        'total_analyses': total_analyses,
        'phishing_detected': phishing_detected,
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'low_risk_count': low_risk_count,
        'trend_labels': list(month_labels),
        'trend_total': list(month_counts.values()),
        'trend_high': list(high_risk_trend.values()),
    }
    
    return render(request, 'email_analysis/dashboard.html', context)


def analysis_detail(request, analysis_id):
    """Detailed view of a specific email analysis"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    try:
        analysis = EmailAnalysis.objects.get(
            id=analysis_id,
            analyzed_by=request.user
        )
    except EmailAnalysis.DoesNotExist:
        return render(request, '404.html', status=404)
    
    # Log view activity
    ActivityLog.log_activity(
        user=request.user,
        activity_type='ANALYSIS_VIEW',
        description=f'Viewed analysis {analysis_id}',
        content_object=analysis,
        ip_address=get_client_ip(request)
    )
    
    context = {
        'analysis': analysis,
        'url_analyses': list(analysis.url_analyses.all()),
        'attachment_analyses': list(analysis.attachment_analyses.all()),
        'phishing_techniques': list(analysis.phishing_techniques.all()),
        'header_analysis': getattr(analysis, 'header_analysis', None),
    }
    
    return render(request, 'email_analysis/analysis_detail.html', context)


def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')
