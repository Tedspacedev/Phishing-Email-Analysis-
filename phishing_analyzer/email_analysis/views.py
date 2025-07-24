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
import os
import time
from django.conf import settings
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
# Remove WeasyPrint import and template usage
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
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"[perform_create] User: {self.request.user}, Data: {serializer.validated_data if hasattr(serializer, 'validated_data') else 'N/A'}")
        email_analysis = serializer.save(analyzed_by=self.request.user)
        logger.debug(f"[perform_create] Created EmailAnalysis ID: {email_analysis.id}")
        
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
            logger.debug(f"[perform_create] Triggering analysis for EmailAnalysis ID: {email_analysis.id}")
            self.trigger_analysis(email_analysis)
        except Exception as e:
            logger.error(f"Error triggering analysis for {email_analysis.id}: {str(e)}", exc_info=True)
            email_analysis.status = 'FAILED'
            email_analysis.save()
    
    def create(self, request, *args, **kwargs):
        print(f"[API] Analyze Email request received. User: {request.user}, Data: {request.data}")
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            print(f"[API] Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=400)
        response = super().create(request, *args, **kwargs)
        print(f"[API] Analyze Email response status: {response.status_code}, data: {getattr(response, 'data', None)}")
        return response
    
    def trigger_analysis(self, email_analysis):
        """Trigger the phishing analysis process"""
        import logging
        logger = logging.getLogger(__name__)
        try:
            logger.debug(f"[trigger_analysis] Parsing email for EmailAnalysis ID: {email_analysis.id}")
            # Parse email content
            parser = EmailParser(email_analysis.raw_email)
            parsed_data = parser.parse_email()
            logger.debug(f"[trigger_analysis] Parsed data: {parsed_data}")
            # Update email analysis with parsed data
            email_analysis.email_subject = parsed_data.get('subject', email_analysis.email_subject)
            if parsed_data.get('sender'):
                email_analysis.sender_email = parsed_data['sender']
            if parsed_data.get('recipient'):
                email_analysis.recipient_email = parsed_data['recipient']
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
            logger.debug(f"[trigger_analysis] Created EmailHeader for EmailAnalysis ID: {email_analysis.id}")
            
            # Run phishing analysis
            analyzer = PhishingAnalyzer(email_analysis)
            analyzer.analyze()
            logger.debug(f"[trigger_analysis] Completed phishing analysis for EmailAnalysis ID: {email_analysis.id}")
        except Exception as e:
            logger.error(f"Analysis failed for email {email_analysis.id}: {str(e)}", exc_info=True)
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
        print('[generate_report] Incoming data:', dict(request.data))
        serializer = EmailAnalysisReportSerializer(data=request.data)
        if not serializer.is_valid():
            print('[generate_report] Validation errors:', serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        validated_data = serializer.validated_data
        print('[generate_report] Validated data:', validated_data)
        print('[generate_report] Requested format:', validated_data['report_format'])

        # Get analyses
        if validated_data.get('analysis_ids'):
            analyses = EmailAnalysis.objects.filter(id__in=validated_data['analysis_ids'])
        else:
            analyses = EmailAnalysis.objects.filter(
                created_at__gte=validated_data['date_from'],
                created_at__lte=validated_data['date_to']
            )
        print(f'[generate_report] Analyses count: {analyses.count()}')
        for a in analyses:
            print(f'[generate_report] Analysis row: id={a.id}, subject={a.email_subject}, sender={a.sender_email}, recipient={a.recipient_email}, risk={a.risk_level}, score={a.phishing_score}, status={a.status}')

        # CSV Export
        if validated_data['report_format'] == 'CSV':
            print('[generate_report] Entering CSV export branch')
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="email_analysis_report.csv"'
            writer = csv.writer(response)
            header = ['ID', 'Subject', 'Sender', 'Recipient', 'Risk Level', 'Phishing Score', 'Status', 'Created At']
            print('[CSV Export] Header:', header)
            writer.writerow(header)
            for a in analyses:
                row = [a.id, a.email_subject, a.sender_email, a.recipient_email, a.risk_level, a.phishing_score, a.status, a.created_at]
                print('[CSV Export] Row:', row)
                writer.writerow(row)
            return response

        # JSON Export
        if validated_data['report_format'] == 'JSON':
            print('[generate_report] Entering JSON export branch')
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
            print('[JSON Export] Data:', data)
            return JsonResponse({'analyses': data}, safe=False)

        # PDF Export (save to file, return URL)
        if validated_data['report_format'] == 'PDF':
            print('[generate_report] Generating PDF (landscape format)')
            if not PDF_AVAILABLE:
                return Response({'error': 'PDF export requires reportlab. Please install it.'}, status=501)

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=landscape(A4),
                rightMargin=40,
                leftMargin=40,
                topMargin=60,
                bottomMargin=40
            )

            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='TableCell', fontSize=8, leading=10))
            styles.add(ParagraphStyle(name='ReportTitle', fontSize=16, leading=20, spaceAfter=12, alignment=0))
            styles.add(ParagraphStyle(name='SectionHeader', fontSize=12, leading=14, spaceAfter=6, alignment=0))
            styles.add(ParagraphStyle(name='MetaInfo', fontSize=10, leading=12, spaceAfter=4))

            elements = []

            # Header Title Block
            org_name = "Phishing Email Analysis System"
            report_title = "Phishing Email Analysis Report"
            generated_on = timezone.now().strftime('%Y-%m-%d %H:%M')
            user_str = str(request.user.username or 'anon').replace(' ', '_')
            date_from = validated_data['date_from'].strftime('%Y-%m-%d %H:%M')
            date_to = validated_data['date_to'].strftime('%Y-%m-%d %H:%M')

            # Professional Header
            elements.append(Paragraph(f"<b>{org_name}</b>", styles['ReportTitle']))
            elements.append(Paragraph(f"<b>{report_title}</b>", styles['SectionHeader']))
            elements.append(Spacer(1, 0.1 * inch))

            # Metadata block
            elements.append(Paragraph(f"<b>Prepared By:</b> {user_str}", styles['MetaInfo']))
            elements.append(Paragraph(f"<b>Date Generated:</b> {generated_on}", styles['MetaInfo']))
            elements.append(Paragraph(f"<b>Date Range:</b> {date_from} to {date_to}", styles['MetaInfo']))
            elements.append(Spacer(1, 0.2 * inch))

            # Table Header
            header = ["ID", "Subject", "Sender", "Recipient", "Risk Level", "Score", "Status"]
            data = [header]

            # Table Data
            analyses_list = list(analyses)
            if not analyses_list:
                elements.append(Paragraph("No analyses found for the selected date range.", styles['MetaInfo']))
            else:
                for a in analyses_list:
                    row = [
                        Paragraph(str(a.id), styles['TableCell']),
                        Paragraph(str(a.email_subject or '-')[:100], styles['TableCell']),
                        Paragraph(str(a.sender_email or '-')[:100], styles['TableCell']),
                        Paragraph(str(a.recipient_email or '-')[:100], styles['TableCell']),
                        Paragraph(str(a.risk_level or '-'), styles['TableCell']),
                        Paragraph(str(a.phishing_score or '-'), styles['TableCell']),
                        Paragraph(str(a.status or '-'), styles['TableCell']),
                    ]
                    data.append(row)

                table = Table(data, colWidths=[
                    0.6 * inch,  # ID
                    2.0 * inch,  # Subject
                    2.0 * inch,  # Sender
                    2.0 * inch,  # Recipient
                    1.0 * inch,  # Risk
                    0.7 * inch,  # Score
                    1.0 * inch   # Status
                ])

                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, 0), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
                ]))

                elements.append(table)

            # Footer: Page numbers
            def add_page_number(canvas, doc):
                canvas.saveState()
                canvas.setFont('Helvetica', 9)
                page_num_text = f"Page {doc.page}"
                canvas.drawRightString(landscape(A4)[0] - 40, 20, page_num_text)
                canvas.restoreState()

            doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)

            buffer.seek(0)
            pdf_bytes = buffer.getvalue()
            print(f'[PDF Export] PDF size in bytes: {len(pdf_bytes)}')

            timestamp = int(time.time())
            filename = f"report-{timestamp}-{user_str}.pdf"
            reports_dir = os.path.join(settings.BASE_DIR, 'phishing_analyzer', 'media', 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            file_path = os.path.join(reports_dir, filename)

            with open(file_path, 'wb') as f:
                f.write(pdf_bytes)

            print(f'[PDF Export] PDF written to: {file_path}')
            pdf_url = f"/media/reports/{filename}"
            return Response({'pdf_url': pdf_url}, status=200)

        print('[generate_report] Not implemented branch hit for format:', validated_data['report_format'])
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
