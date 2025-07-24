from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API Router
router = DefaultRouter()
router.register(r'analyses', views.EmailAnalysisViewSet, basename='emailanalysis')
router.register(r'urls', views.URLAnalysisViewSet, basename='urlanalysis')
router.register(r'attachments', views.AttachmentAnalysisViewSet, basename='attachmentanalysis')
router.register(r'techniques', views.PhishingTechniqueViewSet, basename='phishingtechnique')
router.register(r'headers', views.EmailHeaderViewSet, basename='emailheader')

app_name = 'email_analysis'

urlpatterns = [
    # Web Interface URLs (put these first!)
    path('', views.dashboard, name='dashboard'),
    path('analysis/<int:analysis_id>/', views.analysis_detail, name='analysis_detail'),

    # API URLs
    path('', include(router.urls)),
]