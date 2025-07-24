from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API Router
router = DefaultRouter()
router.register(r'indicators', views.ThreatIndicatorViewSet, basename='threatindicator')
router.register(r'ip-reputation', views.IPReputationViewSet, basename='ipreputation')
router.register(r'domain-reputation', views.DomainReputationViewSet, basename='domainreputation')
router.register(r'feeds', views.ThreatFeedViewSet, basename='threatfeed')
router.register(r'attribution', views.ThreatAttributionViewSet, basename='threatattribution')
router.register(r'reports', views.ThreatIntelligenceReportViewSet, basename='threatreport')
router.register(r'analysis', views.ThreatAnalysisViewSet, basename='threatanalysis')

app_name = 'threat_intelligence'

urlpatterns = [
    # API URLs
    path('api/', include(router.urls)),
]