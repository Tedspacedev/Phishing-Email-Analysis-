"""
URL configuration for phishing_analyzer project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API Documentation and browsable API
    path('api-auth/', include('rest_framework.urls')),
    
    # Main application URLs
    path('', RedirectView.as_view(url='/email-analysis/', permanent=False)),
    path('email-analysis/', include('email_analysis.urls')),
    path('threat-intelligence/', include('threat_intelligence.urls')),
    path('users/', include('user_management.urls')),
    
    # API root
    path('api/v1/', include([
        path('email-analysis/', include('email_analysis.urls')),
        path('threat-intelligence/', include('threat_intelligence.urls')),
        path('users/', include('user_management.urls')),
    ])),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
