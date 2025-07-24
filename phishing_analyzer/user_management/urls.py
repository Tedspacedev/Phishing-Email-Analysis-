from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API Router
router = DefaultRouter()
router.register(r'profiles', views.UserProfileViewSet, basename='userprofile')
router.register(r'activity-logs', views.ActivityLogViewSet, basename='activitylog')
router.register(r'sessions', views.UserSessionViewSet, basename='usersession')
router.register(r'api-keys', views.APIKeyViewSet, basename='apikey')
router.register(r'auth', views.AuthViewSet, basename='auth')

app_name = 'user_management'

urlpatterns = [
    # API URLs
    path('api/', include(router.urls)),
    
    # Web Interface URLs
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
]