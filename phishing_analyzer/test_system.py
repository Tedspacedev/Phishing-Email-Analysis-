#!/usr/bin/env python
"""
Test script for the Phishing Email Analysis System
Demonstrates key functionality and API endpoints
"""

import os
import sys
import django
from datetime import datetime

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishing_analyzer.settings')
django.setup()

from django.contrib.auth.models import User
from email_analysis.models import EmailAnalysis
from email_analysis.services import EmailParser, PhishingAnalyzer
from threat_intelligence.services import ThreatIntelligenceService
from user_management.models import UserProfile, ActivityLog


def create_test_data():
    """Create test data for demonstration"""
    print("🔧 Creating test data...")
    
    # Create test user if not exists
    if not User.objects.filter(username='testuser').exists():
        user = User.objects.create_user(
            username='testuser',
            email='test@eliteluxe.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create user profile
        UserProfile.objects.create(
            user=user,
            role='SECURITY_ANALYST',
            department='IT_SECURITY',
            phone_number='+1-555-0123'
        )
        print(f"✅ Created test user: {user.username}")
    else:
        user = User.objects.get(username='testuser')
        print(f"✅ Using existing test user: {user.username}")
    
    return user


def test_email_analysis():
    """Test email analysis functionality"""
    print("\n📧 Testing Email Analysis...")
    
    # Sample phishing email
    sample_email = {
        'subject': 'URGENT: Verify Your Account Now!',
        'sender': 'security@paypaI-verification.com',  # Note the 'I' instead of 'l'
        'recipient': 'user@eliteluxe.com',
        'body': '''
        Dear Customer,
        
        Your PayPal account has been temporarily suspended due to suspicious activity.
        
        Click here to verify your account immediately:
        http://paypal-verify.suspicious-domain.tk/login
        
        If you don't verify within 24 hours, your account will be permanently closed.
        
        Urgent action required!
        
        PayPal Security Team
        ''',
        'raw_email': '''
        From: security@paypaI-verification.com
        To: user@eliteluxe.com
        Subject: URGENT: Verify Your Account Now!
        Date: Mon, 24 Jul 2024 10:00:00 +0000
        Message-ID: <fake123@suspicious-domain.tk>
        
        [Body content above]
        '''
    }
    
    try:
        # Parse email
        parser = EmailParser()
        parsed_data = parser.parse_email_content(
            sample_email['raw_email'],
            sample_email['subject'],
            sample_email['sender'],
            sample_email['recipient'],
            sample_email['body']
        )
        print(f"✅ Email parsed successfully")
        print(f"   - Subject: {parsed_data['subject']}")
        print(f"   - Sender: {parsed_data['sender']}")
        print(f"   - URLs found: {len(parsed_data['urls'])}")
        
        # Analyze for phishing
        analyzer = PhishingAnalyzer()
        analysis_result = analyzer.analyze_email(parsed_data)
        
        print(f"✅ Phishing analysis completed")
        print(f"   - Risk Level: {analysis_result['risk_level']}")
        print(f"   - Phishing Score: {analysis_result['phishing_score']:.1f}%")
        print(f"   - Techniques Detected: {len(analysis_result['techniques'])}")
        
        # Create database record
        user = User.objects.get(username='testuser')
        email_analysis = EmailAnalysis.objects.create(
            email_subject=sample_email['subject'],
            sender_email=sample_email['sender'],
            recipient_email=sample_email['recipient'],
            email_body=sample_email['body'],
            raw_email=sample_email['raw_email'],
            risk_level=analysis_result['risk_level'],
            phishing_score=analysis_result['phishing_score'],
            is_phishing=analysis_result['phishing_score'] > 70,
            analyzed_by=user,
            status='COMPLETED',
            threat_indicators=analysis_result.get('threat_indicators', {}),
            analysis_summary=analysis_result.get('summary', ''),
            recommendations=analysis_result.get('recommendations', [])
        )
        
        print(f"✅ Analysis saved to database (ID: {email_analysis.id})")
        
        return email_analysis
        
    except Exception as e:
        print(f"❌ Email analysis failed: {str(e)}")
        return None


def test_threat_intelligence():
    """Test threat intelligence functionality"""
    print("\n🛡️  Testing Threat Intelligence...")
    
    try:
        threat_service = ThreatIntelligenceService()
        
        # Test domain analysis
        test_domain = "suspicious-domain.tk"
        print(f"   Analyzing domain: {test_domain}")
        
        domain_analysis = threat_service.analyze_domain(test_domain)
        if domain_analysis:
            print(f"✅ Domain analysis completed")
            print(f"   - Domain: {domain_analysis.domain_name}")
            print(f"   - Reputation: {domain_analysis.reputation}")
            print(f"   - Is DGA: {domain_analysis.is_dga}")
        else:
            print(f"⚠️  Domain analysis completed with limited data (no external APIs)")
        
        # Test IP analysis
        test_ip = "192.168.1.100"
        print(f"   Analyzing IP: {test_ip}")
        
        ip_analysis = threat_service.analyze_ip(test_ip)
        if ip_analysis:
            print(f"✅ IP analysis completed")
            print(f"   - IP: {ip_analysis.ip_address}")
            print(f"   - Reputation: {ip_analysis.reputation}")
        else:
            print(f"⚠️  IP analysis completed with limited data")
        
        return True
        
    except Exception as e:
        print(f"❌ Threat intelligence test failed: {str(e)}")
        return False


def test_user_management():
    """Test user management functionality"""
    print("\n👥 Testing User Management...")
    
    try:
        # Test activity logging
        user = User.objects.get(username='testuser')
        
        ActivityLog.log_activity(
            user=user,
            activity_type='ANALYSIS_CREATE',
            description='Test email analysis performed',
            ip_address='127.0.0.1',
            additional_data={'test': True}
        )
        
        print(f"✅ Activity logged successfully")
        
        # Check user profile
        profile = user.profile
        print(f"✅ User profile found")
        print(f"   - Role: {profile.get_role_display()}")
        print(f"   - Department: {profile.get_department_display()}")
        print(f"   - Has permissions: {profile.has_permission('analyze_emails')}")
        
        return True
        
    except Exception as e:
        print(f"❌ User management test failed: {str(e)}")
        return False


def show_statistics():
    """Display system statistics"""
    print("\n📊 System Statistics:")
    
    try:
        # Email analysis stats
        total_analyses = EmailAnalysis.objects.count()
        high_risk = EmailAnalysis.objects.filter(risk_level='HIGH').count()
        medium_risk = EmailAnalysis.objects.filter(risk_level='MEDIUM').count()
        low_risk = EmailAnalysis.objects.filter(risk_level='LOW').count()
        
        print(f"   📧 Email Analyses:")
        print(f"      - Total: {total_analyses}")
        print(f"      - High Risk: {high_risk}")
        print(f"      - Medium Risk: {medium_risk}")
        print(f"      - Low Risk: {low_risk}")
        
        # User stats
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        
        print(f"   👥 Users:")
        print(f"      - Total: {total_users}")
        print(f"      - Active: {active_users}")
        
        # Activity stats
        total_activities = ActivityLog.objects.count()
        recent_activities = ActivityLog.objects.filter(
            timestamp__gte=datetime.now().replace(hour=0, minute=0, second=0)
        ).count()
        
        print(f"   📝 Activities:")
        print(f"      - Total: {total_activities}")
        print(f"      - Today: {recent_activities}")
        
    except Exception as e:
        print(f"❌ Statistics failed: {str(e)}")


def main():
    """Main test function"""
    print("🚀 Phishing Email Analysis System - Test Suite")
    print("=" * 60)
    
    # Create test data
    user = create_test_data()
    
    # Run tests
    tests_passed = 0
    total_tests = 3
    
    # Test email analysis
    if test_email_analysis():
        tests_passed += 1
    
    # Test threat intelligence
    if test_threat_intelligence():
        tests_passed += 1
    
    # Test user management
    if test_user_management():
        tests_passed += 1
    
    # Show statistics
    show_statistics()
    
    # Summary
    print("\n" + "=" * 60)
    print(f"🎯 Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("✅ All tests passed! System is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    print("\n🌐 Access the system:")
    print("   - Web Interface: http://localhost:8000/")
    print("   - Admin Panel: http://localhost:8000/admin/")
    print("   - Login: admin / admin123")
    print("   - Test User: testuser / testpass123")


if __name__ == '__main__':
    main()