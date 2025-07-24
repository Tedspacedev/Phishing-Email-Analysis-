# 🧪 Testing and Setup Guide - Phishing Email Analysis System

## 🚀 Quick Start Testing

### 1. **System Status Check**
```bash
# Ensure virtual environment is active
source phishing_analyzer_env/bin/activate

# Navigate to project directory
cd phishing_analyzer

# Run system check
python manage.py check

# Start development server
python manage.py runserver 0.0.0.0:8000
```

### 2. **Access Points**
- **Web Interface**: http://localhost:8000/
- **Admin Panel**: http://localhost:8000/admin/
- **API Root**: http://localhost:8000/api/v1/

### 3. **Default Login Credentials**
- **Admin User**: `admin` / `admin123`
- **Test User**: `testuser` / `testpass123`

## 🔑 API Keys Setup

### **VirusTotal API Key** (Highly Recommended)
1. **Create Account**: Go to https://www.virustotal.com/
2. **Sign Up**: Create a free account
3. **Get API Key**: 
   - Go to your profile → API Key
   - Copy your API key
4. **Configure in System**:
   ```bash
   # Edit .env file
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

**Free Tier Limits**: 4 requests/minute, 500 requests/day

### **WHOIS API Key** (Optional)
For enhanced WHOIS data, you can use services like:
- **WhoisXML API**: https://whoisxmlapi.com/
- **WHOIS API**: https://whoisapi.co/
- **DomainTools**: https://domaintools.com/

```bash
# Add to .env file
WHOIS_API_KEY=your_whois_api_key_here
```

### **Without API Keys**
The system works without external API keys but with limited functionality:
- ✅ Email parsing and analysis
- ✅ Basic phishing detection
- ✅ User management
- ✅ Dashboard and reporting
- ❌ VirusTotal URL/file checking
- ❌ Enhanced WHOIS data
- ❌ External threat intelligence feeds

## 🧪 Comprehensive Testing Guide

### **1. Web Interface Testing**

#### **Dashboard Testing**
```bash
# Access dashboard
http://localhost:8000/

# Test features:
✅ View statistics cards
✅ Check interactive charts
✅ Test "Analyze Email" modal
✅ Submit sample phishing email
✅ Verify analysis results
```

#### **Admin Interface Testing**
```bash
# Access admin panel
http://localhost:8000/admin/

# Login with admin/admin123
# Test admin features:
✅ User management
✅ Email analysis records
✅ Threat intelligence data
✅ Activity logs
✅ System configuration
```

### **2. API Testing**

#### **Authentication Test**
```bash
# Get authentication token
curl -X POST http://localhost:8000/api/v1/users/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Expected response:
{
  "token": "your-auth-token-here",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@eliteluxe.com",
    "role": "ADMIN"
  }
}
```

#### **Email Analysis API Test**
```bash
# Replace YOUR_TOKEN with actual token from login
export TOKEN="your-auth-token-here"

# Create email analysis
curl -X POST http://localhost:8000/api/v1/email-analysis/analyses/ \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email_subject": "URGENT: Verify Your Account Now!",
    "sender_email": "security@paypaI-verification.com",
    "recipient_email": "user@eliteluxe.com",
    "email_body": "Your PayPal account has been suspended. Click here to verify: http://paypal-verify.suspicious-domain.tk/login"
  }'

# Get analysis results
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/v1/email-analysis/analyses/

# Get statistics
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/v1/email-analysis/analyses/statistics/
```

#### **Threat Intelligence API Test**
```bash
# Analyze domain
curl -X POST http://localhost:8000/api/v1/threat-intelligence/analysis/analyze/ \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_type": "DOMAIN",
    "target": "suspicious-domain.com"
  }'

# Get threat indicators
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/v1/threat-intelligence/indicators/

# Export IOCs
curl -X POST http://localhost:8000/api/v1/threat-intelligence/indicators/export_iocs/ \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "JSON"}'
```

### **3. System Test Script**
```bash
# Run comprehensive system test
python test_system.py

# Expected output:
🚀 Phishing Email Analysis System - Test Suite
============================================================
🔧 Creating test data...
✅ Created test user: testuser
📧 Testing Email Analysis...
✅ Email parsed successfully
✅ Phishing analysis completed
✅ Analysis saved to database
🛡️ Testing Threat Intelligence...
✅ Domain analysis completed
✅ IP analysis completed
👥 Testing User Management...
✅ Activity logged successfully
✅ User profile found
📊 System Statistics...
🎯 Test Results: 3/3 tests passed
✅ All tests passed! System is working correctly.
```

## 📊 Sample Test Data

### **Sample Phishing Email**
```json
{
  "email_subject": "URGENT: Verify Your PayPal Account",
  "sender_email": "security@paypaI-verification.com",
  "recipient_email": "user@eliteluxe.com",
  "email_body": "Dear Customer,\n\nYour PayPal account has been temporarily suspended due to suspicious activity.\n\nClick here to verify your account immediately:\nhttp://paypal-verify.suspicious-domain.tk/login\n\nIf you don't verify within 24 hours, your account will be permanently closed.\n\nUrgent action required!\n\nPayPal Security Team",
  "raw_email": "From: security@paypaI-verification.com\nTo: user@eliteluxe.com\nSubject: URGENT: Verify Your PayPal Account\nDate: Mon, 24 Jul 2024 10:00:00 +0000\nMessage-ID: <fake123@suspicious-domain.tk>\n\n[Body content above]"
}
```

### **Sample Legitimate Email**
```json
{
  "email_subject": "Monthly Security Report - July 2024",
  "sender_email": "security@eliteluxe.com",
  "recipient_email": "staff@eliteluxe.com",
  "email_body": "Dear Team,\n\nPlease find attached our monthly security report for July 2024.\n\nKey highlights:\n- 0 security incidents\n- 15 phishing attempts blocked\n- All systems operating normally\n\nBest regards,\nIT Security Team"
}
```

## 🔍 Testing Scenarios

### **High-Risk Phishing Detection**
Test emails that should score 70%+ risk:
- Urgent account verification requests
- Suspicious sender domains (typosquatting)
- Shortened URLs or suspicious links
- Requests for sensitive information
- Poor grammar/spelling
- Threatening language

### **Medium-Risk Detection**
Test emails that should score 30-70% risk:
- Promotional emails from unknown senders
- Emails with some suspicious elements
- Legitimate emails with minor red flags

### **Low-Risk Detection**
Test emails that should score 0-30% risk:
- Internal company emails
- Known legitimate senders
- Properly authenticated emails
- No suspicious content or links

## ⚙️ Configuration Testing

### **Environment Variables Test**
```bash
# Test different configurations
DEBUG=False python manage.py check
DEBUG=True python manage.py check

# Test database configurations
DB_ENGINE=django.db.backends.postgresql python manage.py check
DB_ENGINE=django.db.backends.sqlite3 python manage.py check
```

### **Security Settings Test**
```bash
# Test CORS settings
curl -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: X-Requested-With" \
  -X OPTIONS http://localhost:8000/api/v1/email-analysis/analyses/

# Test CSRF protection
curl -X POST http://localhost:8000/api/v1/email-analysis/analyses/ \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

## 🚀 Production Deployment Checklist

### **Pre-Deployment**
- [ ] Set `DEBUG=False` in production
- [ ] Configure production database (PostgreSQL recommended)
- [ ] Set up proper `SECRET_KEY`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Set up HTTPS/SSL certificates
- [ ] Configure web server (Nginx + Gunicorn)
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy

### **API Keys Setup**
- [ ] Obtain VirusTotal API key
- [ ] Configure WHOIS API key (optional)
- [ ] Test API connectivity
- [ ] Set up rate limiting
- [ ] Monitor API usage

### **Security Hardening**
- [ ] Enable firewall
- [ ] Configure fail2ban
- [ ] Set up intrusion detection
- [ ] Regular security updates
- [ ] Database encryption
- [ ] Backup encryption

### **Performance Optimization**
- [ ] Configure Redis for caching
- [ ] Set up Celery for background tasks
- [ ] Database query optimization
- [ ] Static file compression
- [ ] CDN configuration

## 📞 Troubleshooting

### **Common Issues**

#### **Database Issues**
```bash
# Reset database (development only)
rm db.sqlite3
python manage.py migrate

# Fix migration issues
python manage.py migrate --fake-initial
```

#### **API Key Issues**
```bash
# Test API connectivity
python -c "
import requests
response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', 
                       params={'apikey': 'YOUR_KEY', 'resource': 'google.com'})
print(response.status_code, response.json())
"
```

#### **Permission Issues**
```bash
# Fix file permissions
chmod +x manage.py
chown -R www-data:www-data /path/to/project/
```

### **Performance Issues**
```bash
# Check system resources
htop
df -h
free -h

# Monitor Django queries
DEBUG=True python manage.py runserver
# Check Django Debug Toolbar
```

## 📈 Monitoring and Maintenance

### **Log Monitoring**
```bash
# View application logs
tail -f logs/phishing_analyzer.log

# Monitor Django logs
python manage.py runserver --verbosity=2
```

### **Database Maintenance**
```bash
# Regular database cleanup
python manage.py clearsessions
python manage.py collectstatic --noinput

# Database backup
python manage.py dumpdata > backup.json
```

### **System Health Checks**
```bash
# Regular system checks
python manage.py check --deploy
python manage.py check --tag security
python test_system.py
```

## 🎯 Next Steps Recommendations

### **Immediate Actions**
1. **Get VirusTotal API Key** - Essential for full functionality
2. **Test all features** - Use the testing scenarios above
3. **Configure production environment** - Set up proper hosting
4. **Set up monitoring** - Implement log monitoring and alerts
5. **Train users** - Create user documentation and training

### **Enhancement Opportunities**
1. **Machine Learning Integration** - Add ML-based phishing detection
2. **Advanced Threat Feeds** - Integrate more threat intelligence sources
3. **Email Integration** - Direct email server integration
4. **Mobile App** - Mobile interface for analysts
5. **Advanced Analytics** - More sophisticated reporting and analytics

### **Security Enhancements**
1. **Two-Factor Authentication** - Implement 2FA for all users
2. **SIEM Integration** - Connect with security information systems
3. **Threat Hunting** - Advanced threat hunting capabilities
4. **Incident Response** - Automated incident response workflows

---

**🎉 Your Phishing Email Analysis System is ready for production deployment!**

The system provides enterprise-grade email security analysis with professional features, comprehensive API, and modern web interface. Follow this guide to ensure proper testing and deployment.

**Support**: For technical assistance, refer to the comprehensive documentation in README.md or contact the development team.