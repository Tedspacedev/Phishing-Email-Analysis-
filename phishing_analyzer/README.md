# Phishing Email Analysis and Basic Attribution System

## Overview

The Phishing Email Analysis and Basic Attribution System is a comprehensive Django-based web application designed for **Elite Luxe Imports** to analyze suspicious emails, detect phishing attempts, and provide threat intelligence capabilities. The system implements advanced email parsing, threat detection algorithms, and attribution analysis to help security teams identify and respond to email-based threats.

## Features

### Core Functionality

#### 🔍 Email Analysis Engine
- **Comprehensive Email Parsing**: Extract headers, URLs, attachments, and metadata
- **Phishing Detection**: Advanced algorithms to identify suspicious patterns
- **Risk Assessment**: Automated scoring system (0-100%) with risk levels (LOW, MEDIUM, HIGH)
- **Multi-format Support**: Raw email, EML files, and manual input

#### 🛡️ Threat Intelligence
- **VirusTotal Integration**: Automated URL and file hash checking
- **WHOIS Lookups**: Domain registration and ownership analysis
- **DNS Analysis**: MX, A, and TXT record examination
- **Threat Feed Management**: Support for external threat intelligence feeds
- **IOC Export**: Multiple formats (JSON, CSV, STIX 2.0)

#### 👥 User Management
- **Role-Based Access Control**: Admin, Security Analyst, IT Staff, General User, Viewer
- **Activity Logging**: Comprehensive audit trail of all system activities
- **Session Management**: Active session tracking with security monitoring
- **API Key Management**: Secure programmatic access

#### 📊 Reporting & Analytics
- **Interactive Dashboard**: Real-time statistics and charts
- **Detailed Analysis Reports**: Comprehensive threat analysis results
- **Export Capabilities**: PDF, CSV, and JSON report formats
- **Trend Analysis**: Historical data visualization

## Technical Architecture

### Technology Stack
- **Backend**: Django 5.2.4 with Django REST Framework
- **Database**: SQLite (development) / PostgreSQL (production)
- **Frontend**: Bootstrap 5.3.0 with Chart.js
- **APIs**: VirusTotal, WHOIS, DNS resolution
- **Security**: Token-based authentication, CORS support

### System Components

#### Email Analysis Module (`email_analysis/`)
- **Models**: EmailAnalysis, EmailHeader, URLAnalysis, AttachmentAnalysis, PhishingTechnique
- **Services**: EmailParser, PhishingAnalyzer, URLThreatAnalyzer, AttachmentThreatAnalyzer
- **APIs**: RESTful endpoints for analysis management

#### Threat Intelligence Module (`threat_intelligence/`)
- **Models**: ThreatIndicator, IPReputation, DomainReputation, ThreatFeed, ThreatAttribution
- **Services**: VirusTotalService, WHOISService, DNSService, ThreatIntelligenceService
- **APIs**: Threat data management and analysis endpoints

#### User Management Module (`user_management/`)
- **Models**: UserProfile, ActivityLog, UserSession, APIKey
- **Services**: Authentication, authorization, and user activity tracking
- **APIs**: User management and authentication endpoints

## Installation & Setup

### Prerequisites
- Python 3.8+
- Virtual environment (recommended)
- Git

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd phishing_analyzer
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv phishing_analyzer_env
   source phishing_analyzer_env/bin/activate  # Linux/Mac
   # or
   phishing_analyzer_env\Scripts\activate  # Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Database Setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. **Create Required Directories**
   ```bash
   mkdir -p logs static media
   ```

7. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

8. **Access the Application**
   - Web Interface: http://localhost:8000/
   - Admin Panel: http://localhost:8000/admin/
   - API Documentation: http://localhost:8000/api/

### Environment Variables

Create a `.env` file with the following configuration:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration
DB_ENGINE=django.db.backends.sqlite3
DB_NAME=db.sqlite3
DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=

# CORS Settings
CORS_ALLOW_ALL_ORIGINS=True

# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
WHOIS_API_KEY=your_whois_api_key_here

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

## Usage Guide

### Web Interface

#### Dashboard
- Access comprehensive system statistics
- View recent email analyses
- Interactive charts and trend analysis
- Quick email analysis form

#### Email Analysis
1. Navigate to "Email Analysis" section
2. Click "Analyze Email" button
3. Fill in email details (subject, sender, recipient, body)
4. Submit for analysis
5. View detailed results with risk assessment

#### User Management
- Profile management
- Password changes
- Activity log viewing
- Session management

### API Usage

#### Authentication
```bash
# Login to get token
curl -X POST http://localhost:8000/api/v1/users/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use token in subsequent requests
curl -H "Authorization: Token your-token-here" \
  http://localhost:8000/api/v1/email-analysis/analyses/
```

#### Email Analysis API
```bash
# Create new analysis
curl -X POST http://localhost:8000/api/v1/email-analysis/analyses/ \
  -H "Authorization: Token your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "email_subject": "Urgent: Account Verification Required",
    "sender_email": "security@suspicious-bank.com",
    "recipient_email": "user@eliteluxe.com",
    "email_body": "Click here to verify your account..."
  }'

# Get analysis results
curl -H "Authorization: Token your-token-here" \
  http://localhost:8000/api/v1/email-analysis/analyses/1/
```

#### Threat Intelligence API
```bash
# Analyze domain
curl -X POST http://localhost:8000/api/v1/threat-intelligence/analysis/analyze/ \
  -H "Authorization: Token your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_type": "DOMAIN",
    "target": "suspicious-domain.com"
  }'

# Get threat indicators
curl -H "Authorization: Token your-token-here" \
  http://localhost:8000/api/v1/threat-intelligence/indicators/
```

## User Roles & Permissions

### Administrator
- Full system access
- User management
- System configuration
- All analysis and reporting features

### Security Analyst
- Email analysis and investigation
- Threat intelligence access
- Report generation
- Advanced analysis features

### IT Staff
- Basic email analysis
- Limited threat intelligence
- Standard reporting
- User profile management

### General User
- Submit emails for analysis
- View own analysis results
- Basic dashboard access
- Profile management

### Viewer
- Read-only access to analyses
- Dashboard viewing
- Basic statistics
- No modification capabilities

## Security Features

### Authentication & Authorization
- Token-based API authentication
- Role-based access control (RBAC)
- Session management with timeout
- Failed login attempt tracking
- Account lockout protection

### Data Protection
- CSRF protection
- XSS prevention
- SQL injection protection
- Secure headers implementation
- Input validation and sanitization

### Audit & Monitoring
- Comprehensive activity logging
- User session tracking
- Suspicious activity detection
- API access monitoring
- Security event alerting

## Analysis Algorithms

### Phishing Detection Techniques

#### Sender Reputation Analysis
- Domain age verification
- SPF/DKIM/DMARC validation
- Blacklist checking
- Geolocation analysis

#### Content Analysis
- Suspicious keyword detection
- URL analysis and validation
- Attachment scanning
- Social engineering pattern recognition

#### Technical Indicators
- Header inconsistencies
- Spoofing detection
- Typosquatting identification
- DGA (Domain Generation Algorithm) detection

### Risk Scoring System
- **0-30%**: LOW risk - Legitimate email with minimal suspicious indicators
- **31-70%**: MEDIUM risk - Some suspicious patterns detected, requires review
- **71-100%**: HIGH risk - Multiple threat indicators, likely phishing attempt

## Deployment

### Production Deployment

#### Database Configuration
```python
# For PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'phishing_analyzer',
        'USER': 'dbuser',
        'PASSWORD': 'dbpassword',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

#### Web Server (Nginx + Gunicorn)
```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn phishing_analyzer.wsgi:application --bind 0.0.0.0:8000

# Nginx configuration
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /static/ {
        alias /path/to/static/files/;
    }
}
```

#### Security Considerations
- Use HTTPS in production
- Configure proper firewall rules
- Regular security updates
- Database encryption
- Backup strategies

## API Documentation

### Email Analysis Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/email-analysis/analyses/` | GET, POST | List/Create analyses |
| `/api/v1/email-analysis/analyses/{id}/` | GET, PUT, DELETE | Manage specific analysis |
| `/api/v1/email-analysis/analyses/{id}/reanalyze/` | POST | Re-run analysis |
| `/api/v1/email-analysis/analyses/statistics/` | GET | Get analysis statistics |
| `/api/v1/email-analysis/analyses/bulk_analyze/` | POST | Bulk email analysis |

### Threat Intelligence Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/threat-intelligence/indicators/` | GET, POST | Manage threat indicators |
| `/api/v1/threat-intelligence/feeds/` | GET, POST | Manage threat feeds |
| `/api/v1/threat-intelligence/analysis/analyze/` | POST | Analyze domains/IPs |
| `/api/v1/threat-intelligence/indicators/export_iocs/` | POST | Export IOCs |

### User Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/users/auth/login/` | POST | User authentication |
| `/api/v1/users/auth/logout/` | POST | User logout |
| `/api/v1/users/profiles/me/` | GET | Get current user profile |
| `/api/v1/users/activity-logs/` | GET | Get activity logs |

## Troubleshooting

### Common Issues

#### Database Migration Errors
```bash
# Reset migrations (development only)
python manage.py migrate --fake-initial
python manage.py migrate
```

#### Permission Errors
```bash
# Fix file permissions
chmod +x manage.py
chown -R www-data:www-data /path/to/project/
```

#### API Key Issues
- Verify VirusTotal API key is valid
- Check API rate limits
- Ensure network connectivity

### Logging

System logs are stored in `logs/phishing_analyzer.log`. Log levels:
- ERROR: System errors and exceptions
- WARNING: Potential issues and security events
- INFO: General system operations
- DEBUG: Detailed debugging information

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Follow coding standards
4. Write tests for new features
5. Submit pull request

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings to functions and classes
- Write comprehensive tests

## Support

### Documentation
- API documentation available at `/api/docs/`
- Admin interface at `/admin/`
- User guides in the web interface

### Contact
- **Technical Support**: it-support@eliteluxe.com
- **Security Issues**: security@eliteluxe.com
- **General Inquiries**: info@eliteluxe.com

## License

This software is proprietary to Elite Luxe Imports. All rights reserved.

## Version History

### v1.0.0 (Current)
- Initial release
- Core email analysis functionality
- Threat intelligence integration
- User management system
- Web interface and API
- Comprehensive reporting

---

**Elite Luxe Imports - Cybersecurity Division**  
*Protecting your business from email-based threats*