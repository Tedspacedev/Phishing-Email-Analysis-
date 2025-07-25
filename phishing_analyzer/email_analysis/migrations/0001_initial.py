# Generated by Django 5.2.4 on 2025-07-24 11:40

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_subject', models.CharField(blank=True, max_length=500)),
                ('sender_email', models.EmailField(max_length=254)),
                ('recipient_email', models.EmailField(max_length=254)),
                ('email_body', models.TextField()),
                ('raw_email', models.TextField(help_text='Raw email content')),
                ('risk_level', models.CharField(choices=[('LOW', 'Low Risk'), ('MEDIUM', 'Medium Risk'), ('HIGH', 'High Risk'), ('CRITICAL', 'Critical Risk')], default='LOW', max_length=10)),
                ('phishing_score', models.FloatField(default=0.0, help_text='Score from 0-100')),
                ('is_phishing', models.BooleanField(default=False)),
                ('status', models.CharField(choices=[('PENDING', 'Pending Analysis'), ('PROCESSING', 'Processing'), ('COMPLETED', 'Analysis Completed'), ('FAILED', 'Analysis Failed')], default='PENDING', max_length=15)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('analysis_duration', models.FloatField(blank=True, help_text='Analysis time in seconds', null=True)),
                ('threat_indicators', models.JSONField(default=list, help_text='List of detected threat indicators')),
                ('analysis_summary', models.TextField(blank=True)),
                ('recommendations', models.TextField(blank=True)),
                ('analyzed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Email Analysis',
                'verbose_name_plural': 'Email Analyses',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='AttachmentAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filename', models.CharField(max_length=255)),
                ('file_size', models.BigIntegerField(help_text='File size in bytes')),
                ('file_type', models.CharField(max_length=100)),
                ('mime_type', models.CharField(max_length=100)),
                ('md5_hash', models.CharField(blank=True, max_length=32)),
                ('sha1_hash', models.CharField(blank=True, max_length=40)),
                ('sha256_hash', models.CharField(blank=True, max_length=64)),
                ('threat_level', models.CharField(choices=[('SAFE', 'Safe'), ('SUSPICIOUS', 'Suspicious'), ('MALICIOUS', 'Malicious'), ('UNKNOWN', 'Unknown')], default='UNKNOWN', max_length=15)),
                ('is_executable', models.BooleanField(default=False)),
                ('has_macros', models.BooleanField(default=False)),
                ('virustotal_score', models.JSONField(blank=True, null=True)),
                ('virustotal_detected', models.BooleanField(default=False)),
                ('detection_engines', models.JSONField(default=list, help_text='List of engines that detected threats')),
                ('embedded_urls', models.JSONField(default=list, help_text='URLs found in the attachment')),
                ('suspicious_strings', models.JSONField(default=list, help_text='Suspicious strings found in the file')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email_analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachment_analyses', to='email_analysis.emailanalysis')),
            ],
            options={
                'verbose_name': 'Attachment Analysis',
                'verbose_name_plural': 'Attachment Analyses',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='EmailHeader',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('raw_headers', models.TextField()),
                ('message_id', models.CharField(blank=True, max_length=255)),
                ('return_path', models.EmailField(blank=True, max_length=254)),
                ('received_headers', models.JSONField(default=list, help_text='List of Received headers')),
                ('spf_result', models.CharField(blank=True, max_length=50)),
                ('dkim_result', models.CharField(blank=True, max_length=50)),
                ('dmarc_result', models.CharField(blank=True, max_length=50)),
                ('originating_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('mail_servers', models.JSONField(default=list, help_text='List of mail servers in delivery path')),
                ('header_inconsistencies', models.JSONField(default=list)),
                ('spoofing_indicators', models.JSONField(default=list)),
                ('sender_country', models.CharField(blank=True, max_length=100)),
                ('sender_region', models.CharField(blank=True, max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email_analysis', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='header_analysis', to='email_analysis.emailanalysis')),
            ],
            options={
                'verbose_name': 'Email Header Analysis',
                'verbose_name_plural': 'Email Header Analyses',
            },
        ),
        migrations.CreateModel(
            name='PhishingTechnique',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('technique_type', models.CharField(choices=[('SPOOFING', 'Email Spoofing'), ('SOCIAL_ENGINEERING', 'Social Engineering'), ('MALICIOUS_LINKS', 'Malicious Links'), ('MALWARE', 'Malware Distribution'), ('CREDENTIAL_HARVESTING', 'Credential Harvesting'), ('BUSINESS_EMAIL_COMPROMISE', 'Business Email Compromise'), ('TYPOSQUATTING', 'Typosquatting'), ('HOMOGRAPH_ATTACK', 'Homograph Attack')], max_length=30)),
                ('technique_name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('confidence_score', models.FloatField(help_text='Confidence score from 0-100')),
                ('evidence', models.JSONField(default=dict, help_text='Supporting evidence for the detection')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email_analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='phishing_techniques', to='email_analysis.emailanalysis')),
            ],
            options={
                'verbose_name': 'Phishing Technique',
                'verbose_name_plural': 'Phishing Techniques',
                'ordering': ['-confidence_score'],
            },
        ),
        migrations.CreateModel(
            name='URLAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('original_url', models.URLField(max_length=2000)),
                ('final_url', models.URLField(blank=True, help_text='URL after following redirects', max_length=2000)),
                ('domain', models.CharField(max_length=255)),
                ('threat_level', models.CharField(choices=[('SAFE', 'Safe'), ('SUSPICIOUS', 'Suspicious'), ('MALICIOUS', 'Malicious'), ('UNKNOWN', 'Unknown')], default='UNKNOWN', max_length=15)),
                ('is_shortened', models.BooleanField(default=False)),
                ('redirect_count', models.IntegerField(default=0)),
                ('virustotal_score', models.JSONField(blank=True, null=True)),
                ('virustotal_detected', models.BooleanField(default=False)),
                ('domain_age', models.IntegerField(blank=True, help_text='Domain age in days', null=True)),
                ('domain_registrar', models.CharField(blank=True, max_length=255)),
                ('is_typosquatting', models.BooleanField(default=False)),
                ('http_status_code', models.IntegerField(blank=True, null=True)),
                ('response_time', models.FloatField(blank=True, help_text='Response time in seconds', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('email_analysis', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='url_analyses', to='email_analysis.emailanalysis')),
            ],
            options={
                'verbose_name': 'URL Analysis',
                'verbose_name_plural': 'URL Analyses',
                'ordering': ['-created_at'],
            },
        ),
    ]
