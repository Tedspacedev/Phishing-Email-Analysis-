import os
import dj_database_url

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = ['phishing-email.onrender.com', 'localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
## Commented out to avoid staticfiles.W004 warning. Uncomment if you add a static directory.
# STATICFILES_DIRS = [
#     BASE_DIR / 'static',
# ]

# WhiteNoise static files storage
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}
# To use PostgreSQL on Render, uncomment below and set DATABASE_URL env var
# import dj_database_url
# DATABASES = {
#     'default': dj_database_url.config(default=os.environ.get('DATABASE_URL'))
# } 