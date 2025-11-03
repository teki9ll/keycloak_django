"""
Django Settings for Keycloak Integration

This configuration file contains all settings for the stateless Keycloak integration.
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path('/root/projects/keycloak_demo')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-keycloak-demo-key-change-in-production'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']  # Update for production

# Application definition - No database apps for pure stateless implementation
INSTALLED_APPS = [
    # Note: NO django.contrib.auth, django.contrib.contenttypes, django.contrib.sessions,
    #       django.contrib.messages, django.contrib.admin, or django.contrib.staticfiles
    # Using CDN for static files, pure stateless implementation
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # CSRF protection for forms
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Custom Keycloak middleware for TRULY stateless authentication (NO DATABASE)
    'middleware.stateless_keycloak_middleware.StatelessKeycloakMiddleware',
]

ROOT_URLCONF = 'urls_simple'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
            ],
        },
    },
]

# No Database - Pure Stateless Implementation
# DATABASES not configured - we use signed cookies for session data
DATABASES = {}

# No sessions - Using signed cookies for token storage (TRULY stateless)
# SESSION settings not used - no database dependency

# Cookie security settings for token storage
TOKEN_COOKIE_SECURE = False  # Set to True in production with HTTPS
TOKEN_COOKIE_HTTPONLY = True
TOKEN_COOKIE_SAMESITE = 'Lax'
TOKEN_COOKIE_MAX_AGE = 86400  # 24 hours

# Static files (CSS, JavaScript, Images) - Using CDN, so static files not critical
STATIC_URL = '/static/'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Keycloak Configuration
KEYCLOAK_CONFIG = {
    "SERVER_URL": "http://172.28.136.214:8080/",  # Update with your Keycloak server
    "REALM": "teki_9",  # Update with your realm
    "CLIENT_ID": "easytask",  # Update with your client ID
    "CLIENT_SECRET": "",  # Add if client requires secret
}

# Authentication and Security
LOGIN_URL = '/login/'
LOGOUT_URL = '/logout/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# Public URLs that don't require authentication
PUBLIC_URLS = [
    '/login/',
    '/logout/',
    '/static/',
    '/media/',
]

# CSRF Configuration
CSRF_TRUSTED_ORIGINS = [
    "http://172.28.136.214:8010",
    "http://localhost:8010",
    "http://172.28.136.214:8080",
]

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'django.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'keycloak_manager': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'middleware': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'views': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# Cache Configuration (for Keycloak public keys)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'keycloak-django-cache',
    }
}

# Security Settings (for production)
if not DEBUG:
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    X_FRAME_OPTIONS = 'DENY'

# Custom User Settings
AUTH_USER_MODEL = None  # Not using Django's built-in User model

# REST Framework (optional, for API endpoints)
INSTALLED_APPS += [
    'rest_framework',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # No authentication classes - using custom middleware
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

# CORS Settings (if needed for frontend integration)
CORS_ALLOWED_ORIGINS = [
    "http://172.28.136.214:8010",
    "http://localhost:8010",
    "http://172.28.136.214:8080",
]

CORS_ALLOW_CREDENTIALS = True

# Email Configuration (optional)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Additional Settings
APPEND_SLASH = True
DEFAULT_CHARSET = 'utf-8'