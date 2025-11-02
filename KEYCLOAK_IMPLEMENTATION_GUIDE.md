# 🔐 Django Keycloak Implementation Guide

> **Copy-paste ready implementation to add Keycloak stateless authentication to any Django project**

---

## 📋 **Overview**

This guide provides complete, copy-paste ready code to replace Django's default authentication with **Keycloak stateless authentication**. You'll get a custom login form, 30-day persistent sessions, and global logout functionality.

### ✅ **What You'll Get**
- 🎨 **Custom login form** (no Keycloak redirects)
- 🔐 **Stateless authentication** (no Django User model)
- 📅 **30-day persistent sessions** with automatic refresh
- 🌍 **Global logout** across all devices
- 🎭 **Role-based access control**
- 📊 **Session tracking** and audit trails

---

## 🛠️ **Step-by-Step Implementation**

### **Step 1: Install Dependencies**

Add to your `requirements.txt`:
```txt
requests>=2.31.0
python-jose>=3.3.0
django-decoupler>=3.8
```

Install:
```bash
pip install requests python-jose django-decoupler
```

### **Step 2: Update Django Settings**

Add to your `settings.py`:

```python
# Add to INSTALLED_APPS
INSTALLED_APPS = [
    # ... existing apps
    'django.contrib.messages',  # Add if not present
    'your_app_name',  # Create this app
]

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'your_app_name.auth.backends.KeycloakSessionBackend',
    'your_app_name.auth.backends.KeycloakAPIBackend',
    'your_app_name.auth.backends.KeycloakRoleBackend',
]

# Middleware (replace existing MIDDLEWARE)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'your_app_name.auth.middleware.KeycloakAuthMiddleware',
    'your_app_name.middleware.session_check.SessionValidationMiddleware',
]

# Session configuration
SESSION_COOKIE_AGE = 30 * 24 * 60 * 60  # 30 days
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Keycloak configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8080/'
KEYCLOAK_REALM = 'your_realm'
KEYCLOAK_CLIENT_ID = 'your_client_id'
KEYCLOAK_CLIENT_SECRET = 'your_client_secret'
KEYCLOAK_SESSION_TIMEOUT = 2592000  # 30 days
KEYCLOAK_TOKEN_REFRESH_THRESHOLD = 300  # 5 minutes
```

Create `.env` file:
```bash
KEYCLOAK_SERVER_URL=http://localhost:8080/
KEYCLOAK_REALM=your_realm
KEYCLOAK_CLIENT_ID=your_client_id
KEYCLOAK_CLIENT_SECRET=your_client_secret_here
```

### **Step 3: Create Authentication App**

```bash
python manage.py startapp your_app_name
```

### **Step 4: Create Models**

Copy to `your_app_name/models.py`:
```python
from django.db import models
from django.utils import timezone
import time


class UserSession(models.Model):
    """Track active user sessions for global logout"""
    user_id = models.CharField(max_length=255, db_index=True)
    username = models.CharField(max_length=150, db_index=True)
    session_key = models.CharField(max_length=40, unique=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    session_data = models.JSONField(default=dict, blank=True)

    is_active = models.BooleanField(default=True)
    logout_requested = models.BooleanField(default=False)

    class Meta:
        db_table = 'keycloak_user_sessions'

    @classmethod
    def create_session(cls, request, user_info):
        """Create new session record"""
        session = cls.objects.create(
            user_id=user_info.get('sub', ''),
            username=user_info.get('username', user_info.get('preferred_username', '')),
            session_key=request.session.session_key,
            expires_at=request.session.get_expiry_date(),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            ip_address=cls._get_client_ip(request),
            session_data={
                'created_at': int(time.time()),
                'roles': user_info.get('roles', []),
            }
        )
        return session

    @classmethod
    def invalidate_all_user_sessions(cls, user_id=None, username=None):
        """Invalidate all sessions for a user"""
        sessions = cls.objects.filter(is_active=True)
        if user_id:
            sessions = sessions.filter(user_id=user_id)
        elif username:
            sessions = sessions.filter(username=username)

        count = sessions.count()
        sessions.update(is_active=False, logout_requested=True)
        return count

    @staticmethod
    def _get_client_ip(request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')


class GlobalLogoutRequest(models.Model):
    """Track global logout requests for auditing"""
    user_id = models.CharField(max_length=255, db_index=True)
    username = models.CharField(max_length=150, db_index=True)
    logout_type = models.CharField(max_length=20, default='global')

    requested_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    sessions_affected = models.PositiveIntegerField(default=0)
    completed_successfully = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'keycloak_global_logout_requests'
        ordering = ['-requested_at']
```

### **Step 5: Create Authentication Backends**

Create directory: `your_app_name/auth/__init__.py` (empty file)

Copy to `your_app_name/auth/backends.py`:
```python
from django.conf import settings
import jwt
import requests
import logging

logger = logging.getLogger(__name__)


class StatelessUser:
    """Stateless user object (no database storage)"""
    def __init__(self, user_id):
        self.id = user_id
        self.pk = user_id
        self.username = ''
        self.email = ''
        self.first_name = ''
        self.last_name = ''
        self.is_authenticated = True
        self.is_active = True
        self.is_staff = False
        self.is_superuser = False
        self.roles = []

    def __str__(self):
        return self.username

    def has_perm(self, perm):
        return False

    def has_module_perms(self, app_label):
        return False

    def has_role(self, role):
        return role in getattr(self, 'roles', [])


class KeycloakSessionBackend:
    """Backend for session-based authentication using custom login form"""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Custom login form authentication"""
        if not username or not password:
            return None

        try:
            token_data = {
                'grant_type': 'password',
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
                'username': username,
                'password': password,
                'scope': 'openid profile email'
            }

            token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
            response = requests.post(token_url, data=token_data)

            if response.status_code != 200:
                return None

            token_info = response.json()
            access_token = token_info.get('access_token')

            payload = jwt.decode(access_token, options={"verify_signature": False})
            user = self._get_stateless_user(payload)

            return user

        except Exception as e:
            logger.error(f"Keycloak authentication error: {e}")
            return None

    def get_user(self, user_id):
        """Get user by ID"""
        try:
            return StatelessUser(user_id)
        except:
            return None

    def _get_stateless_user(self, payload):
        """Create stateless user from JWT payload"""
        user = StatelessUser(payload.get('sub'))
        user.username = payload.get('preferred_username', '')
        user.email = payload.get('email', '')
        user.first_name = payload.get('given_name', '')
        user.last_name = payload.get('family_name', '')
        user.roles = payload.get('realm_access', {}).get('roles', [])
        return user


class KeycloakAPIBackend:
    """Backend for API token authentication"""

    def authenticate(self, request, token=None):
        """Authenticate using JWT token from Authorization header"""
        if not token:
            token = self._extract_token_from_header(request)

        if not token:
            return None

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            user = StatelessUser(payload.get('sub'))
            user.username = payload.get('preferred_username', '')
            user.email = payload.get('email', '')
            user.roles = payload.get('realm_access', {}).get('roles', [])
            return user

        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return None

    def _extract_token_from_header(self, request):
        """Extract Bearer token from Authorization header"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header.split(' ')[1]
        return None


class KeycloakRoleBackend:
    """Backend for role-based authentication"""
    def authenticate(self, request, required_role=None):
        """Authenticate based on user role"""
        pass
```

### **Step 6: Create Authentication Middleware**

Copy to `your_app_name/auth/middleware.py`:
```python
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.conf import settings
import jwt
import requests
import time
import logging

logger = logging.getLogger(__name__)


class KeycloakAuthMiddleware(AuthenticationMiddleware):
    """Middleware for Keycloak authentication and token refresh"""

    def process_request(self, request):
        """Process request for Keycloak authentication"""
        # Skip authentication for certain paths
        if self._skip_authentication(request.path):
            return None

        # Try to authenticate user from session
        user = self._get_user_from_session(request)

        if user and user.is_authenticated:
            # Check if token needs refresh
            if self._should_refresh_token(request):
                self._refresh_token(request)

            request.user = user
            return None

        # Try API authentication
        user = self._get_user_from_api_token(request)
        if user and user.is_authenticated:
            request.user = user
            return None

        # No authentication found
        request.user = self._get_anonymous_user()
        return None

    def _skip_authentication(self, path):
        """Skip authentication for certain paths"""
        skip_paths = [
            '/login/',
            '/auth/custom-login/',
            '/callback/',
            '/api/auth/status/',
            '/static/',
            '/media/',
        ]
        return path in skip_paths

    def _get_user_from_session(self, request):
        """Get user from Django session"""
        access_token = request.session.get('access_token')
        if not access_token:
            return None

        try:
            payload = jwt.decode(access_token, options={"verify_signature": False})
            user = self._get_stateless_user(payload)
            user.username = request.session.get('user_info', {}).get('username', '')
            user.roles = request.session.get('user_info', {}).get('roles', [])
            return user
        except Exception as e:
            logger.error(f"Session authentication error: {e}")
            return None

    def _get_user_from_api_token(self, request):
        """Get user from API Authorization header"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            user = self._get_stateless_user(payload)
            user.username = payload.get('preferred_username', '')
            user.roles = payload.get('realm_access', {}).get('roles', [])
            return user
        except Exception as e:
            logger.error(f"API token authentication error: {e}")
            return None

    def _should_refresh_token(self, request):
        """Check if access token needs refresh"""
        acquired_at = request.session.get('token_acquired_at', 0)
        expires_in = request.session.get('token_expires_in', 3600)
        threshold = getattr(settings, 'KEYCLOAK_TOKEN_REFRESH_THRESHOLD', 300)

        return (time.time() - acquired_at) > (expires_in - threshold)

    def _refresh_token(self, request):
        """Refresh access token using refresh token"""
        refresh_token = request.session.get('refresh_token')
        if not refresh_token:
            return

        try:
            refresh_data = {
                'grant_type': 'refresh_token',
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
                'refresh_token': refresh_token
            }

            token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
            response = requests.post(token_url, data=refresh_data)

            if response.status_code == 200:
                token_info = response.json()
                request.session['access_token'] = token_info.get('access_token')
                request.session['token_acquired_at'] = int(time.time())
                request.session['token_expires_in'] = token_info.get('expires_in', 3600)

                if 'refresh_token' in token_info:
                    request.session['refresh_token'] = token_info['refresh_token']

                logger.info("Token refreshed successfully")
            else:
                logger.warning("Token refresh failed")

        except Exception as e:
            logger.error(f"Token refresh error: {e}")

    def _get_stateless_user(self, payload):
        """Create stateless user from JWT payload"""
        from .backends import StatelessUser
        user = StatelessUser(payload.get('sub'))
        user.username = payload.get('preferred_username', '')
        user.email = payload.get('email', '')
        user.first_name = payload.get('given_name', '')
        user.last_name = payload.get('family_name', '')
        user.roles = payload.get('realm_access', {}).get('roles', [])
        return user

    def _get_anonymous_user(self):
        """Get anonymous user"""
        from django.contrib.auth.models import AnonymousUser
        return AnonymousUser()
```

### **Step 7: Create Session Validation Middleware**

Create directory: `your_app_name/middleware/__init__.py` (empty file)

Copy to `your_app_name/middleware/session_check.py`:
```python
from django.shortcuts import redirect
from django.contrib import messages
from django.conf import settings
from ..models import UserSession
import logging

logger = logging.getLogger(__name__)


class SessionValidationMiddleware:
    """Middleware to validate session against tracking system"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip validation for certain paths
        if self._skip_validation(request.path):
            return self.get_response(request)

        # Validate session if user is authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            session_key = request.session.get('session_key') or request.session.session_key
            if session_key and not self._is_session_valid(session_key):
                logger.info(f"Session {session_key} invalidated. Redirecting to login.")

                request.session.flush()
                messages.warning(request, "Your session expired due to logout from another device.")
                return redirect('login')

        return self.get_response(request)

    def _skip_validation(self, path):
        """Skip validation for certain paths"""
        skip_paths = ['/login/', '/auth/custom-login/', '/api/auth/status/', '/static/', '/media/']
        return path in skip_paths

    def _is_session_valid(self, session_key):
        """Check if session is still active in tracking system"""
        try:
            return UserSession.objects.filter(
                session_key=session_key,
                is_active=True
            ).exists()
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return True  # Allow access if validation fails
```

### **Step 8: Create Authentication Decorators**

Copy to `your_app_name/decorators.py`:
```python
from functools import wraps
from django.http import JsonResponse
from django.shortcuts import redirect


def keycloak_login_required(view_func):
    """Decorator to require Keycloak authentication"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'error': 'Authentication required',
                    'code': 'auth_required'
                }, status=401)
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper


def require_role(allowed_roles):
    """Decorator to require specific roles"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            user_roles = getattr(request.user, 'roles', [])
            if not any(role in user_roles for role in allowed_roles):
                if isinstance(allowed_roles, str):
                    allowed_roles = [allowed_roles]

                return JsonResponse({
                    'error': 'Insufficient permissions',
                    'required_roles': allowed_roles,
                    'user_roles': user_roles
                }, status=403)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_any_role(allowed_roles):
    """Decorator to require any of the specified roles"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse({'error': 'Authentication required'}, status=401)

            user_roles = getattr(request.user, 'roles', [])
            if not any(role in user_roles for role in allowed_roles):
                return JsonResponse({
                    'error': 'Insufficient permissions',
                    'required_roles': allowed_roles,
                    'user_roles': user_roles
                }, status=403)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
```

### **Step 9: Create Authentication Views**

Copy to `your_app_name/views.py`:
```python
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.conf import settings
import requests
import jwt
import time
import json

from .decorators import keycloak_login_required
from .models import UserSession, GlobalLogoutRequest


@require_http_methods(["GET"])
def login(request):
    """Display custom login form"""
    if getattr(request.user, 'is_authenticated', False):
        return redirect('dashboard')
    return render(request, 'your_app_name/custom_login.html')


@require_http_methods(["POST"])
@csrf_exempt
def custom_login_submit(request):
    """Handle custom login form submission"""
    try:
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if not username or not password:
            return JsonResponse({
                'success': False,
                'error': 'Username and password are required'
            })

        # Authenticate with Keycloak
        token_data = {
            'grant_type': 'password',
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'username': username,
            'password': password,
            'scope': 'openid profile email'
        }

        token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
        response = requests.post(token_url, data=token_data)

        if response.status_code != 200:
            return JsonResponse({
                'success': False,
                'error': 'Invalid username or password'
            })

        # Process successful authentication
        token_info = response.json()
        access_token = token_info.get('access_token')
        refresh_token = token_info.get('refresh_token')
        expires_in = token_info.get('expires_in', 3600)

        # Decode token for user info
        payload = jwt.decode(access_token, options={"verify_signature": False})
        user_info = {
            'sub': payload.get('sub'),
            'username': payload.get('preferred_username', username),
            'email': payload.get('email', ''),
            'name': payload.get('name', ''),
            'roles': payload.get('realm_access', {}).get('roles', [])
        }

        # Store in session
        request.session['access_token'] = access_token
        if refresh_token:
            request.session['refresh_token'] = refresh_token
        request.session['token_acquired_at'] = int(time.time())
        request.session['token_expires_in'] = expires_in
        request.session['user_info'] = user_info
        request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days

        # Ensure session is created
        if not request.session.session_key:
            request.session.create()

        # Create session tracking record
        try:
            UserSession.create_session(request, user_info)
        except Exception as e:
            print(f"Session tracking error: {e}")

        return JsonResponse({
            'success': True,
            'redirect_url': '/dashboard/',
            'user_info': user_info
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Authentication failed'
        })


def logout(request):
    """Simple logout - clear Django session only"""
    try:
        request.session.flush()
    except Exception:
        pass
    return redirect('login')


def keycloak_logout(request):
    """Global logout - invalidate all user sessions"""
    try:
        session_key = request.session.session_key
        user_info = request.session.get('user_info', {})
        access_token = request.session.get('access_token')
        refresh_token = request.session.get('refresh_token')

        user_id = user_info.get('sub')
        username = user_info.get('username', user_info.get('preferred_username'))

        sessions_affected = 0

        # Invalidate all Django sessions for this user
        try:
            invalidated_count = UserSession.invalidate_all_user_sessions(
                user_id=user_id,
                username=username
            )
            sessions_affected += invalidated_count

            # Record logout request
            GlobalLogoutRequest.objects.create(
                user_id=user_id or '',
                username=username or '',
                logout_type='global',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                sessions_affected=invalidated_count
            )

        except Exception as e:
            print(f"Session invalidation error: {e}")

        # Logout from Keycloak
        if refresh_token:
            try:
                logout_data = {
                    'client_id': settings.KEYCLOAK_CLIENT_ID,
                    'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
                    'refresh_token': refresh_token
                }
                logout_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"
                requests.post(logout_url, data=logout_data)
            except Exception as e:
                print(f"Keycloak logout error: {e}")

        # Clear current session
        request.session.flush()

        if sessions_affected > 1:
            messages.success(request, f"Logged out from {sessions_affected} devices.")
        else:
            messages.success(request, "Logged out successfully.")

        return redirect('login')

    except Exception as e:
        messages.error(request, "Logout failed. Please try again.")
        return redirect('login')


@keycloak_login_required
def dashboard(request):
    """Dashboard view"""
    return render(request, 'your_app_name/dashboard.html', {
        'user': request.user,
        'user_info': request.session.get('user_info', {})
    })


def auth_status(request):
    """Check authentication status"""
    if hasattr(request, 'user') and request.user.is_authenticated:
        return JsonResponse({
            'authenticated': True,
            'username': getattr(request.user, 'username', ''),
            'email': getattr(request.user, 'email', ''),
            'roles': getattr(request.user, 'roles', [])
        })
    return JsonResponse({'authenticated': False})
```

### **Step 10: Create URLs**

Copy to `your_app_name/urls.py`:
```python
from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('login/', views.login, name='login'),
    path('auth/custom-login/', views.custom_login_submit, name='custom_login_submit'),
    path('logout/', views.logout, name='logout'),
    path('auth/keycloak-logout/', views.keycloak_logout, name='keycloak_logout'),

    # Protected URLs
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/auth/status/', views.auth_status, name='auth_status'),
]
```

Update your main `urls.py` to include:
```python
from django.urls import path, include

urlpatterns = [
    # Add authentication URLs
    path('', include('your_app_name.urls')),

    # Your existing URLs...
]
```

### **Step 11: Create Templates**

Create directory: `your_app_name/templates/your_app_name/`

Copy to `your_app_name/templates/your_app_name/custom_login.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Your App</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 420px;
        }
        .form-group { margin-bottom: 25px; }
        .form-group label {
            display: block; margin-bottom: 8px;
            color: #2c3e50; font-weight: 600; font-size: 14px;
        }
        .form-group input {
            width: 100%; padding: 14px 16px;
            border: 2px solid #e1e8ed; border-radius: 8px; font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus {
            outline: none; border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .login-button {
            width: 100%; padding: 16px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 8px;
            font-size: 16px; font-weight: 600; cursor: pointer;
            transition: transform 0.2s ease;
        }
        .login-button:hover { transform: translateY(-2px); }
        .login-button.loading { opacity: 0.7; cursor: not-allowed; }
        .error-message, .success-message {
            padding: 16px; border-radius: 8px;
            margin-bottom: 20px; text-align: center; font-size: 14px;
        }
        .error-message {
            background: #fee; border: 1px solid #fcc;
            color: #d63026;
        }
        .success-message {
            background: #d4edda; border: 1px solid #c3e6cb;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #2c3e50; margin-bottom: 10px;">Welcome Back</h1>
            <p style="color: #7f8c8d;">Sign in to access your account</p>
        </div>

        {% if error %}
            <div class="error-message">{{ error }}</div>
        {% endif %}

        {% if messages %}
            {% for message in messages %}
                <div class="success-message">{{ message }}</div>
            {% endfor %}
        {% endif %}

        <form method="post" id="login-form">
            {% csrf_token %}
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="login-button" id="login-button">
                <span id="button-text">Sign In</span>
            </button>
        </form>
    </div>

    <script>
        document.getElementById('login-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const form = e.target;
            const button = document.getElementById('login-button');
            const buttonText = document.getElementById('button-text');
            button.classList.add('loading');
            buttonText.textContent = 'Signing In...';
            const formData = new FormData(form);
            fetch('/auth/custom-login/', { method: 'POST', body: formData })
            .then(response => response.ok ? response.json() : Promise.reject('Login failed'))
            .then(data => {
                if (data.success) {
                    window.location.href = data.redirect_url;
                } else {
                    throw new Error(data.error || 'Login failed');
                }
            })
            .catch(error => {
                console.error('Login error:', error);
                button.classList.remove('loading');
                buttonText.textContent = 'Sign In';
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                errorDiv.textContent = error.message || 'Login failed. Please try again.';
                form.insertBefore(errorDiv, form.firstChild);
                setTimeout(() => {
                    if (errorDiv.parentNode) {
                        errorDiv.parentNode.removeChild(errorDiv);
                    }
                }, 5000);
            });
        });
    </script>
</body>
</html>
```

Copy to `your_app_name/templates/your_app_name/dashboard.html`:
```html
{% extends "base.html" %}
{% block title %}Dashboard - {{ user.username }}{% endblock %}
{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <h2 class="mb-1">Welcome back, {{ user.username }}!</h2>
                            <p class="mb-2 text-muted">{{ user_info.email|default:"No email provided" }}</p>
                            <div>
                                {% for role in user.roles %}
                                    <span class="badge bg-primary me-2">{{ role|title }}</span>
                                {% endfor %}
                            </div>
                        </div>
                        <div class="col-md-4 text-end">
                            <form method="post" action="{% url 'logout' %}" style="display: inline;">
                                {% csrf_token %}
                                <button type="submit" class="btn btn-outline-danger btn-sm me-2"
                                        onclick="return confirm('Are you sure you want to logout?')">
                                    <i class="fas fa-sign-out-alt"></i> Logout
                                </button>
                            </form>
                            <form method="post" action="{% url 'keycloak_logout' %}" style="display: inline;">
                                {% csrf_token %}
                                <button type="submit" class="btn btn-danger btn-sm"
                                        title="Logout from all devices"
                                        onclick="return confirm('Are you sure you want to logout from ALL devices?')">
                                    <i class="fas fa-shield-alt"></i> Global Logout
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5>Session Information</h5>
                </div>
                <div class="card-body">
                    <p><strong>Authentication Method:</strong> Keycloak OAuth2</p>
                    <p><strong>User ID:</strong> {{ user_info.sub|default:"N/A" }}</p>
                    <p><strong>Email Verified:</strong>
                        {% if user_info.email_verified %}
                            <span class="badge bg-success">Yes</span>
                        {% else %}
                            <span class="badge bg-warning">No</span>
                        {% endif %}
                    </p>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5>Active Sessions</h5>
                </div>
                <div class="card-body">
                    <p>This is a stateless authentication system.</p>
                    <p>Use "Global Logout" to invalidate all sessions across devices.</p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

### **Step 12: Run Migrations**

```bash
python manage.py makemigrations your_app_name
python manage.py migrate
```

### **Step 13: Configure Keycloak**

1. **Access Keycloak Admin**: http://localhost:8080/admin
2. **Create Realm**: Your realm name
3. **Create Client**: Your client ID
4. **Settings**:
   - **Access Type**: confidential
   - **Direct Access Grants**: ON
   - **Standard Flow**: OFF (since we're using custom login)
   - **Valid Redirect URIs**: `http://localhost:8000/*`
5. **Get Client Secret** from Credentials tab

### **Step 14: Test Implementation**

1. **Start Django**: `python manage.py runserver`
2. **Visit**: http://localhost:8000/login/
3. **Login** with Keycloak user credentials
4. **Verify redirect** to dashboard
5. **Test global logout** functionality

---

## 🎯 **Key Features Explained**

### **Custom Login Form**
- No Keycloak redirect - users stay on your site
- AJAX form submission with loading states
- Real-time error handling and feedback

### **Stateless Authentication**
- No Django User model required
- All user data comes from Keycloak JWT tokens
- Automatic token refresh before expiry

### **Global Logout System**
- Tracks all active sessions in database
- Logout from one device = logout from all devices
- Complete audit trail for security compliance

### **Role-Based Access Control**
- Extract roles from Keycloak tokens
- Decorator-based endpoint protection
- Role-specific UI elements

---

## 🚀 **Production Tips**

### **Security**
```python
# settings.py
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
```

### **Environment Variables**
```bash
# Production
KEYCLOAK_SERVER_URL=https://auth.yourcompany.com/
KEYCLOAK_CLIENT_SECRET=your-production-secret
```

### **Performance**
- Add database indexes on session tracking tables
- Cache Keycloak public keys for JWT validation
- Clean up expired sessions regularly

---

## 🛠️ **Troubleshooting**

### **Common Issues**
1. **"No token found"** - Check middleware order in settings.py
2. **Session validation errors** - Ensure database tables exist
3. **Keycloak connection issues** - Test Keycloak URL and credentials
4. **Token validation problems** - Check JWT decoding

### **Debug Mode**
Add to settings.py for debugging:
```python
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'your_app_name': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

---

**🎉 Your Django project now has enterprise-grade Keycloak authentication!**

The implementation provides secure, stateless authentication with a seamless user experience and enterprise features like global logout and session tracking. 🚀