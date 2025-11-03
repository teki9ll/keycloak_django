"""
Simplified URL Configuration for Keycloak Django Integration
"""

from django.urls import path, reverse
from django.shortcuts import redirect, render
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

from keycloak_manager import keycloak_manager
from middleware.stateless_keycloak_middleware import (
    store_tokens_in_cookies,
    clear_tokens_from_cookies,
    get_tokens_from_cookies
)
from auth.stateless_user import StatelessUser


# Simple login view
def login_view(request):
    """Simple login view"""
    if request.method == 'GET':
        return render(request, 'auth/login.html')

    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            return render(request, 'auth/login.html', {
                'error': 'Username and password are required'
            })

        # Authenticate with Keycloak
        auth_result = keycloak_manager.authenticate_user(username, password)

        if not auth_result:
            return render(request, 'auth/login.html', {
                'error': 'Invalid username or password'
            })

        # Store tokens in cookies (TRULY stateless - no database)
        tokens = auth_result.get('tokens', {})
        user_info = auth_result.get('user_info', {})

        # Create user object
        user = StatelessUser(user_info)
        request.user = user

        # Create response and set cookies
        response = redirect(reverse('dashboard'))

        # Handle demo tokens differently
        access_token = tokens.get('access_token', '')
        if user_info and user_info.get('sub', '').startswith('demo-'):
            # Demo mode: Store tokens directly in cookies
            response.set_cookie(
                'demo_access_token',
                access_token,
                max_age=86400,  # 1 day
                httponly=True,
                samesite='Lax',
                secure=False
            )

            refresh_token = tokens.get('refresh_token')
            if refresh_token:
                response.set_cookie(
                    'demo_refresh_token',
                    refresh_token,
                    max_age=86400 * 7,  # 7 days
                    httponly=True,
                    samesite='Lax',
                    secure=False
                )
        else:
            # Keycloak mode: Use the standard signed cookie approach
            store_tokens_in_cookies(response, tokens)

        return response

  

def logout_view(request):
    """Simple logout view - TRULY stateless"""
    # Create response and clear all possible token cookies
    response = redirect(reverse('login'))

    # Clear demo tokens
    response.delete_cookie('demo_access_token')
    response.delete_cookie('demo_refresh_token')

    # Clear standard Keycloak tokens
    clear_tokens_from_cookies(response)

    return response


def dashboard_view(request):
    """Simple dashboard view"""
    logger.debug(f"Dashboard view: user exists={hasattr(request, 'user')}, authenticated={getattr(request.user, 'is_authenticated', False) if hasattr(request, 'user') else False}")

    if not hasattr(request, 'user') or not request.user.is_authenticated:
        logger.debug("Dashboard view: user not authenticated, redirecting to login")
        return redirect('login')

    # Get user roles and permissions
    user = request.user
    roles = user.get_roles()
    highest_role = user.get_highest_role()

    logger.debug(f"Dashboard view: username={user.username}, roles={roles}, highest_role={highest_role}")

    context = {
        'user_info': user.to_dict(),
        'navigation': [
            {
                'name': 'Dashboard',
                'url': '/dashboard/',
                'icon': 'dashboard',
                'active': True,
                'visible': True
            }
        ],
        'dashboard_data': {
            'user': {
                'name': user.name or user.username,
                'role': highest_role or 'Unknown',
                'last_login': '2024-01-15 10:30:00',
            },
            'system': {
                'status': 'Healthy',
                'uptime': '15 days, 7 hours',
                'version': '1.0.0'
            }
        },
        'available_actions': []
    }

    # Add role-specific navigation and actions
    if user.has_role('role_super_admin') or user.has_role('admin'):
        context['navigation'].extend([
            {
                'name': 'Manage Users',
                'url': '/dashboard/users/',
                'icon': 'users',
                'active': False,
                'visible': True
            },
            {
                'name': 'Integrations',
                'url': '/dashboard/integrations/',
                'icon': 'integrations',
                'active': False,
                'visible': True
            }
        ])

        if user.has_role('role_super_admin'):
            context['available_actions'].extend([
                {'name': 'Add User', 'url': '#', 'icon': 'person_add'},
                {'name': 'Manage Roles', 'url': '#', 'icon': 'admin_panel_settings'},
            ])

    if user.has_role('role_super_admin') or user.has_role('admin') or user.has_role('user'):
        context['navigation'].append({
            'name': 'Tasks',
            'url': '/dashboard/tasks/',
            'icon': 'tasks',
            'active': False,
            'visible': True
        })

        context['available_actions'].append({
            'name': 'Create Task', 'url': '#', 'icon': 'add'
        })

    if user.has_role('role_super_admin') or user.has_role('admin') or user.has_role('operator'):
        context['navigation'].append({
            'name': 'Adhoc Tasks',
            'url': '/dashboard/adhoc/',
            'icon': 'adhoc',
            'active': False,
            'visible': True
        })

        context['available_actions'].append({
            'name': 'Execute Adhoc Task', 'url': '#', 'icon': 'play'
        })

    logger.debug(f"Dashboard view: rendering with context keys: {list(context.keys())}")
    logger.debug(f"Dashboard view: user_info keys: {list(context['user_info'].keys()) if 'user_info' in context else 'None'}")
    logger.debug(f"Dashboard view: navigation items: {len(context.get('navigation', []))}")
    logger.debug(f"Dashboard view: available actions: {len(context.get('available_actions', []))}")

    # Render the dashboard
    response = render(request, 'dashboard/dashboard.html', context)
    logger.debug(f"Dashboard view: rendered dashboard with status {response.status_code}")
    return response


# API endpoints
def whoami_view(request):
    """Get current user information"""
    try:
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Not authenticated',
                'message': 'Please login to access this endpoint'
            }, status=401)

        user_data = request.user.to_dict()
        return JsonResponse({
            'success': True,
            'user': user_data
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Failed to get user information',
            'message': str(e)
        }, status=500)


def check_auth_view(request):
    """Check authentication status"""
    try:
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return JsonResponse({
                'authenticated': False,
                'message': 'Not authenticated'
            })

        return JsonResponse({
            'authenticated': True,
            'user': {
                'username': request.user.username,
                'email': request.user.email,
                'name': request.user.name,
                'roles': request.user.get_roles(),
                'highest_role': request.user.get_highest_role(),
                'is_staff': request.user.is_staff,
                'is_superuser': request.user.is_superuser
            }
        })

    except Exception as e:
        return JsonResponse({
            'authenticated': False,
            'error': 'Failed to check authentication status'
        }, status=500)


# URL patterns
urlpatterns = [
    # Authentication
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    # Dashboard
    path('dashboard/', dashboard_view, name='dashboard'),

    # API endpoints
    path('api/whoami/', whoami_view, name='whoami'),
    path('api/check-auth/', check_auth_view, name='check_auth'),

    # Root URL
    path('', lambda request: redirect(reverse('dashboard') if hasattr(request, 'user') and request.user.is_authenticated else reverse('login'))),
]