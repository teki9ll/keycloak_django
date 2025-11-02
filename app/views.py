from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import logout as django_logout
from django.conf import settings
from urllib.parse import urlencode
from app.decorators import keycloak_login_required, require_role, require_any_role, AnonymousUser
import json
import base64
import secrets


def login(request):
    """Login page - redirects to Keycloak for authentication"""
    if getattr(request.user, 'is_authenticated', False):
        return redirect('dashboard')

    if request.method == 'POST':
        # Generate PKCE parameters
        # code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        # request.session['pkce_code_verifier'] = code_verifier

        # code_challenge = base64.urlsafe_b64encode(
        #     code_verifier.encode('utf-8')
        # ).decode('utf-8').rstrip('=')

        # Generate state parameter for security
        state = secrets.token_urlsafe(16)
        request.session['oauth_state'] = state

        # Build Keycloak authorization URL
        auth_params = {
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': request.build_absolute_uri('/callback/'),
            'state': state,
            # 'code_challenge': code_challenge,
            # 'code_challenge_method': 'S256',
        }

        auth_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/auth?{urlencode(auth_params)}"

        return redirect(auth_url)

    return render(request, 'app/login.html')


def callback(request):
    """OAuth2 callback from Keycloak"""
    error = request.GET.get('error')
    if error:
        return render(request, 'app/login.html', {
            'error': f"Authentication failed: {error}"
        })

    # Verify state parameter
    state = request.GET.get('state')
    stored_state = request.session.get('oauth_state')
    if not state or state != stored_state:
        return render(request, 'app/login.html', {
            'error': "Invalid state parameter"
        })

    # Exchange authorization code for tokens
    code = request.GET.get('code')
    if not code:
        return render(request, 'app/login.html', {
            'error': "No authorization code received"
        })

    try:
        # Exchange code for token
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': request.build_absolute_uri('/callback/'),
            # 'code_verifier': request.session.get('pkce_code_verifier'),
        }

        import requests

        token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"

        # Debug logging
        print(f"Keycloak token URL: {token_url}")
        print(f"Token request data: {token_data}")
        print(f"Client ID: {settings.KEYCLOAK_CLIENT_ID}")
        print(f"Client Secret: {'*' * len(settings.KEYCLOAK_CLIENT_SECRET) if settings.KEYCLOAK_CLIENT_SECRET else 'None'}")
        print(f"Code verifier present: {bool(request.session.get('pkce_code_verifier'))}")

        response = requests.post(token_url, data=token_data)
        print(f"Token response status: {response.status_code}")
        print(f"Token response headers: {dict(response.headers)}")
        print(f"Token response body: {response.text[:500]}")  # First 500 chars

        if response.status_code != 200:
            error_details = f"Token request failed with status {response.status_code}"
            try:
                error_data = response.json()
                error_details += f": {error_data.get('error_description', error_data.get('error', 'Unknown error'))}"
            except:
                error_details += f": {response.text[:200]}"

            print(f"Keycloak token error: {error_details}")  # Debug logging
            return render(request, 'app/login.html', {
                'error': error_details
            })

        token_info = response.json()
        access_token = token_info.get('access_token')
        refresh_token = token_info.get('refresh_token')
        expires_in = token_info.get('expires_in', 3600)

        # Store tokens in session
        request.session['access_token'] = access_token
        if refresh_token:
            request.session['refresh_token'] = refresh_token

        # Store token metadata
        import time
        request.session['token_acquired_at'] = int(time.time())
        request.session['token_expires_in'] = expires_in
        request.session['authenticated_at'] = int(time.time())

        # Ensure session persists
        request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days

        print(f"Stored tokens: access_token={bool(access_token)}, refresh_token={bool(refresh_token)}")
        print(f"Token expires in: {expires_in} seconds")

        return redirect('dashboard')

    except Exception as e:
        error_msg = f"Authentication error: {str(e)}"
        print(f"Keycloak authentication exception: {error_msg}")  # Debug logging
        import traceback
        traceback.print_exc()  # Print full stack trace
        return render(request, 'app/login.html', {
            'error': error_msg
        })


def logout(request):
    """Logout and redirect to Keycloak"""
    try:
        # Clear session
        request.session.flush()

        # Build Keycloak logout URL
        logout_params = {
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'post_logout_redirect_uri': request.build_absolute_uri('/'),
        }

        logout_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout?{urlencode(logout_params)}"

        return redirect(logout_url)

    except Exception:
        return redirect('login')


def dashboard_view(request):
    """Dashboard page with user details"""
    if not getattr(request.user, 'is_authenticated', False):
        return redirect('login')
    user = request.user

    # Get user info from token if available
    token = request.session.get('access_token')
    user_info = {}

    if token:
        try:
            import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            user_info = {
                'sub': payload.get('sub'),
                'email_verified': payload.get('email_verified', False),
                'name': payload.get('name'),
                'preferred_username': payload.get('preferred_username'),
                'given_name': payload.get('given_name'),
                'family_name': payload.get('family_name'),
                'email': payload.get('email'),
            }
        except:
            pass

    context = {
        'user': user,
        'user_info': user_info,
        'session_info': {
            'authenticated_at': request.session.get('authenticated_at'),
            'token_present': bool(token),
        }
    }

    return render(request, 'app/dashboard.html', context)


def public_info(request):
    """Public endpoint - no authentication required"""
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            "message": "This is a public endpoint",
            "service": "Django Keycloak Demo",
            "status": "running"
        })
    else:
        return render(request, 'app/public.html')


@keycloak_login_required
def dashboard(request):
    """Protected endpoint - authentication required"""
    return JsonResponse({
        "message": f"Welcome {request.user.username}",
        "email": getattr(request.user, 'email', ''),
        "roles": getattr(request.user, 'roles', []),
        "is_authenticated": True
    })


@require_role("admin")
def admin_panel(request):
    """Admin only endpoint"""
    return JsonResponse({
        "message": f"Admin access granted to {request.user.username}",
        "user_roles": getattr(request.user, 'roles', []),
        "admin_data": {
            "total_users": "N/A (stateless)",
            "system_status": "operational"
        }
    })


@require_any_role(["admin", "manager"])
def manager_panel(request):
    """Admin or Manager endpoint"""
    return JsonResponse({
        "message": f"Manager access granted to {request.user.username}",
        "user_roles": getattr(request.user, 'roles', []),
        "manager_data": {
            "team_size": "N/A (stateless)",
            "projects": []
        }
    })


@keycloak_login_required
@require_http_methods(["POST"])
@csrf_exempt
def update_profile(request):
    """Example of a POST endpoint that processes JSON data"""
    try:
        data = json.loads(request.body)
        return JsonResponse({
            "message": f"Profile updated for {request.user.username}",
            "received_data": data,
            "user_roles": getattr(request.user, 'roles', [])
        })
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)


def auth_status(request):
    """Check current authentication status"""
    user = getattr(request, 'user', None)
    if user and getattr(user, 'is_authenticated', False):
        return JsonResponse({
            "authenticated": True,
            "username": getattr(user, 'username', ''),
            "email": getattr(user, 'email', ''),
            "roles": getattr(user, 'roles', [])
        })
    else:
        return JsonResponse({
            "authenticated": False,
            "message": "No valid authentication token found"
        })
