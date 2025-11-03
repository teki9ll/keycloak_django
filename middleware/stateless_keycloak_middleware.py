"""
Stateless Keycloak Authentication Middleware

This middleware handles TRULY stateless authentication using Keycloak tokens.
It validates tokens on each request and injects a user object into the request.

Features:
- Automatic token validation using Keycloak public keys
- Token refresh when access token is expired
- COOKIE-based token storage (NO database, NO sessions)
- Role-based user object injection
- Pure stateless implementation
"""

import time
import json
import logging
from typing import Optional, Dict, Any
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.conf import settings
from django.urls import reverse
from django.core.signing import Signer, BadSignature

from keycloak_manager import keycloak_manager
from auth.stateless_user import StatelessUser, AnonymousStatelessUser

logger = logging.getLogger(__name__)


class StatelessKeycloakMiddleware:
    """
    TRULY Stateless Middleware for Keycloak authentication
    Uses cookies instead of sessions - NO database dependency
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.login_url = getattr(settings, 'LOGIN_URL', '/login/')
        self.logout_url = getattr(settings, 'LOGOUT_URL', '/logout/')
        self.public_urls = getattr(settings, 'PUBLIC_URLS', [
            '/login/',
            '/logout/',
            '/static/',
            '/media/',
        ])
        # Cookie-based token storage
        self.signer = Signer()
        self.token_cookie_name = 'kc_tokens'
        self.user_cookie_name = 'kc_user'

    def __call__(self, request):
        # Skip authentication for public URLs
        if self._is_public_url(request.path):
            request.user = AnonymousStatelessUser()
            return self.get_response(request)

        # Try to authenticate user
        user = self._authenticate_user(request)

        if user is None:
            # Authentication failed - redirect to login
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'error': 'Authentication required',
                    'message': 'Please login to access this resource'
                }, status=401)
            else:
                return redirect(self.login_url + '?next=' + request.path)

        # Inject user into request
        request.user = user

        return self.get_response(request)

    def _is_public_url(self, path: str) -> bool:
        """Check if URL is public (doesn't require authentication)"""
        for public_url in self.public_urls:
            if path.startswith(public_url):
                return True
        return False

    def _authenticate_user(self, request):
        """
        Authenticate user using token from cookies or headers
        """
        try:
            # Try to get token from cookies first
            token_data = self._get_token_from_cookies(request)

            # If not in cookies, try Authorization header
            if not token_data:
                token_data = self._get_token_from_header(request)

            if not token_data:
                logger.debug("No token found in cookies or headers")
                return None

            access_token = token_data.get('access_token')
            if not access_token:
                logger.debug("No access token in token data")
                return None

            # Validate token
            token_payload = keycloak_manager.validate_token(access_token)
            if not token_payload:
                # Token is invalid or expired, try refresh
                logger.debug("Token validation failed, attempting refresh")
                token_payload = self._refresh_token(request)

                if not token_payload:
                    logger.debug("Token refresh failed")
                    return None

            # Get additional user info
            # For demo tokens, validate_token returned user_info, but we need the original payload
            if token_payload.get('is_demo', False):
                # Re-decode the original JWT token to get the full payload with roles
                import jwt
                try:
                    demo_secret = 'demo-secret-key-for-stateless-auth'
                    original_payload = jwt.decode(access_token, demo_secret, algorithms=['HS256'], audience='easytask')

                    # Check if this is an old token with too many roles (from before our cleanup)
                    roles = original_payload.get('realm_access', {}).get('roles', [])
                    if len(roles) > 5:  # Old tokens had 40+ roles, new tokens should have 0
                        logger.warning(f"Detected old token with {len(roles)} roles, invalidating")
                        return None  # Force logout by returning None

                    user_info = token_payload  # Use the processed user_info for basic fields
                    # But create user with original payload for roles
                    user = StatelessUser(original_payload, user_info)
                except Exception as e:
                    logger.error(f"Error re-decoding demo token: {e}")
                    user = StatelessUser(token_payload, token_payload)
            else:
                user_info = keycloak_manager.get_user_info(access_token)
                user = StatelessUser(token_payload, user_info)

            # Store token info in request for later use
            request._token_data = token_data

            logger.debug(f"User authenticated: {user.username} with roles: {user.get_roles()}")
            return user

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def _get_token_from_cookies(self, request) -> Optional[Dict[str, Any]]:
        """Get token data from cookies"""
        try:
            # First check for demo tokens
            demo_access_token = request.COOKIES.get('demo_access_token')
            if demo_access_token:
                # Demo mode: Get user info from token
                try:
                    # Validate demo token and get user info
                    user_info = keycloak_manager.validate_token(demo_access_token)
                    if user_info:
                        demo_refresh_token = request.COOKIES.get('demo_refresh_token')
                        return {
                            'access_token': demo_access_token,
                            'refresh_token': demo_refresh_token,
                            'expires_in': 3600,  # 1 hour
                            'token_type': 'Bearer'
                        }
                except Exception as e:
                    logger.error(f"Error validating demo token: {e}")
                    return None

            # Original Keycloak mode: Check for signed cookie
            token_cookie = request.COOKIES.get(self.token_cookie_name)
            if not token_cookie:
                return None

            # Decode signed cookie
            token_data = self.signer.unsign(token_cookie)
            return json.loads(token_data)

        except BadSignature:
            logger.warning("Invalid token cookie signature")
            return None
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error decoding token cookie: {e}")
            return None

    def _get_token_from_header(self, request) -> Optional[Dict[str, Any]]:
        """Get token data from Authorization header"""
        try:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                access_token = auth_header[7:]  # Remove 'Bearer ' prefix
                return {
                    'access_token': access_token,
                    'stored_at': time.time()
                }
        except Exception as e:
            logger.error(f"Error getting token from header: {e}")
        return None

    def _refresh_token(self, request) -> Optional[Dict[str, Any]]:
        """
        Refresh access token using refresh token from cookies
        """
        try:
            token_data = self._get_token_from_cookies(request)
            if not token_data:
                return None

            refresh_token = token_data.get('refresh_token')
            if not refresh_token:
                logger.debug("No refresh token available")
                return None

            # Attempt to refresh token
            new_tokens = keycloak_manager.refresh_token(refresh_token)
            if not new_tokens:
                logger.debug("Token refresh failed")
                # Clear invalid tokens
                self._clear_token_cookies(request)
                return None

            # Update token data
            updated_token_data = {
                'access_token': new_tokens.get('access_token'),
                'refresh_token': new_tokens.get('refresh_token'),
                'expires_in': new_tokens.get('expires_in'),
                'token_type': new_tokens.get('token_type', 'Bearer'),
                'stored_at': time.time()
            }

            # Store new tokens in cookies (will be done in response)
            request._new_token_data = updated_token_data

            # Validate new token
            access_token = new_tokens.get('access_token')
            if access_token:
                token_payload = keycloak_manager.validate_token(access_token)
                if token_payload:
                    logger.debug("Token refreshed successfully")
                    return token_payload

            return None

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return None

    def _clear_token_cookies(self, request):
        """Clear token cookies"""
        # This will be handled in response processing
        request._clear_cookies = True

    def process_response(self, request, response):
        """
        Process response to set/clear cookies
        """
        try:
            # Handle new token data after refresh
            if hasattr(request, '_new_token_data'):
                self._set_token_cookies(response, request._new_token_data)

            # Handle cookie clearing
            if hasattr(request, '_clear_cookies') and request._clear_cookies:
                self._clear_cookies_from_response(response)

        except Exception as e:
            logger.error(f"Error processing response: {e}")

        return response

    def _set_token_cookies(self, response, token_data: Dict[str, Any]):
        """Set token data in signed cookies"""
        try:
            # For demo tokens, store directly (no double encoding)
            # For Keycloak tokens, we might need to handle differently
            access_token = token_data.get('access_token')

            if access_token and 'demo-' in token_data.get('user_info', {}).get('sub', ''):
                # Demo mode: Store tokens directly in cookies
                response.set_cookie(
                    'demo_access_token',
                    access_token,
                    max_age=getattr(settings, 'TOKEN_COOKIE_MAX_AGE', 86400),
                    httponly=getattr(settings, 'TOKEN_COOKIE_HTTPONLY', True),
                    samesite=getattr(settings, 'TOKEN_COOKIE_SAMESITE', 'Lax'),
                    secure=getattr(settings, 'TOKEN_COOKIE_SECURE', False)
                )

                refresh_token = token_data.get('refresh_token')
                if refresh_token:
                    response.set_cookie(
                        'demo_refresh_token',
                        refresh_token,
                        max_age=getattr(settings, 'TOKEN_COOKIE_MAX_AAGE', 86400) * 24,
                        httponly=getattr(settings, 'TOKEN_COOKIE_HTTPONLY', True),
                        samesite=getattr(settings, 'TOKEN_SAMESITE', 'Lax'),
                        secure=getattr(settings, 'TOKEN_COOKIE_SECURE', False)
                    )
            else:
                # Original Keycloak mode: Sign the token data
                signed_data = self.signer.sign(json.dumps(token_data))
                response.set_cookie(
                    self.token_cookie_name,
                    signed_data,
                    max_age=getattr(settings, 'TOKEN_COOKIE_MAX_AGE', 86400),
                    httponly=getattr(settings, 'TOKEN_COOKIE_HTTPONLY', True),
                    samesite=getattr(settings, 'TOKEN_COOKIE_SAMESITE', 'Lax'),
                    secure=getattr(settings, 'TOKEN_COOKIE_SECURE', False)
                )

            logger.debug("Token cookies set successfully")

        except Exception as e:
            logger.error(f"Error setting token cookies: {e}")

    def _clear_cookies_from_response(self, response):
        """Clear token cookies"""
        try:
            response.delete_cookie(self.token_cookie_name)
            response.delete_cookie(self.user_cookie_name)
            logger.debug("Token cookies cleared")
        except Exception as e:
            logger.error(f"Error clearing cookies: {e}")


# Utility functions for cookie-based token management
def store_tokens_in_cookies(response, tokens: Dict[str, Any]):
    """Store Keycloak tokens in signed cookies"""
    try:
        signer = Signer()
        token_data = {
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'expires_in': tokens.get('expires_in'),
            'refresh_expires_in': tokens.get('refresh_expires_in'),
            'token_type': tokens.get('token_type', 'Bearer'),
            'stored_at': time.time()
        }

        signed_data = signer.sign(json.dumps(token_data))

        response.set_cookie(
            'kc_tokens',
            signed_data,
            max_age=getattr(settings, 'TOKEN_COOKIE_MAX_AGE', 86400),
            httponly=getattr(settings, 'TOKEN_COOKIE_HTTPONLY', True),
            samesite=getattr(settings, 'TOKEN_COOKIE_SAMESITE', 'Lax'),
            secure=getattr(settings, 'TOKEN_COOKIE_SECURE', False)
        )

        logger.debug("Tokens stored in cookies successfully")

    except Exception as e:
        logger.error(f"Error storing tokens in cookies: {e}")


def clear_tokens_from_cookies(response):
    """Clear Keycloak tokens from cookies"""
    try:
        response.delete_cookie('kc_tokens')
        logger.debug("Tokens cleared from cookies successfully")
    except Exception as e:
        logger.error(f"Error clearing tokens from cookies: {e}")


def get_tokens_from_cookies(request) -> Optional[Dict[str, Any]]:
    """Get Keycloak tokens from signed cookies"""
    try:
        signer = Signer()
        token_cookie = request.COOKIES.get('kc_tokens')

        if not token_cookie:
            return None

        token_data = signer.unsign(token_cookie)
        return json.loads(token_data)

    except BadSignature:
        logger.warning("Invalid token cookie signature")
        return None
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Error getting tokens from cookies: {e}")
        return None


def is_token_expired(request) -> bool:
    """Check if the stored access token is expired"""
    try:
        tokens = get_tokens_from_cookies(request)
        if not tokens:
            return True

        stored_at = tokens.get('stored_at', 0)
        expires_in = tokens.get('expires_in', 0)

        # Add 60 seconds buffer to avoid edge cases
        return (stored_at + expires_in - 60) < time.time()
    except Exception as e:
        logger.error(f"Error checking token expiration: {e}")
        return True