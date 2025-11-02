"""
Middleware to check if user sessions have been invalidated (global logout).
This middleware runs on every request to ensure the session is still valid.
Uses cache-based session tracking - no database required.
"""

from django.shortcuts import redirect
from django.conf import settings
from app.session_manager import SessionManager
import logging

logger = logging.getLogger(__name__)


class SessionValidationMiddleware:
    """
    Middleware that validates the current user session against our cache-based tracking system.
    If the session has been invalidated (e.g., by global logout), redirect to login.
    No database required - uses Django cache framework.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip session validation for certain paths
        skip_paths = [
            '/login/',
            '/auth/custom-login/',
            '/api/auth/status/',
            '/static/',
            '/media/',
        ]

        if request.path in skip_paths:
            return self.get_response(request)

        # Check if user has an active session with valid tokens
        if hasattr(request, 'session') and request.session.session_key:
            session_key = request.session.session_key
            access_token = request.session.get('access_token')
            user_info = request.session.get('user_info', {})

            # Only validate if we have tokens, user info, and session was actually tracked
            if (access_token and user_info and 'username' in user_info and
                # Check if we have session tracking data in cache
                SessionManager._is_session_cached(session_key)):
                username = user_info.get('username')
                user_id = user_info.get('sub')

                try:
                    # Check if this session is still active in our cache-based tracking system
                    is_session_valid = SessionManager.is_session_valid(session_key)

                    logger.debug(f"Session validation for {username} - Session key: {session_key[:8]}... Valid: {is_session_valid}")

                    if not is_session_valid:
                        logger.info(f"Session {session_key[:8]}... for user {username} has been invalidated. Redirecting to login.")

                        # Clear the invalid session completely
                        request.session.flush()

                        # Add a message explaining why they were logged out
                        from django.contrib import messages
                        messages.warning(request, "Your session has been expired due to a logout from another device.")

                        return redirect('login')

                    logger.debug(f"Session {session_key[:8]}... for user {username} is valid.")

                except Exception as e:
                    logger.error(f"Error validating session: {e}")
                    # If there's an error checking the session, we'll allow the request to continue
                    # but log the issue for debugging
                    import traceback
                    traceback.print_exc()

        return self.get_response(request)