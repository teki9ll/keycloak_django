"""
Database-free session tracking using Django's cache framework.
This provides session management without requiring database models.
"""

from django.core.cache import cache
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)


class SessionManager:
    """In-memory session tracking using Django cache"""

    # Cache key prefixes
    USER_SESSIONS_PREFIX = "keycloak_user_sessions:"
    SESSION_INFO_PREFIX = "keycloak_session_info:"
    LOGOUT_REQUEST_PREFIX = "keycloak_logout:"

    # Default timeouts
    DEFAULT_SESSION_TIMEOUT = 30 * 24 * 60 * 60  # 30 days
    LOGOUT_REQUEST_TIMEOUT = 7 * 24 * 60 * 60  # 7 days

    @classmethod
    def create_session(cls, request, user_info):
        """Create a new session record in cache"""
        session_key = request.session.session_key
        user_id = user_info.get('sub', '')
        username = user_info.get('username', user_info.get('preferred_username', ''))

        if not session_key:
            logger.warning("Cannot create session record - no session key available")
            return False

        # Session information
        session_info = {
            'session_key': session_key,
            'user_id': user_id,
            'username': username,
            'created_at': int(time.time()),
            'last_accessed': int(time.time()),
            'expires_at': request.session.get_expiry_date().timestamp(),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
            'ip_address': cls._get_client_ip(request),
            'roles': user_info.get('roles', []),
            'email': user_info.get('email', ''),
            'is_active': True,
        }

        # Store session info
        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        cache.set(session_cache_key, session_info, cls.DEFAULT_SESSION_TIMEOUT)

        # Add to user's active sessions list
        user_sessions_key = f"{cls.USER_SESSIONS_PREFIX}{user_id}"
        user_sessions = cache.get(user_sessions_key, [])

        # Remove any expired sessions from the list
        user_sessions = [s for s in user_sessions if s != session_key and cls._is_session_cached(s)]

        # Add new session if not already present
        if session_key not in user_sessions:
            user_sessions.append(session_key)

        cache.set(user_sessions_key, user_sessions, cls.DEFAULT_SESSION_TIMEOUT)

        logger.info(f"Created session tracking for user: {username}, session: {session_key[:8]}...")

        # Verify the session was actually stored
        if cls.is_session_valid(session_key):
            logger.info(f"Session {session_key[:8]}... successfully stored and validated")
        else:
            logger.error(f"Failed to store session {session_key[:8]}... in cache")

        return True

    @classmethod
    def is_session_valid(cls, session_key):
        """Check if session is still valid and active"""
        if not session_key:
            return False

        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        session_info = cache.get(session_cache_key)

        if not session_info:
            logger.debug(f"Session {session_key[:8]}... not found in cache")
            return False

        # Check if session is still active
        if not session_info.get('is_active', True):
            logger.debug(f"Session {session_key[:8]}... marked as inactive")
            return False

        # Check if session has expired
        if time.time() > session_info.get('expires_at', 0):
            logger.debug(f"Session {session_key[:8]}... has expired")
            cls.invalidate_session(session_key)
            return False

        # Update last accessed time
        session_info['last_accessed'] = int(time.time())
        cache.set(session_cache_key, session_info, cls.DEFAULT_SESSION_TIMEOUT)

        return True

    @classmethod
    def invalidate_session(cls, session_key):
        """Mark a single session as inactive"""
        if not session_key:
            return False

        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        session_info = cache.get(session_cache_key)

        if session_info:
            session_info['is_active'] = False
            session_info['logout_requested'] = True
            cache.set(session_cache_key, session_info, cls.DEFAULT_SESSION_TIMEOUT)
            logger.info(f"Invalidated session: {session_key[:8]}...")
            return True

        return False

    @classmethod
    def invalidate_all_user_sessions(cls, user_id=None, username=None):
        """Invalidate all active sessions for a user"""
        if not user_id and not username:
            return 0

        sessions_invalidated = 0

        # Find user by username if no user_id provided
        if not user_id and username:
            user_id = cls._find_user_id_by_username(username)

        if not user_id:
            logger.warning(f"Could not find user_id for username: {username}")
            return 0

        # Get all sessions for this user
        user_sessions_key = f"{cls.USER_SESSIONS_PREFIX}{user_id}"
        user_sessions = cache.get(user_sessions_key, [])

        # Invalidate each session
        for session_key in user_sessions:
            if cls.invalidate_session(session_key):
                sessions_invalidated += 1

        # Clear the user's session list
        cache.delete(user_sessions_key)

        logger.info(f"Invalidated {sessions_invalidated} sessions for user: {username or user_id}")
        return sessions_invalidated

    @classmethod
    def get_user_sessions(cls, user_id=None, username=None):
        """Get all active sessions for a user"""
        if not user_id and not username:
            return []

        # Find user by username if no user_id provided
        if not user_id and username:
            user_id = cls._find_user_id_by_username(username)

        if not user_id:
            return []

        user_sessions_key = f"{cls.USER_SESSIONS_PREFIX}{user_id}"
        user_sessions = cache.get(user_sessions_key, [])

        # Filter active sessions and get session info
        active_sessions = []
        for session_key in user_sessions:
            if cls._is_session_cached(session_key):
                session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
                session_info = cache.get(session_cache_key)
                if session_info and session_info.get('is_active', True):
                    # Remove sensitive data for display
                    display_info = {
                        'session_key': session_key[:16] + '...',
                        'created_at': session_info['created_at'],
                        'last_accessed': session_info['last_accessed'],
                        'user_agent': session_info['user_agent'],
                        'ip_address': session_info['ip_address'],
                        'is_current': False,  # Would need request context
                    }
                    active_sessions.append(display_info)

        return active_sessions

    @classmethod
    def record_logout_request(cls, user_id, username, logout_type='global', sessions_affected=0, request=None):
        """Record a logout request for audit purposes"""
        logout_info = {
            'user_id': user_id,
            'username': username,
            'logout_type': logout_type,
            'sessions_affected': sessions_affected,
            'requested_at': int(time.time()),
            'ip_address': request.META.get('REMOTE_ADDR') if request else 'Unknown',
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200] if request else '',
            'completed_successfully': True,
            'error_message': '',
        }

        # Store logout request with unique key
        logout_key = f"{cls.LOGOUT_REQUEST_PREFIX}{user_id}_{int(time.time())}"
        cache.set(logout_key, logout_info, cls.LOGOUT_REQUEST_TIMEOUT)

        logger.info(f"Recorded logout request: {logout_type} for {username}, sessions affected: {sessions_affected}")

    @classmethod
    def get_logout_history(cls, user_id=None, username=None, limit=10):
        """Get logout history for a user"""
        history = []

        # This is a simplified approach - in production, you might want a more efficient method
        # For now, we'll return recent history from a separate cache key

        history_key = f"{cls.LOGOUT_REQUEST_PREFIX}history_{user_id or username}"
        cached_history = cache.get(history_key, [])

        return cached_history[:limit]

    @classmethod
    def _is_session_cached(cls, session_key):
        """Check if session exists in cache"""
        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        return cache.get(session_cache_key) is not None

    @classmethod
    def _find_user_id_by_username(cls, username):
        """Find user_id by searching through recent sessions (simplified approach)"""
        # This is a simplified implementation
        # In practice, you might maintain a separate username->user_id mapping

        # For now, return None as we don't store this mapping in cache
        # This is acceptable for the current use case
        return None

    @classmethod
    def _get_client_ip(cls, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

    @classmethod
    def cleanup_expired_sessions(cls):
        """Clean up expired sessions from cache"""
        # This would be called periodically by a management command
        # For now, rely on cache TTL to automatically clean up expired sessions
        logger.debug("Session cleanup relies on cache TTL expiration")
        return True

    @classmethod
    def get_session_stats(cls):
        """Get session statistics (simplified)"""
        return {
            'active_sessions': 'Unknown (cache-based tracking)',
            'storage_type': 'Django Cache (In-memory)',
            'database_required': False,
        }