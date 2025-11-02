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
            'user_id': user_id or username,  # Fallback to username if no user_id
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

        # Store username to user_id mapping for easier lookup during logout
        mapping_key = f"username_mapping:{username}"
        cache.set(mapping_key, user_id, cls.DEFAULT_SESSION_TIMEOUT)

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
        """
        Invalidate all active sessions for a user.

        This implementation focuses on reliable cache-based session invalidation
        which provides effective global logout functionality by ensuring that
        all Django sessions for the user are immediately invalidated.

        For true Keycloak session revocation, additional admin privileges are
        required which may not be available with client credentials.
        """
        if not user_id and not username:
            return 0

        sessions_invalidated = 0

        try:
            # Primary approach: Invalidate all Django sessions for the user
            # This is the most reliable method and ensures the user is logged out
            # from all Django application instances immediately

            # If we only have username, try to find a session to get the user_id
            if not user_id and username:
                user_id = cls._find_user_id_by_username(username)

            logger.info(f"Attempting cache invalidation for user_id: {user_id}, username: {username}")
            cache_invalidated = cls._invalidate_cache_sessions(user_id, username)
            sessions_invalidated += cache_invalidated
            logger.info(f"Cache invalidation result: {cache_invalidated}")

            # Secondary approach: Try to invalidate Keycloak sessions if possible
            # This requires elevated permissions that may not be available
            admin_token = cls._get_admin_token()
            if admin_token:
                logger.info("Got admin token, attempting to invalidate Keycloak sessions")

                try:
                    from django.conf import settings
                    import requests

                    # Try to find user sessions using a more basic approach
                    if username:
                        # Try to get user ID first
                        users_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/users"
                        users_response = requests.get(users_url, headers={
                            'Authorization': f'Bearer {admin_token}',
                            'Content-Type': 'application/json'
                        })

                        if users_response.status_code == 200:
                            users = users_response.json()
                            target_user = None

                            for user in users:
                                if user.get('username') == username:
                                    target_user = user
                                    break

                            if target_user:
                                user_id = target_user.get('id')
                                logger.info(f"Found user {username} with ID: {user_id}")

                                # Get user sessions
                                sessions_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/sessions"
                                sessions_response = requests.get(sessions_url, headers={
                                    'Authorization': f'Bearer {admin_token}',
                                    'Content-Type': 'application/json'
                                })

                                if sessions_response.status_code == 200:
                                    sessions_data = sessions_response.json()
                                    sessions = sessions_data.get('sessions', [])

                                    logger.info(f"Found {len(sessions)} Keycloak sessions for user {username}")

                                    # Try to invalidate sessions
                                    keycloak_invalidated = 0
                                    for session in sessions:
                                        try:
                                            session_id = session.get('id')
                                            if session_id and session.get('active'):
                                                # Try to revoke the session
                                                revoke_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/sessions/{session_id}"
                                                revoke_response = requests.delete(revoke_url, headers={
                                                    'Authorization': f'Bearer {admin_token}'
                                                })

                                                if revoke_response.status_code == 204:
                                                    logger.info(f"Successfully revoked Keycloak session {session_id[:8]}...")
                                                    keycloak_invalidated += 1
                                                else:
                                                    logger.debug(f"Could not revoke session {session_id[:8]}... Status: {revoke_response.status_code}")
                                        except Exception as e:
                                            logger.debug(f"Error revoking session: {e}")

                                    sessions_invalidated += keycloak_invalidated
                                    if keycloak_invalidated > 0:
                                        logger.info(f"Revoked {keycloak_invalidated} Keycloak sessions")
                                    else:
                                        logger.info("No Keycloak sessions could be revoked (may require additional permissions)")
                                else:
                                    logger.debug(f"Could not get user sessions. Status: {sessions_response.status_code}")
                            else:
                                logger.debug(f"User {username} not found in Keycloak")
                        else:
                            logger.debug(f"Could not access users endpoint. Status: {users_response.status_code}")

                except Exception as e:
                    logger.debug(f"Error accessing Keycloak admin API: {e}")
            else:
                logger.debug("Could not get Keycloak admin token - using cache-based invalidation only")

        except Exception as e:
            logger.error(f"Error in global logout: {e}")
            # Always fall back to cache-based invalidation
            sessions_invalidated = cls._invalidate_cache_sessions(user_id, username)

        logger.info(f"Global logout completed for {username or user_id}. Total sessions invalidated: {sessions_invalidated}")

        # Record the logout request for audit purposes
        cls.record_logout_request(user_id, username, logout_type='global', sessions_affected=sessions_invalidated)

        return sessions_invalidated

    @classmethod
    def _invalidate_cache_sessions(cls, user_id=None, username=None):
        """Fallback method: invalidate only cache sessions"""
        sessions_invalidated = 0

        # Since LocMemCache doesn't support keys() method, we need to maintain
        # a list of user sessions separately or use a different approach
        # For now, let's use the user sessions mapping approach

        if user_id:
            # If we have user_id, we can invalidate sessions using the user sessions mapping
            user_sessions_key = f"{cls.USER_SESSIONS_PREFIX}{user_id}"
            user_sessions = cache.get(user_sessions_key, [])

            logger.info(f"Found {len(user_sessions)} sessions for user {user_id}: {user_sessions}")

            for session_key in user_sessions:
                if cls._is_session_cached(session_key):
                    logger.info(f"Invalidating session: {session_key}")
                    cls.invalidate_session(session_key)
                    sessions_invalidated += 1
                else:
                    logger.warning(f"Session {session_key} not found in cache")

        elif username:
            # Try to find user sessions using the user sessions mapping
            # We need to find the user_id first since sessions are indexed by user_id
            # This is a limitation - we can't easily find by username without the mapping

            # Alternative approach: invalidate all sessions we can find by checking common patterns
            # In a production environment, you'd want to use Redis or maintain a username->user_id mapping

            # For this implementation, we'll try a simple approach
            # This won't work perfectly with LocMemCache, but provides the basic structure
            logger.warning("Cache-based session invalidation limited with LocMemCache - consider using Redis for production")

            # Try to find session by user sessions prefix (if we had user_id)
            # For now, return 0 as we can't effectively search without the keys() method
            return 0

        return sessions_invalidated

    @classmethod
    def _get_admin_token(cls):
        """Get admin token from Keycloak for session management"""
        try:
            from django.conf import settings
            import requests

            token_data = {
                'grant_type': 'client_credentials',
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            }

            token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
            response = requests.post(token_url, data=token_data)

            if response.status_code == 200:
                token_info = response.json()
                return token_info.get('access_token')
            else:
                logger.error(f"Failed to get admin token: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error getting admin token: {e}")
            return None

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
    def update_session_activity(cls, request):
        """Update the last activity time for current user's session"""
        if not request.session or not request.session.session_key:
            return False

        user_info = request.session.get('user_info', {})
        if not user_info:
            return False

        session_key = request.session.session_key
        user_id = user_info.get('sub', '')
        username = user_info.get('username', '')

        if not session_key or not user_id:
            return False

        # Get existing session info
        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        session_info = cache.get(session_cache_key)

        if not session_info:
            # Session not found in cache, recreate it
            return cls.create_session(request, user_info)

        # Update last activity time
        session_info['last_accessed'] = int(time.time())
        session_info['ip_address'] = cls._get_client_ip(request)
        session_info['is_active'] = True

        # Save updated session info
        cache.set(session_cache_key, session_info, cls.DEFAULT_SESSION_TIMEOUT)

        logger.debug(f"Updated session activity for user: {username}")
        return True

    @classmethod
    def _is_session_cached(cls, session_key):
        """Check if session exists in cache"""
        session_cache_key = f"{cls.SESSION_INFO_PREFIX}{session_key}"
        return cache.get(session_cache_key) is not None

    @classmethod
    def _find_user_id_by_username(cls, username):
        """Find user_id by searching through cached sessions"""
        # Since we can't use cache.keys() with LocMemCache, we'll use a different approach
        # In a production environment with Redis, you could search through all sessions

        # For this demo, we'll maintain a simple mapping in cache
        # This is a simplified approach for demonstration purposes
        mapping_key = f"username_mapping:{username}"
        user_id = cache.get(mapping_key)

        if user_id:
            return user_id

        # Try to find the user_id by checking if we have any session info cached
        # This is a basic approach - in production you'd want a more robust solution
        logger.debug(f"Could not find user_id for username: {username}")
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