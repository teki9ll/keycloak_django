"""
Django model for tracking active user sessions for global logout functionality.
This allows us to track and invalidate all sessions for a user across multiple devices.
"""

from django.db import models
from django.conf import settings
import json
import time


class UserSession(models.Model):
    """Track active user sessions for global logout management"""

    # Keycloak user identifier (from JWT sub claim)
    user_id = models.CharField(max_length=255, db_index=True)
    username = models.CharField(max_length=150, db_index=True)

    # Django session identifier
    session_key = models.CharField(max_length=40, unique=True, db_index=True)

    # Session metadata
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    # Device/browser info for tracking
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    # Session data (JSON)
    session_data = models.JSONField(default=dict, blank=True)

    # Status flags
    is_active = models.BooleanField(default=True)
    logout_requested = models.BooleanField(default=False)

    class Meta:
        db_table = 'keycloak_user_sessions'
        indexes = [
            models.Index(fields=['user_id', 'is_active']),
            models.Index(fields=['username', 'is_active']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.username} - {self.session_key[:8]}... ({'Active' if self.is_active else 'Inactive'})"

    @classmethod
    def create_session(cls, request, user_info):
        """Create a new user session record"""
        session_key = request.session.session_key

        # Clean up any existing inactive sessions for this user
        cls.cleanup_expired_sessions()

        # Create new session record
        session = cls.objects.create(
            user_id=user_info.get('sub', ''),
            username=user_info.get('username', user_info.get('preferred_username', '')),
            session_key=session_key,
            expires_at=request.session.get_expiry_date(),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            ip_address=cls._get_client_ip(request),
            session_data={
                'access_token_issued': int(time.time()),
                'roles': user_info.get('roles', []),
                'email': user_info.get('email', ''),
            }
        )

        return session

    @classmethod
    def get_active_sessions(cls, user_id=None, username=None):
        """Get all active sessions for a user"""
        queryset = cls.objects.filter(is_active=True)

        if user_id:
            queryset = queryset.filter(user_id=user_id)
        elif username:
            queryset = queryset.filter(username=username)

        return queryset.select_related().order_by('-last_accessed')

    @classmethod
    def invalidate_all_user_sessions(cls, user_id=None, username=None):
        """Invalidate all active sessions for a user"""
        queryset = cls.get_active_sessions(user_id=user_id, username=username)
        count = queryset.count()

        # Mark sessions as inactive
        queryset.update(is_active=False, logout_requested=True)

        return count

    @classmethod
    def invalidate_single_session(cls, session_key):
        """Invalidate a single session"""
        try:
            session = cls.objects.get(session_key=session_key, is_active=True)
            session.is_active = False
            session.logout_requested = True
            session.save()
            return True
        except cls.DoesNotExist:
            return False

    @classmethod
    def cleanup_expired_sessions(cls):
        """Clean up expired sessions"""
        from django.utils import timezone
        return cls.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)

    @staticmethod
    def _get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def to_dict(self):
        """Convert session to dictionary for display"""
        return {
            'id': self.id,
            'username': self.username,
            'session_key': self.session_key[:16] + '...',
            'created_at': self.created_at.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'user_agent': self.user_agent[:100] + '...' if len(self.user_agent) > 100 else self.user_agent,
            'ip_address': str(self.ip_address) if self.ip_address else 'Unknown',
            'is_current': self.is_current_session(),
            'is_active': self.is_active,
        }

    def is_current_session(self, session_key=None):
        """Check if this is the current session"""
        # This would need to be called with the current request's session key
        return False  # To be implemented when called with session key


class GlobalLogoutRequest(models.Model):
    """Track global logout requests for audit purposes"""

    # User who requested logout
    user_id = models.CharField(max_length=255, db_index=True)
    username = models.CharField(max_length=150, db_index=True)

    # Logout details
    logout_type = models.CharField(
        max_length=20,
        choices=[
            ('self', 'Self Logout'),
            ('global', 'Global Logout'),
            ('admin', 'Admin Force Logout'),
        ],
        default='global'
    )

    # Request metadata
    requested_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Results
    sessions_affected = models.PositiveIntegerField(default=0)
    completed_successfully = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'keycloak_global_logout_requests'
        ordering = ['-requested_at']

    def __str__(self):
        return f"{self.username} - {self.logout_type} ({self.requested_at})"
