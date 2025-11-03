"""
Simple Stateless User Object

This module provides a lightweight user object that mimics Django's User interface
but gets all data from JWT tokens without requiring any database models.
"""

from typing import Dict, List, Any, Optional


class StatelessUser:
    """
    A simple stateless user object that mimics Django's User interface
    but gets all data from JWT tokens.
    """

    def __init__(self, token_payload: Dict[str, Any], user_info: Optional[Dict[str, Any]] = None):
        self._token_payload = token_payload
        self._user_info = user_info or token_payload

        # Extract basic user information
        self.username = self._user_info.get('preferred_username') or self._user_info.get('sub')
        self.email = self._user_info.get('email')
        self.first_name = self._user_info.get('given_name', '')
        self.last_name = self._user_info.get('family_name', '')
        self.name = self._user_info.get('name', f"{self.first_name} {self.last_name}".strip())
        self.user_id = self._user_info.get('sub')
        self.is_active = True

        # Extract roles
        self._roles = self._extract_roles()

        # Token information
        self._token_exp = token_payload.get('exp')
        self._token_iat = token_payload.get('iat')
        self._token_jti = token_payload.get('jti')

    def _extract_roles(self) -> List[str]:
        """Extract roles from token payload"""
        realm_access = self._token_payload.get('realm_access', {})
        return realm_access.get('roles', [])

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return True

    @property
    def is_anonymous(self) -> bool:
        """Check if user is anonymous"""
        return False

    @property
    def is_staff(self) -> bool:
        """Check if user is staff"""
        return False

    @property
    def is_superuser(self) -> bool:
        """Check if user is superuser"""
        return False

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return role_name in self._roles

    def has_any_role(self, role_names: List[str]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self._roles for role in role_names)

    def has_all_roles(self, role_names: List[str]) -> bool:
        """Check if user has all of the specified roles"""
        return all(role in self._roles for role in role_names)

    def get_roles(self) -> List[str]:
        """Get all user roles"""
        return self._roles.copy()

    def get_highest_role(self) -> Optional[str]:
        """Get the highest role based on hierarchy"""
        role_hierarchy = {
            'admin': 2,
            'user': 1,
        }

        highest_role = None
        highest_level = 0

        for role in self._roles:
            level = role_hierarchy.get(role, 0)
            if level > highest_level:
                highest_level = level
                highest_role = role

        return highest_role

    def get_token_info(self) -> Dict[str, Any]:
        """Get token information"""
        import time
        return {
            'exp': self._token_exp,
            'iat': self._token_iat,
            'jti': self._token_jti,
            'is_expired': self._token_exp and self._token_exp < time.time()
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert user object to dictionary"""
        return {
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'name': self.name,
            'user_id': self.user_id,
            'roles': self._roles,
            'is_authenticated': self.is_authenticated,
            'is_staff': self.is_staff,
            'is_superuser': self.is_superuser,
            'highest_role': self.get_highest_role()
        }

    # Django compatibility methods
    def has_perm(self, perm: str, obj: Any = None) -> bool:
        """Django compatibility - check permission"""
        return False

    def has_module_perms(self, app_label: str) -> bool:
        """Django compatibility - check module permissions"""
        return False

    def __str__(self) -> str:
        return self.username or 'AnonymousUser'

    def __repr__(self) -> str:
        return f"StatelessUser(username='{self.username}', roles={self._roles})"


class AnonymousStatelessUser:
    """
    Simple anonymous user for unauthenticated requests
    """

    def __init__(self):
        self.username = ''
        self.email = ''
        self.first_name = ''
        self.last_name = ''
        self.name = ''
        self.user_id = None
        self.is_active = False

    @property
    def is_authenticated(self) -> bool:
        return False

    @property
    def is_anonymous(self) -> bool:
        return True

    @property
    def is_staff(self) -> bool:
        return False

    @property
    def is_superuser(self) -> bool:
        return False

    def has_role(self, role_name: str) -> bool:
        return False

    def has_any_role(self, role_names: List[str]) -> bool:
        return False

    def has_all_roles(self, role_names: List[str]) -> bool:
        return False

    def get_roles(self) -> List[str]:
        return []

    def get_highest_role(self) -> Optional[str]:
        return None

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        return False

    def has_module_perms(self, app_label: str) -> bool:
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'username': '',
            'is_authenticated': False,
            'is_anonymous': True,
            'roles': []
        }

    def __str__(self) -> str:
        return 'AnonymousUser'

    def __repr__(self) -> str:
        return 'AnonymousStatelessUser()'