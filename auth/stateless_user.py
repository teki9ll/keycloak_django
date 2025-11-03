"""
Stateless User Object for Keycloak Integration

This module provides a lightweight user object that mimics Django's User interface
but gets all data from Keycloak tokens without requiring any database models.
"""

from typing import Dict, List, Any, Optional


class StatelessUser:
    """
    A stateless user object that mimics Django's User interface
    but gets all data from Keycloak JWT tokens.
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
        """Check if user is staff (admin or higher)"""
        return self.has_role('role_super_admin') or self.has_role('admin')

    @property
    def is_superuser(self) -> bool:
        """Check if user is superuser (highest role)"""
        return self.has_role('role_super_admin')

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
            'role_super_admin': 4,
            'admin': 3,
            'user': 2,
            'operator': 1,
        }

        highest_role = None
        highest_level = 0

        for role in self._roles:
            level = role_hierarchy.get(role, 0)
            if level > highest_level:
                highest_level = level
                highest_role = role

        return highest_role

    def can_manage_users(self) -> bool:
        """Check if user can manage other users"""
        return self.has_role('role_super_admin')

    def can_manage_integrations(self) -> bool:
        """Check if user can manage integrations"""
        return self.has_any_role(['role_super_admin', 'admin'])

    def can_manage_tasks(self) -> bool:
        """Check if user can manage tasks"""
        return self.has_any_role(['role_super_admin', 'admin', 'user'])

    def can_execute_adhoc_tasks(self) -> bool:
        """Check if user can execute adhoc tasks"""
        return self.has_any_role(['role_super_admin', 'admin', 'operator'])

    # Keycloak Realm Management Permissions
    def is_realm_admin(self) -> bool:
        """Check if user is a realm administrator"""
        return self.has_role('realm-admin') or self.has_role('role_super_admin')

    def can_manage_realm(self) -> bool:
        """Check if user can manage realm settings"""
        return self.has_any_role(['manage-realm', 'realm-admin', 'role_super_admin'])

    def can_manage_keycloak_users(self) -> bool:
        """Check if user can manage Keycloak users (create, update, delete, reset passwords)"""
        return self.has_any_role(['manage-users', 'realm-admin', 'role_super_admin'])

    def can_view_keycloak_users(self) -> bool:
        """Check if user can view Keycloak users"""
        return self.has_any_role(['view-users', 'manage-users', 'realm-admin', 'role_super_admin'])

    def can_query_users(self) -> bool:
        """Check if user can query/search users"""
        return self.has_any_role(['query-users', 'manage-users', 'realm-admin', 'role_super_admin'])

    def can_manage_user_authorization(self) -> bool:
        """Check if user can manage user permissions and authorization"""
        return self.has_any_role(['manage-authorization', 'realm-admin', 'role_super_admin'])

    def can_manage_roles(self) -> bool:
        """Check if user can manage roles"""
        return self.has_any_role(['manage-roles', 'realm-admin', 'role_super_admin'])

    def can_view_roles(self) -> bool:
        """Check if user can view roles"""
        return self.has_any_role(['view-roles', 'manage-roles', 'realm-admin', 'role_super_admin'])

    def can_manage_groups(self) -> bool:
        """Check if user can manage groups"""
        return self.has_any_role(['manage-groups', 'realm-admin', 'role_super_admin'])

    def can_view_groups(self) -> bool:
        """Check if user can view groups"""
        return self.has_any_role(['view-groups', 'manage-groups', 'realm-admin', 'role_super_admin'])

    def can_manage_clients(self) -> bool:
        """Check if user can manage OAuth clients"""
        return self.has_any_role(['manage-clients', 'realm-admin', 'role_super_admin'])

    def can_view_clients(self) -> bool:
        """Check if user can view OAuth clients"""
        return self.has_any_role(['view-clients', 'manage-clients', 'realm-admin', 'role_super_admin'])

    def can_manage_identity_providers(self) -> bool:
        """Check if user can manage identity providers"""
        return self.has_any_role(['manage-identity-providers', 'realm-admin', 'role_super_admin'])

    def can_view_identity_providers(self) -> bool:
        """Check if user can view identity providers"""
        return self.has_any_role(['view-identity-providers', 'manage-identity-providers', 'realm-admin', 'role_super_admin'])

    def can_manage_sessions(self) -> bool:
        """Check if user can manage user sessions"""
        return self.has_any_role(['manage-sessions', 'realm-admin', 'role_super_admin'])

    def can_view_sessions(self) -> bool:
        """Check if user can view user sessions"""
        return self.has_any_role(['view-sessions', 'manage-sessions', 'realm-admin', 'role_super_admin'])

    def can_manage_events(self) -> bool:
        """Check if user can manage admin events"""
        return self.has_any_role(['manage-events', 'manage-realm-events', 'realm-admin', 'role_super_admin'])

    def can_view_events(self) -> bool:
        """Check if user can view admin events"""
        return self.has_any_role(['view-events', 'manage-events', 'realm-admin', 'role_super_admin'])

    def can_manage_attack_detection(self) -> bool:
        """Check if user can manage attack detection"""
        return self.has_any_role(['manage-attack-detection', 'realm-admin', 'role_super_admin'])

    def can_view_attack_detection(self) -> bool:
        """Check if user can view attack detection"""
        return self.has_any_role(['view-attack-detection', 'manage-attack-detection', 'realm-admin', 'role_super_admin'])

    def can_create_clients(self) -> bool:
        """Check if user can create OAuth clients"""
        return self.has_any_role(['create-client', 'manage-clients', 'realm-admin', 'role_super_admin'])

    def can_read_tokens(self) -> bool:
        """Check if user can read tokens"""
        return self.has_any_role(['read-token', 'realm-admin', 'role_super_admin'])

    def can_logout_all_users(self) -> bool:
        """Check if user can logout all users"""
        return self.has_any_role(['logout-all', 'manage-sessions', 'realm-admin', 'role_super_admin'])

    def has_full_realm_admin_permissions(self) -> bool:
        """Check if user has all realm admin permissions"""
        return self.has_role('realm-admin') and self.has_role('role_super_admin')

    def get_token_info(self) -> Dict[str, Any]:
        """Get token information"""
        return {
            'exp': self._token_exp,
            'iat': self._token_iat,
            'jti': self._token_jti,
            'is_expired': self._token_exp and self._token_exp < time.time() if 'time' in globals() else False
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
            'highest_role': self.get_highest_role(),
            'permissions': {
                # Application permissions
                'can_manage_users': self.can_manage_users(),
                'can_manage_integrations': self.can_manage_integrations(),
                'can_manage_tasks': self.can_manage_tasks(),
                'can_execute_adhoc_tasks': self.can_execute_adhoc_tasks(),

                # Keycloak Realm Management permissions
                'is_realm_admin': self.is_realm_admin(),
                'can_manage_realm': self.can_manage_realm(),
                'can_manage_keycloak_users': self.can_manage_keycloak_users(),
                'can_view_keycloak_users': self.can_view_keycloak_users(),
                'can_query_users': self.can_query_users(),
                'can_manage_user_authorization': self.can_manage_user_authorization(),
                'can_manage_roles': self.can_manage_roles(),
                'can_view_roles': self.can_view_roles(),
                'can_manage_groups': self.can_manage_groups(),
                'can_view_groups': self.can_view_groups(),
                'can_manage_clients': self.can_manage_clients(),
                'can_view_clients': self.can_view_clients(),
                'can_manage_identity_providers': self.can_manage_identity_providers(),
                'can_view_identity_providers': self.can_view_identity_providers(),
                'can_manage_sessions': self.can_manage_sessions(),
                'can_view_sessions': self.can_view_sessions(),
                'can_manage_events': self.can_manage_events(),
                'can_view_events': self.can_view_events(),
                'can_manage_attack_detection': self.can_manage_attack_detection(),
                'can_view_attack_detection': self.can_view_attack_detection(),
                'can_create_clients': self.can_create_clients(),
                'can_read_tokens': self.can_read_tokens(),
                'can_logout_all_users': self.can_logout_all_users(),
                'has_full_realm_admin_permissions': self.has_full_realm_admin_permissions(),
            }
        }

    # Django compatibility methods
    def has_perm(self, perm: str, obj: Any = None) -> bool:
        """Django compatibility - check permission"""
        # Map Django permissions to our role-based system
        perm_mapping = {
            'auth.add_user': self.can_manage_users(),
            'auth.change_user': self.can_manage_users(),
            'auth.delete_user': self.can_manage_users(),
            'auth.view_user': self.can_manage_users(),
            'app.add_task': self.can_manage_tasks(),
            'app.change_task': self.can_manage_tasks(),
            'app.delete_task': self.can_manage_tasks(),
            'app.view_task': self.can_manage_tasks(),
            'app.add_integration': self.can_manage_integrations(),
            'app.change_integration': self.can_manage_integrations(),
            'app.delete_integration': self.can_manage_integrations(),
            'app.view_integration': self.can_manage_integrations(),
        }
        return perm_mapping.get(perm, False)

    def has_module_perms(self, app_label: str) -> bool:
        """Django compatibility - check module permissions"""
        if app_label == 'auth':
            return self.can_manage_users()
        elif app_label == 'app':
            return True  # Basic access to app module
        return self.is_staff

    def __str__(self) -> str:
        return self.username or 'AnonymousUser'

    def __repr__(self) -> str:
        return f"StatelessUser(username='{self.username}', roles={self._roles})"


class AnonymousStatelessUser:
    """
    Anonymous user for unauthenticated requests
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

    def can_manage_users(self) -> bool:
        return False

    def can_manage_integrations(self) -> bool:
        return False

    def can_manage_tasks(self) -> bool:
        return False

    def can_execute_adhoc_tasks(self) -> bool:
        return False

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