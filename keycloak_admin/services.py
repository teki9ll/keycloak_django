"""
Keycloak Admin API Service

This service handles all interactions with Keycloak's Admin API for managing
users, roles, and permissions. It provides a clean interface for Django
applications to manage Keycloak resources.
"""

import requests
import json
import time
import logging
from django.conf import settings
from django.core.cache import cache
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class KeycloakAdminService:
    """
    Service class for interacting with Keycloak Admin API.

    This service provides methods for managing users, roles, and permissions
    in Keycloak through the Admin REST API.
    """

    def __init__(self):
        self.server_url = settings.KEYCLOAK_SERVER_URL.rstrip('/')
        self.realm = settings.KEYCLOAK_REALM
        self.client_id = settings.KEYCLOAK_CLIENT_ID
        self.client_secret = settings.KEYCLOAK_CLIENT_SECRET
        self._admin_token = None
        self._token_expires_at = 0

    def _get_admin_token(self) -> Optional[str]:
        """
        Get admin access token using client credentials grant.

        Returns:
            Admin access token or None if failed
        """
        try:
            # Check if we have a valid cached token
            current_time = int(time.time())
            if self._admin_token and current_time < self._token_expires_at:
                return self._admin_token

            # Request new admin token
            token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

            token_data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            }

            response = requests.post(token_url, data=token_data)
            if response.status_code == 200:
                token_info = response.json()
                self._admin_token = token_info.get('access_token')
                expires_in = token_info.get('expires_in', 300)
                self._token_expires_at = current_time + expires_in - 60  # Refresh 1 minute early

                logger.info("Successfully obtained Keycloak admin token")
                return self._admin_token
            else:
                logger.error(f"Failed to get admin token: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error getting admin token: {e}")
            return None

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        """
        Make authenticated request to Keycloak Admin API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without base URL)
            **kwargs: Additional arguments for requests

        Returns:
            Response object or None if failed
        """
        token = self._get_admin_token()
        if not token:
            logger.error("Cannot make request: No admin token available")
            return None

        try:
            url = f"{self.server_url}/admin/realms/{self.realm}/{endpoint}"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                **kwargs.pop('headers', {})
            }

            response = requests.request(method, url, headers=headers, **kwargs)

            if response.status_code == 401:
                # Token might be expired, try to refresh and retry once
                self._admin_token = None
                token = self._get_admin_token()
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                    response = requests.request(method, url, headers=headers, **kwargs)

            return response

        except Exception as e:
            logger.error(f"Error making request to {endpoint}: {e}")
            return None

    # User Management Methods

    def get_users(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get list of users from Keycloak.

        Args:
            max_results: Maximum number of users to return

        Returns:
            List of user dictionaries
        """
        try:
            response = self._make_request('GET', f'users?max={max_results}')
            if response and response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get specific user by ID.

        Args:
            user_id: Keycloak user ID

        Returns:
            User dictionary or None if not found
        """
        try:
            response = self._make_request('GET', f'users/{user_id}')
            if response and response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None

    def create_user(self, user_data: Dict[str, Any]) -> Optional[str]:
        """
        Create a new user in Keycloak.

        Args:
            user_data: Dictionary containing user information

        Returns:
            User ID if successful, None otherwise
        """
        try:
            response = self._make_request('POST', 'users', json=user_data)
            if response and response.status_code == 201:
                # Extract user ID from Location header
                location = response.headers.get('Location', '')
                user_id = location.split('/')[-1] if location else None
                logger.info(f"Created user with ID: {user_id}")
                return user_id
            else:
                logger.error(f"Failed to create user: {response.status_code if response else 'No response'}")
                if response:
                    logger.error(f"Response: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """
        Update existing user.

        Args:
            user_id: Keycloak user ID
            user_data: Updated user information

        Returns:
            True if successful, False otherwise
        """
        try:
            response = self._make_request('PUT', f'users/{user_id}', json=user_data)
            if response and response.status_code == 204:
                logger.info(f"Updated user {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False

    def delete_user(self, user_id: str) -> bool:
        """
        Delete user from Keycloak.

        Args:
            user_id: Keycloak user ID

        Returns:
            True if successful, False otherwise
        """
        try:
            response = self._make_request('DELETE', f'users/{user_id}')
            if response and response.status_code == 204:
                logger.info(f"Deleted user {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return False

    def reset_password(self, user_id: str, password: str, temporary: bool = False) -> bool:
        """
        Reset user password.

        Args:
            user_id: Keycloak user ID
            password: New password
            temporary: Whether password should be temporary

        Returns:
            True if successful, False otherwise
        """
        try:
            password_data = {
                'type': 'password',
                'value': password,
                'temporary': temporary
            }
            response = self._make_request('PUT', f'users/{user_id}/reset-password', json=password_data)
            if response and response.status_code == 204:
                logger.info(f"Reset password for user {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error resetting password for user {user_id}: {e}")
            return False

    # Role Management Methods

    def get_roles(self) -> List[Dict[str, Any]]:
        """
        Get all roles from Keycloak.

        Returns:
            List of role dictionaries
        """
        try:
            response = self._make_request('GET', 'roles')
            if response and response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error getting roles: {e}")
            return []

    def create_role(self, role_name: str, description: str = "") -> Optional[Dict[str, Any]]:
        """
        Create a new role in Keycloak.

        Args:
            role_name: Name of the role
            description: Role description

        Returns:
            Created role dictionary or None if failed
        """
        try:
            role_data = {
                'name': role_name,
                'description': description
            }
            response = self._make_request('POST', 'roles', json=role_data)
            if response and response.status_code == 201:
                logger.info(f"Created role: {role_name}")
                return {'name': role_name, 'description': description}
            return None
        except Exception as e:
            logger.error(f"Error creating role {role_name}: {e}")
            return None

    def delete_role(self, role_name: str) -> bool:
        """
        Delete role from Keycloak.

        Args:
            role_name: Name of the role

        Returns:
            True if successful, False otherwise
        """
        try:
            response = self._make_request('DELETE', f'roles/{role_name}')
            if response and response.status_code == 204:
                logger.info(f"Deleted role: {role_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting role {role_name}: {e}")
            return False

    def get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get roles assigned to a specific user.

        Args:
            user_id: Keycloak user ID

        Returns:
            List of role dictionaries
        """
        try:
            response = self._make_request('GET', f'users/{user_id}/role-mappings/realm')
            if response and response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error getting roles for user {user_id}: {e}")
            return []

    def assign_role_to_user(self, user_id: str, role_name: str) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: Keycloak user ID
            role_name: Name of the role

        Returns:
            True if successful, False otherwise
        """
        try:
            # First get the role representation
            response = self._make_request('GET', f'roles/{role_name}')
            if response and response.status_code == 200:
                role_data = response.json()
                # Assign role to user
                response = self._make_request(
                    'POST',
                    f'users/{user_id}/role-mappings/realm',
                    json=[role_data]
                )
                if response and response.status_code == 204:
                    logger.info(f"Assigned role {role_name} to user {user_id}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error assigning role {role_name} to user {user_id}: {e}")
            return False

    def remove_role_from_user(self, user_id: str, role_name: str) -> bool:
        """
        Remove a role from a user.

        Args:
            user_id: Keycloak user ID
            role_name: Name of the role

        Returns:
            True if successful, False otherwise
        """
        try:
            # First get the role representation
            response = self._make_request('GET', f'roles/{role_name}')
            if response and response.status_code == 200:
                role_data = response.json()
                # Remove role from user
                response = self._make_request(
                    'DELETE',
                    f'users/{user_id}/role-mappings/realm',
                    json=[role_data]
                )
                if response and response.status_code == 204:
                    logger.info(f"Removed role {role_name} from user {user_id}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error removing role {role_name} from user {user_id}: {e}")
            return False

    # Permission Management Methods (using client scopes and roles)

    def create_permission_role(self, permission_name: str, description: str = "") -> Optional[Dict[str, Any]]:
        """
        Create a permission role (using roles as permissions).

        Args:
            permission_name: Name of the permission
            description: Permission description

        Returns:
            Created permission role dictionary or None if failed
        """
        # Prefix permission roles to distinguish them
        role_name = f"permission_{permission_name}"
        return self.create_role(role_name, description)

    def get_permissions(self) -> List[Dict[str, Any]]:
        """
        Get all permission roles.

        Returns:
            List of permission role dictionaries
        """
        all_roles = self.get_roles()
        # Filter roles that start with 'permission_'
        permission_roles = [
            {
                'name': role['name'].replace('permission_', ''),
                'full_name': role['name'],
                'description': role.get('description', '')
            }
            for role in all_roles
            if role['name'].startswith('permission_')
        ]
        return permission_roles

    def assign_permission_to_role(self, role_name: str, permission_name: str) -> bool:
        """
        Assign a permission to a role by creating composite role.

        Args:
            role_name: Name of the role
            permission_name: Name of the permission

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get both roles
            role_response = self._make_request('GET', f'roles/{role_name}')
            permission_response = self._make_request('GET', f'roles/permission_{permission_name}')

            if (role_response and role_response.status_code == 200 and
                permission_response and permission_response.status_code == 200):

                role_data = role_response.json()
                permission_data = permission_response.json()

                # Make the role a composite role by adding the permission role
                composite_response = self._make_request(
                    'POST',
                    f'roles/{role_name}/composites',
                    json=[permission_data]
                )

                if composite_response and composite_response.status_code == 204:
                    logger.info(f"Assigned permission {permission_name} to role {role_name}")
                    return True

            return False
        except Exception as e:
            logger.error(f"Error assigning permission {permission_name} to role {role_name}: {e}")
            return False

    def get_role_permissions(self, role_name: str) -> List[Dict[str, Any]]:
        """
        Get all permissions assigned to a role.

        Args:
            role_name: Name of the role

        Returns:
            List of permission dictionaries
        """
        try:
            response = self._make_request('GET', f'roles/{role_name}/composites')
            if response and response.status_code == 200:
                composites = response.json()
                # Filter for permission roles
                permissions = [
                    {
                        'name': composite['name'].replace('permission_', ''),
                        'description': composite.get('description', '')
                    }
                    for composite in composites
                    if composite['name'].startswith('permission_')
                ]
                return permissions
            return []
        except Exception as e:
            logger.error(f"Error getting permissions for role {role_name}: {e}")
            return []

    def _assign_role_to_user(self, user_id: str, role_id: str) -> bool:
        """
        Assign a role directly to a user.

        Args:
            user_id: The user's ID in Keycloak
            role_id: The role ID to assign

        Returns:
            True if successful, False otherwise
        """
        try:
            response = self._make_request(
                'POST',
                f'users/{user_id}/role-mappings/realm',
                json=[{'id': role_id}]
            )
            return response and response.status_code == 204
        except Exception as e:
            logger.error(f"Error assigning role to user {user_id}: {e}")
            return False

    def _get_role_id(self, role_name: str) -> str:
        """
        Get the ID of a role by name.

        Args:
            role_name: The name of the role

        Returns:
            The role ID or None if not found
        """
        try:
            response = self._make_request('GET', f'roles/{role_name}')
            if response and response.status_code == 200:
                return response.json().get('id')
            return None
        except Exception as e:
            logger.error(f"Error getting role ID for {role_name}: {e}")
            return None

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """
        Get user details by ID.

        Args:
            user_id: The user's ID

        Returns:
            User dictionary or None if not found
        """
        try:
            response = self._make_request('GET', f'users/{user_id}')
            if response and response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None


# Global instance for use across the application
keycloak_admin = KeycloakAdminService()