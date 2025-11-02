from django.core.management.base import BaseCommand
from django.conf import settings
import requests
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old permissions from Keycloak and keep only the specified ones'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force cleanup of old permissions',
        )

    def handle(self, *args, **options):
        self.stdout.write("Cleaning up old Keycloak permissions...")

        try:
            # Get admin token
            admin_token = self._get_admin_token()
            if not admin_token:
                self.stdout.write(self.style.ERROR('Failed to get admin token'))
                return

            # Define which permissions to KEEP
            permissions_to_keep = [
                'permission_view_tasks',
                'permission_manage_tasks',
                'permission_view_integrations',
                'permission_manage_integrations',
                'permission_view_admin',
                'permission_manage_admin'
            ]

            # Get all current permissions
            current_permissions = self._get_all_permissions(admin_token)

            # Find permissions to delete
            permissions_to_delete = [
                perm for perm in current_permissions
                if perm['name'] not in permissions_to_keep
            ]

            self.stdout.write(f"Found {len(current_permissions)} total permissions")
            self.stdout.write(f"Keeping {len(permissions_to_keep)} specified permissions")
            self.stdout.write(f"Deleting {len(permissions_to_delete)} unwanted permissions")

            # First, remove permissions from all roles
            self.stdout.write("Removing permissions from roles...")
            all_roles = self._get_all_roles(admin_token)

            for role in all_roles:
                role_permissions = self._get_role_composite_permissions(admin_token, role['id'])
                permissions_to_remove = [
                    perm for perm in role_permissions
                    if perm not in permissions_to_keep
                ]

                if permissions_to_remove:
                    if self._remove_permissions_from_role(admin_token, role['id'], permissions_to_remove):
                        self.stdout.write(f"  ✓ Removed {len(permissions_to_remove)} permissions from role: {role['name']}")

            # Now delete the unwanted permissions
            self.stdout.write("Deleting unwanted permissions...")
            for permission in permissions_to_delete:
                if self._delete_permission(admin_token, permission['id']):
                    self.stdout.write(f"  ✓ Deleted permission: {permission['name']}")
                else:
                    self.stdout.write(f"  ✗ Failed to delete permission: {permission['name']}")

            self.stdout.write(self.style.SUCCESS('Permission cleanup completed!'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error during cleanup: {str(e)}'))
            logger.error(f"Error during permission cleanup: {e}")

    def _get_admin_token(self):
        """Get admin token from Keycloak"""
        keycloak_url = getattr(settings, 'KEYCLOAK_URL', 'http://localhost:8080')
        realm = getattr(settings, 'KEYCLOAK_REALM', 'teki_9')
        client_id = getattr(settings, 'KEYCLOAK_CLIENT_ID', 'admin-cli')
        client_secret = getattr(settings, 'KEYCLOAK_CLIENT_SECRET', 'admin-cli-secret')

        token_url = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token"

        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret
        }

        try:
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                return response.json()['access_token']
            else:
                logger.error(f"Failed to get admin token: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting admin token: {e}")
            return None

    def _get_all_permissions(self, admin_token):
        """Get all current permissions from Keycloak"""
        keycloak_url = getattr(settings, 'KEYCLOAK_URL', 'http://localhost:8080')
        realm = getattr(settings, 'KEYCLOAK_REALM', 'teki_9')

        roles_url = f"{keycloak_url}/admin/realms/{realm}/roles"
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.get(roles_url, headers=headers)
            if response.status_code == 200:
                all_roles = response.json()
                # Return only roles that start with 'permission_'
                return [role for role in all_roles if role['name'].startswith('permission_')]
            else:
                logger.error(f"Failed to get roles: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting roles: {e}")
            return []

    def _delete_permission(self, admin_token, permission_id):
        """Delete a permission from Keycloak"""
        keycloak_url = getattr(settings, 'KEYCLOAK_URL', 'http://localhost:8080')
        realm = getattr(settings, 'KEYCLOAK_REALM', 'teki_9')

        role_url = f"{keycloak_url}/admin/realms/{realm}/roles/{permission_id}"
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.delete(role_url, headers=headers)
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Error deleting permission {permission_id}: {e}")
            return False