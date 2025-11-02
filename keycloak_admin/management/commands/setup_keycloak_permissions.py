"""
Django management command to set up Keycloak roles and permissions.

This command creates the necessary roles and permissions for managing
tasks, integrations, and admin functions in Keycloak.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
import requests
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Set up Keycloak roles and permissions for task management'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recreation of existing roles and permissions',
        )

    def handle(self, *args, **options):
        self.stdout.write("Setting up Keycloak roles and permissions...")

        try:
            # Get admin token
            admin_token = self._get_admin_token()
            if not admin_token:
                self.stdout.write(self.style.ERROR('Failed to get admin token'))
                return

            # Define permissions to create
            permissions = [
                {
                    'name': 'view_tasks',
                    'description': 'Can view tasks and task lists'
                },
                {
                    'name': 'manage_tasks',
                    'description': 'Can create, update, delete tasks and manage task assignments'
                },
                {
                    'name': 'view_integrations',
                    'description': 'Can view system integrations and their status'
                },
                {
                    'name': 'manage_integrations',
                    'description': 'Can configure and manage system integrations'
                },
                {
                    'name': 'view_admin',
                    'description': 'Can view administrative functions and system settings'
                },
                {
                    'name': 'manage_admin',
                    'description': 'Can access and modify administrative functions and system settings'
                }
            ]

            # Define role-permission mappings
            role_permissions = {
                'admin': [
                    'view_tasks', 'manage_tasks', 'view_integrations', 'manage_integrations',
                    'view_admin', 'manage_admin'
                ],
                'manager': [
                    'view_tasks', 'manage_tasks', 'view_integrations', 'manage_integrations'
                ],
                'user': [
                    'view_tasks', 'manage_tasks'
                ]
            }

            # Create permissions (as roles with permission_ prefix)
            self.stdout.write("Creating permissions...")
            for permission in permissions:
                permission_role_name = f"permission_{permission['name']}"
                if self._create_role(admin_token, permission_role_name, permission['description'], options['force']):
                    self.stdout.write(f"  ✓ Created permission: {permission['name']}")
                else:
                    self.stdout.write(f"  ⚠ Permission {permission['name']} already exists")

            # Create roles and assign permissions
            self.stdout.write("Creating roles and assigning permissions...")
            for role_name, permission_names in role_permissions.items():
                # Create the role
                if self._create_role(admin_token, role_name, f"Role: {role_name}", options['force']):
                    self.stdout.write(f"  ✓ Created role: {role_name}")
                else:
                    self.stdout.write(f"  ⚠ Role {role_name} already exists")

                # Get role ID
                role_id = self._get_role_id(admin_token, role_name)
                if role_id:
                    # Assign permissions to role
                    for permission_name in permission_names:
                        permission_role_name = f"permission_{permission_name}"
                        permission_role_id = self._get_role_id(admin_token, permission_role_name)
                        if permission_role_id:
                            if self._assign_composite_role(admin_token, role_id, permission_role_id):
                                self.stdout.write(f"    ✓ Assigned permission {permission_name} to role {role_name}")
                            else:
                                self.stdout.write(f"    ⚠ Permission {permission_name} already assigned to role {role_name}")

            # Configure client to include permissions in token
            self.stdout.write("Configuring client token claims...")
            if self._configure_client_claims(admin_token):
                self.stdout.write("  ✓ Configured client to include permissions in JWT tokens")
            else:
                self.stdout.write("  ⚠ Failed to configure client claims (may need manual configuration)")

            self.stdout.write(self.style.SUCCESS('Setup completed successfully!'))
            self.stdout.write("\nNext steps:")
            self.stdout.write("1. Assign roles to users through the Keycloak Admin Dashboard")
            self.stdout.write("2. Test login and check that permissions appear in JWT tokens")
            self.stdout.write("3. Access the Keycloak Admin Dashboard at /keycloak-admin/")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error during setup: {e}'))
            logger.exception("Error during Keycloak setup")

    def _get_admin_token(self):
        """Get admin token from Keycloak"""
        try:
            token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            }

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

    def _create_role(self, admin_token, role_name, description, force=False):
        """Create a role in Keycloak"""
        try:
            # Check if role already exists
            if not force and self._get_role_id(admin_token, role_name):
                return False

            role_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/roles"
            role_data = {
                'name': role_name,
                'description': description
            }

            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            response = requests.post(role_url, json=role_data, headers=headers)
            return response.status_code in [201, 409]  # 201 created, 409 conflict (exists)

        except Exception as e:
            logger.error(f"Error creating role {role_name}: {e}")
            return False

    def _get_role_id(self, admin_token, role_name):
        """Get role ID by name"""
        try:
            role_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/roles/{role_name}"
            headers = {'Authorization': f'Bearer {admin_token}'}

            response = requests.get(role_url, headers=headers)
            if response.status_code == 200:
                role_data = response.json()
                return role_data.get('id')
            return None

        except Exception as e:
            logger.error(f"Error getting role ID for {role_name}: {e}")
            return None

    def _assign_composite_role(self, admin_token, role_id, composite_role_id):
        """Assign a composite role to a role"""
        try:
            composite_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/roles/{role_id}/composites"
            composite_data = [{'id': composite_role_id}]

            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            response = requests.post(composite_url, json=composite_data, headers=headers)
            return response.status_code in [204, 409]  # 204 success, 409 already exists

        except Exception as e:
            logger.error(f"Error assigning composite role: {e}")
            return False

    def _configure_client_claims(self, admin_token):
        """Configure client to include realm roles and permissions in JWT tokens"""
        try:
            # Get client ID
            clients_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/clients"
            headers = {'Authorization': f'Bearer {admin_token}'}

            response = requests.get(clients_url, headers=headers)
            if response.status_code != 200:
                return False

            clients = response.json()
            client = None
            for c in clients:
                if c['clientId'] == settings.KEYCLOAK_CLIENT_ID:
                    client = c
                    break

            if not client:
                logger.error("Client not found")
                return False

            # Update client configuration
            client_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/clients/{client['id']}"

            # Configure default client scopes to include roles
            client_scopes_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/clients/{client['id']}/default-client-scopes"

            # Get available client scopes
            scopes_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/client-scopes"
            scopes_response = requests.get(scopes_url, headers=headers)

            if scopes_response.status_code == 200:
                scopes = scopes_response.json()

                # Find and assign roles scope
                roles_scope = None
                for scope in scopes:
                    if scope['name'] == 'roles':
                        roles_scope = scope
                        break

                if roles_scope:
                    # Assign roles scope to client
                    assign_data = [{'id': roles_scope['id'], 'name': 'roles'}]
                    assign_response = requests.put(client_scopes_url, json=assign_data, headers=headers)

                    if assign_response.status_code == 204:
                        return True

            return False

        except Exception as e:
            logger.error(f"Error configuring client claims: {e}")
            return False