# Keycloak Management Dashboard Guide

This comprehensive guide explains how to use the Keycloak Management Dashboard that provides a web interface for managing users, roles, and permissions in Keycloak.

## Overview

The Keycloak Management Dashboard is a pluggable Django application that provides:
- **User Management**: Create, list, update, and delete users
- **Role Management**: Create roles and assign them to users
- **Permission Management**: Define granular permissions and assign them to roles
- **Session Management**: View and manage active sessions
- **Global Logout**: Logout users from all devices

## Features

### 🔐 Authentication & Security
- Uses Keycloak for authentication
- Role-based access control
- Session management with global logout
- Cache-based session tracking (no database required)

### 👥 User Management
- Create new users with passwords
- Update user information
- Enable/disable user accounts
- Reset user passwords
- View user roles and permissions

### 🏷️ Role Management
- Create custom roles
- Assign roles to users
- View role assignments
- Role hierarchy support

### 🛡️ Permission Management
- Define granular permissions (manage_tasks, manage_integrations, manage_admin, etc.)
- Assign permissions to roles
- Composite role support
- Permissions included in JWT tokens

## Quick Start

### 1. Installation

Add the `keycloak_admin` app to your Django project:

```python
# settings.py
INSTALLED_APPS = [
    # ... other apps
    'keycloak_admin',
]

# Include the URLs
# urls.py
urlpatterns = [
    # ... other URLs
    path('keycloak-admin/', include('keycloak_admin.urls')),
]
```

### 2. Configuration

Ensure your Keycloak settings are configured:

```python
# settings.py
KEYCLOAK_SERVER_URL = 'http://your-keycloak-server:8080/'
KEYCLOAK_REALM = 'your-realm'
KEYCLOAK_CLIENT_ID = 'your-client'
KEYCLOAK_CLIENT_SECRET = 'your-client-secret'
```

### 3. Set Up Permissions

Run the management command to create the necessary roles and permissions:

```bash
python manage.py setup_keycloak_permissions
```

This will create:
- **Permissions**: manage_tasks, manage_integrations, manage_admin, view_reports, manage_users, manage_roles
- **Roles**: admin, manager, user
- **Role-Permission Assignments**: Appropriate permissions assigned to each role

### 4. Access the Dashboard

Navigate to `/keycloak-admin/` in your browser. Users with `admin` or `keycloak-admin` roles will have access.

## User Interface

### Dashboard Overview
The main dashboard provides:
- **Statistics**: Total users, roles, permissions
- **Recent Users**: List of recently created users
- **Recent Roles**: List of recently created roles
- **Quick Actions**: Shortcuts to common tasks

### User Management
- **User List**: View all users with pagination and search
- **User Details**: View user information and manage roles
- **Create User**: Create new users with passwords
- **User Actions**: Enable/disable, reset password, delete users

### Role Management
- **Role List**: View all roles and permissions
- **Create Role**: Create new roles with descriptions
- **Role Permissions**: View and manage permissions for each role
- **Delete Role**: Remove roles (with confirmation)

### Permission Management
- **Permission List**: View all available permissions
- **Create Permission**: Define new granular permissions
- **Permission Assignment**: Assign permissions to roles

## Permissions System

### Available Permissions

| Permission | Description |
|------------|-------------|
| `manage_tasks` | Can create, update, delete tasks |
| `manage_integrations` | Can configure and manage system integrations |
| `manage_admin` | Can access administrative functions |
| `view_reports` | Can view reports and analytics |
| `manage_users` | Can manage user accounts |
| `manage_roles` | Can manage roles and permissions |

### Role Hierarchy

| Role | Permissions |
|------|-------------|
| **admin** | All permissions |
| **manager** | manage_tasks, manage_integrations, view_reports |
| **user** | manage_tasks |

### JWT Token Claims

Permissions are included in JWT tokens under the `realm_access.roles` claim. Example:

```json
{
  "realm_access": {
    "roles": [
      "user",
      "permission_manage_tasks",
      "offline_access",
      "uma_authorization"
    ]
  }
}
```

## API Endpoints

The dashboard includes AJAX endpoints for real-time operations:

### User Role Management
- `POST /keycloak-admin/api/users/<user_id>/assign-role/`
- `POST /keycloak-admin/api/users/<user_id>/remove-role/`

### Permission Assignment
- `POST /keycloak-admin/api/roles/assign-permission/`

## Integration Guide

### 1. Check User Permissions in Django

```python
def my_view(request):
    user_info = request.session.get('user_info', {})
    user_roles = user_info.get('roles', [])

    # Check if user has specific permission
    if 'permission_manage_tasks' in user_roles:
        # User can manage tasks
        pass

    # Check if user has admin role
    if 'admin' in user_roles:
        # User is admin
        pass
```

### 2. Protect Views Based on Permissions

```python
from django.shortcuts import redirect

def admin_required(view_func):
    def wrapper(request, *args, **kwargs):
        user_info = request.session.get('user_info', {})
        user_roles = user_info.get('roles', [])

        if 'admin' not in user_roles:
            return redirect('dashboard')  # Or show permission denied

        return view_func(request, *args, **kwargs)
    return wrapper

@admin_required
def admin_only_view(request):
    # Only admins can access this view
    pass
```

### 3. Permission-Based UI Elements

```html
{% if 'permission_manage_users' in user_info.roles %}
<button onclick="showUserManagement()">Manage Users</button>
{% endif %}

{% if 'admin' in user_info.roles %}
<a href="/keycloak-admin/">Admin Dashboard</a>
{% endif %}
```

## Session Management

### Global Logout

The dashboard provides global logout functionality that:
1. Invalidates all Django sessions for the user
2. Attempts to revoke Keycloak sessions via Admin API
3. Records logout requests for audit purposes

### Session Validation

The session validation middleware checks:
- Session validity on each request
- Automatic redirect to login if session is invalid
- Support for multiple browser sessions

## Security Considerations

### Access Control
- Only users with `admin` or `keycloak-admin` roles can access the dashboard
- All operations are logged for audit purposes
- CSRF protection on all forms

### Session Security
- Sessions are tracked in cache (no database dependency)
- Automatic session expiration
- Secure session key generation

### API Security
- Admin API uses client credentials for authentication
- Token caching with automatic refresh
- Error handling for API failures

## Troubleshooting

### Common Issues

1. **"You don't have permission to access Keycloak administration"**
   - Ensure the user has `admin` or `keycloak-admin` role in Keycloak
   - Check that the role is properly assigned in the Keycloak Admin Console

2. **"Failed to get admin token"**
   - Verify KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET are correct
   - Ensure the client has `Service Accounts Enabled` in Keycloak
   - Check that the client has appropriate roles in Keycloak

3. **"Permission not found in JWT tokens"**
   - Run `python manage.py setup_keycloak_permissions`
   - Ensure the client has `roles` client scope assigned
   - Check Keycloak client configuration

4. **"Users not showing in list"**
   - Verify the Keycloak Admin API is accessible
   - Check the user's roles and permissions
   - Review server logs for API errors

### Logging

Enable debug logging to troubleshoot issues:

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'keycloak_admin': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
```

## Customization

### Adding New Permissions

1. Run the setup command with a custom management command
2. Assign permissions to roles as needed
3. Check permissions in your Django views

```python
# Example: Adding a new permission
from keycloak_admin.services import keycloak_admin

# Create permission
keycloak_admin.create_permission_role('new_permission', 'Description of new permission')

# Assign to role
keycloak_admin.assign_permission_to_role('manager', 'new_permission')
```

### Custom Templates

Override templates in your project:

```python
# settings.py
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        # ... other settings
    }
]
```

Create custom templates in `your_project/templates/keycloak_admin/`.

### Extending the Service

Extend the `KeycloakAdminService` for custom functionality:

```python
from keycloak_admin.services import KeycloakAdminService

class CustomKeycloakService(KeycloakAdminService):
    def custom_method(self):
        # Your custom logic
        pass
```

## Production Deployment

### Requirements

- Redis or similar cache backend for session tracking (LocMemCache works for development)
- Proper Keycloak configuration with service accounts
- HTTPS for production environments

### Environment Variables

```bash
export KEYCLOAK_SERVER_URL=https://your-keycloak.com/
export KEYCLOAK_REALM=production
export KEYCLOAK_CLIENT_ID=django-app
export KEYCLOAK_CLIENT_SECRET=your-secret-key
```

### Database Considerations

The system is designed to work without a database for session tracking. However, you can still use a database for other Django features if needed.

## API Reference

### KeycloakAdminService

#### User Management
- `get_users(max_results=100)` - List users
- `get_user(user_id)` - Get specific user
- `create_user(user_data)` - Create user
- `update_user(user_id, user_data)` - Update user
- `delete_user(user_id)` - Delete user
- `reset_password(user_id, password, temporary=False)` - Reset password

#### Role Management
- `get_roles()` - List roles
- `create_role(name, description)` - Create role
- `delete_role(name)` - Delete role
- `get_user_roles(user_id)` - Get user roles
- `assign_role_to_user(user_id, role_name)` - Assign role
- `remove_role_from_user(user_id, role_name)` - Remove role

#### Permission Management
- `get_permissions()` - List permissions
- `create_permission_role(name, description)` - Create permission
- `assign_permission_to_role(role_name, permission_name)` - Assign permission
- `get_role_permissions(role_name)` - Get role permissions

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review Django and Keycloak logs
3. Verify Keycloak configuration
4. Test API connectivity

## License

This Keycloak Management Dashboard is provided as-is for educational and development purposes. Please adapt it according to your production requirements.