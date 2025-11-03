"""
Keycloak Admin Dashboard Views

This module provides Django views for managing Keycloak users, roles, and permissions
through a web interface. These views can be easily integrated into any Django project.
"""

import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from functools import wraps

from .services import keycloak_admin
from .forms import UserForm, RoleForm, PermissionForm, UserRoleForm
from app.decorators import track_user_activity

logger = logging.getLogger(__name__)


def track_admin_session(view_func):
    """
    Decorator to ensure admin sessions are tracked in cache.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_info'):
            return redirect('login')

        user_info = request.session.get('user_info', {})
        user_roles = user_info.get('roles', [])

        # Check if user has admin permissions
        has_admin_access = any(role in ['admin', 'keycloak-admin'] for role in user_roles)

        if not has_admin_access:
            messages.error(request, "You don't have permission to access Keycloak administration.")
            return redirect('dashboard')

        # Ensure session is tracked in cache for admin users
        try:
            from app.session_manager import SessionManager
            session_key = request.session.session_key

            # Only track if not already tracked
            if not SessionManager._is_session_cached(session_key):
                SessionManager.create_session(request, user_info)
                logger.info(f"Tracked admin session for user: {user_info.get('username')}")
        except Exception as e:
            logger.error(f"Error tracking admin session: {e}")
            # Continue even if tracking fails

        return view_func(request, *args, **kwargs)
    return wrapper


# Mixins for permission checking
class KeycloakAdminRequiredMixin:
    """
    Mixin to check if user has Keycloak admin permissions.
    """
    def dispatch(self, request, *args, **kwargs):
        if not request.session.get('user_info'):
            return redirect('login')

        user_info = request.session.get('user_info', {})
        user_roles = user_info.get('roles', [])

        # Check if user has admin permission roles
        has_admin_access = any(role in ['view_admin', 'manage_admin'] for role in user_roles)

        if not has_admin_access:
            messages.error(request, "You don't have permission to access the admin panel. Please contact an administrator to get the required permissions (view_admin or manage_admin).")
            return redirect('dashboard')

        return super().dispatch(request, *args, **kwargs)


# Permission-based Decorators
def get_client_ip(request):
    """
    Get the client's IP address from the request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def require_view_admin_permission(view_func):
    """
    Decorator to ensure user has view_admin permission.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_info'):
            return redirect('login')

        user_info = request.session.get('user_info', {})
        user_roles = user_info.get('roles', [])

        # Check if user has view_admin permission (only permission roles, not Keycloak admin roles)
        has_view_permission = (
            any(role == 'view_admin' for role in user_roles) or
            any(role == 'permission_view_admin' for role in user_roles) or
            any(role == 'manage_admin' for role in user_roles) or
            any(role == 'permission_manage_admin' for role in user_roles)  # manage_admin implies view_admin
        )

        if not has_view_permission:
            messages.error(request, "You don't have permission to access the admin panel. Please contact an administrator to get the required permissions (view_admin or manage_admin).")
            return redirect('dashboard')

        # Ensure session is tracked in cache for admin users
        try:
            from app.session_manager import SessionManager
            session_key = request.session.session_key

            # Only track if not already tracked
            if not SessionManager._is_session_cached(session_key):
                SessionManager.create_session(request, user_info)
                logger.info(f"Tracked admin session for user: {user_info.get('username')}")
        except Exception as e:
            logger.error(f"Error tracking admin session: {e}")
            # Continue even if tracking fails

        return view_func(request, *args, **kwargs)

    return wrapper


def require_manage_admin_permission(view_func):
    """
    Decorator to ensure user has manage_admin permission for CRUD operations.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_info'):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Authentication required'}, status=401)
            return redirect('login')

        user_info = request.session.get('user_info', {})
        user_roles = user_info.get('roles', [])

        # Check if user has manage_admin permission (only permission roles)
        has_manage_permission = (
            any(role == 'manage_admin' for role in user_roles) or
            any(role == 'permission_manage_admin' for role in user_roles)
        )

        if not has_manage_permission:
            error_message = "You don't have permission to perform administrative operations."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': error_message}, status=403)
            messages.error(request, error_message)
            return redirect('keycloak_admin:dashboard')

        return view_func(request, *args, **kwargs)

    return wrapper


# Dashboard Views
@require_view_admin_permission
@track_user_activity
def keycloak_dashboard(request):
    """
    Main Keycloak administration dashboard with consolidated user management.
    """
    user_info = request.session.get('user_info', {})

    try:
        # Get statistics
        all_users = keycloak_admin.get_users()
        all_roles = keycloak_admin.get_roles()
        all_permissions = keycloak_admin.get_permissions()

        stats = {
            'total_users': len(all_users),
            'total_roles': len(all_roles),
            'total_permissions': len(all_permissions),
        }

        # Get all users with session status and permissions
        from app.session_manager import SessionManager

        # Add session status and permissions to each user
        users_with_status = []
        for user in all_users:
            user_id = user.get('id', '')
            username = user.get('username', '')

            # Get user sessions from unified session manager
            user_sessions = SessionManager.get_user_sessions(user_id=user_id, username=username)

            # Get user roles/permissions
            user_roles = keycloak_admin.get_user_roles(user_id)
            user_permissions = [
                role['name'].replace('permission_', '')
                for role in user_roles
                if role['name'].startswith('permission_')
            ]

            # Check if user is currently online (active in last 5 minutes)
            current_time = timezone.now().timestamp()
            is_online = False
            last_activity = None
            ip_address = None
            session_count = len(user_sessions)

            if user_sessions:
                # Sort by last_activity to get the most recent session
                user_sessions.sort(key=lambda x: x.get('last_accessed', 0), reverse=True)
                latest_session = user_sessions[0]
                last_activity = latest_session.get('last_accessed')
                ip_address = latest_session.get('ip_address')

                # Consider user online if last activity was within 5 minutes
                if last_activity and (current_time - last_activity) < 300:
                    is_online = True

            user_with_status = {
                **user,
                'is_online': is_online,
                'last_session': last_activity,
                'ip_address': ip_address,
                'session_count': session_count,
                'permissions': user_permissions,
            }
            users_with_status.append(user_with_status)

        # Get online users count (total sessions, not unique users)
        online_users_count = sum(user['session_count'] for user in users_with_status if user['is_online'])

        # Get current user's permissions (only permission roles)
        current_user_roles = user_info.get('roles', [])
        current_user_permissions = [
            role for role in current_user_roles
            if role in ['view_admin', 'manage_admin', 'permission_view_admin', 'permission_manage_admin']
        ]

        context = {
            'stats': stats,
            'users': users_with_status,
            'online_users_count': online_users_count,
            'available_permissions': all_permissions,
            'current_user_permissions': current_user_permissions,
            'can_manage_admin': any(role in ['manage_admin', 'permission_manage_admin'] for role in current_user_roles),
            'has_view_admin': any(role in ['view_admin', 'manage_admin', 'permission_view_admin', 'permission_manage_admin'] for role in current_user_roles),
            'page_title': 'Easytask User Management',
        }

        return render(request, 'keycloak_admin/dashboard.html', context)

    except Exception as e:
        logger.error(f"Error loading Keycloak dashboard: {e}")
        messages.error(request, "Error loading administration dashboard.")
        return redirect('dashboard')


@require_manage_admin_permission
@require_http_methods(["POST"])
def logout_user(request, user_id):
    """
    Logout a specific user from their session.
    """
    try:
        # Get current user info for permission check
        current_user_info = request.session.get('user_info', {})
        current_user_id = current_user_info.get('sub')
        current_user_roles = current_user_info.get('roles', [])

        # Check if user has admin permissions
        has_admin_permission = any(role in ['admin', 'manage_admin'] for role in current_user_roles)
        if not has_admin_permission:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Permission denied'}, status=403)
            messages.error(request, "You don't have permission to logout other users.")
            return redirect('keycloak_admin:dashboard')

        # Prevent self-logout
        if user_id == current_user_id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Cannot logout yourself'}, status=400)
            messages.error(request, "You cannot logout yourself from this panel.")
            return redirect('keycloak_admin:dashboard')

        # Remove user sessions using unified session manager
        from app.session_manager import SessionManager

        # Get username for the user
        user_info = request.session.get('user_info', {})
        current_username = user_info.get('username', '')

        # Logout all sessions for the target user
        try:
            # Find the target user's username
            target_username = None
            all_users = keycloak_admin.get_users()
            for user in all_users:
                if user.get('id') == user_id:
                    target_username = user.get('username')
                    break

            if target_username:
                sessions_invalidated = SessionManager.logout_user(user_id, target_username, request=request)
                logger.info(f"Invalidated {sessions_invalidated} sessions for user {target_username}")
        except Exception as e:
            logger.error(f"Error logging out user sessions: {e}")

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': 'User logged out successfully'})

        messages.success(request, "User has been logged out successfully.")
        return redirect('keycloak_admin:dashboard')

    except Exception as e:
        logger.error(f"Error logging out user {user_id}: {e}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': 'Failed to logout user'}, status=500)
        messages.error(request, "Failed to logout user.")
        return redirect('keycloak_admin:dashboard')


# User Management Views
@track_admin_session
@track_user_activity
def user_list(request):
    """
    List all users in Keycloak and handle user creation.
    """
    # Get available permissions for the form
    try:
        permissions = keycloak_admin.get_permissions()
        permission_choices = [(perm['name'], perm['name']) for perm in permissions]
    except Exception as e:
        logger.error(f"Error getting permissions: {e}")
        permission_choices = []

    form = UserForm()  # Initialize form for GET requests
    form.fields['permissions'].choices = permission_choices

    if request.method == 'POST':
        form = UserForm(request.POST)
        form.fields['permissions'].choices = permission_choices  # Set choices for POST form

        if form.is_valid():
            try:
                user_data = {
                    'username': form.cleaned_data['username'],
                    'email': form.cleaned_data['email'],
                    'firstName': form.cleaned_data['first_name'],
                    'lastName': form.cleaned_data['last_name'],
                    'enabled': form.cleaned_data.get('enabled', True),
                    'emailVerified': True,  # Always verified by default
                }

                # Add password if provided
                if form.cleaned_data.get('password'):
                    user_data['credentials'] = [{
                        'type': 'password',
                        'value': form.cleaned_data['password'],
                        'temporary': False  # Never temporary
                    }]

                user_id = keycloak_admin.create_user(user_data)
                if user_id:
                    # Assign permissions to the user
                    selected_permissions = form.cleaned_data.get('permissions', [])
                    if selected_permissions:
                        try:
                            # Get user info to find their ID
                            user_info = keycloak_admin.get_user(user_id)
                            if user_info:
                                # Assign each permission directly to the user
                                for permission_name in selected_permissions:
                                    # Find the permission role ID
                                    permission_role_id = keycloak_admin._get_role_id(f"permission_{permission_name}")
                                    if permission_role_id:
                                        # Assign permission role directly to user
                                        keycloak_admin._assign_role_to_user(user_id, permission_role_id)
                                        logger.info(f"Assigned permission {permission_name} to user {user_data['username']}")
                        except Exception as perm_error:
                            logger.error(f"Error assigning permissions: {perm_error}")
                            # Don't fail the user creation if permission assignment fails
                            messages.warning(request, f"User created but some permissions may not have been assigned: {str(perm_error)}")

                    messages.success(request, f"User '{form.cleaned_data['username']}' created successfully.")
                    form = UserForm()  # Reset form after successful creation
                    form.fields['permissions'].choices = permission_choices  # Re-set choices for new form
                else:
                    messages.error(request, "Failed to create user in Keycloak.")

            except Exception as e:
                logger.error(f"Error creating user: {e}")
                messages.error(request, f"Error creating user: {str(e)}")

    try:
        users = keycloak_admin.get_users(100)  # Get up to 100 users

        # Pagination
        paginator = Paginator(users, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'page_obj': page_obj,
            'form': form,
            'page_title': 'User Management - Keycloak Admin',
        }

        return render(request, 'keycloak_admin/users/list.html', context)

    except Exception as e:
        logger.error(f"Error listing users: {e}")
        messages.error(request, "Error loading users.")
        return redirect('keycloak_admin:dashboard')


@track_admin_session
def user_create(request):
    """
    Create a new user in Keycloak.
    """

    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            try:
                user_data = {
                    'username': form.cleaned_data['username'],
                    'email': form.cleaned_data['email'],
                    'firstName': form.cleaned_data['first_name'],
                    'lastName': form.cleaned_data['last_name'],
                    'enabled': form.cleaned_data.get('enabled', True),
                    'emailVerified': True,  # Always verified by default
                }

                # Add password if provided
                if form.cleaned_data.get('password'):
                    user_data['credentials'] = [{
                        'type': 'password',
                        'value': form.cleaned_data['password'],
                        'temporary': False  # Never temporary
                    }]

                user_id = keycloak_admin.create_user(user_data)
                if user_id:
                    messages.success(request, f"User '{form.cleaned_data['username']}' created successfully.")
                    return redirect('keycloak_admin:user_list')
                else:
                    messages.error(request, "Failed to create user in Keycloak.")

            except Exception as e:
                logger.error(f"Error creating user: {e}")
                messages.error(request, f"Error creating user: {str(e)}")
    else:
        form = UserForm()

    context = {
        'form': form,
        'page_title': 'Create User - Keycloak Admin',
        'action': 'Create',
    }

    return render(request, 'keycloak_admin/users/form.html', context)


def user_detail(request, user_id):
    """
    Show user details and manage their roles.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    try:
        user = keycloak_admin.get_user(user_id)
        if not user:
            messages.error(request, "User not found.")
            return redirect('keycloak_admin:user_list')

        # Get user roles
        user_roles = keycloak_admin.get_user_roles(user_id)

        # Get all available roles for assignment
        all_roles = keycloak_admin.get_roles()
        available_roles = [role for role in all_roles if role not in user_roles]

        # Get current user info for security checks
        current_user_info = request.session.get('user_info', {})
        current_user_id = current_user_info.get('sub')
        current_user_roles = current_user_info.get('roles', [])
        current_is_admin = any(role in ['admin', 'keycloak-admin'] for role in current_user_roles)

        # Check if target user is admin
        target_is_admin = any(role in ['admin', 'keycloak-admin'] for role in user_roles)
        is_own_profile = user_id == current_user_id

        context = {
            'user': user,
            'user_roles': user_roles,
            'available_roles': available_roles,
            'current_user_id': current_user_id,
            'current_user_roles': current_user_roles,
            'current_is_admin': current_is_admin,
            'target_is_admin': target_is_admin,
            'is_own_profile': is_own_profile,
            'page_title': f"User {user.get('username', 'Unknown')} - Keycloak Admin",
        }

        return render(request, 'keycloak_admin/users/detail.html', context)

    except Exception as e:
        logger.error(f"Error getting user details: {e}")
        messages.error(request, "Error loading user details.")
        return redirect('keycloak_admin:user_list')


def user_delete(request, user_id):
    """
    Delete a user from Keycloak with security checks.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    # Get current logged-in user info
    current_user_info = request.session.get('user_info', {})
    current_user_id = current_user_info.get('sub')  # Keycloak user ID
    current_user_roles = current_user_info.get('roles', [])

    if request.method == 'POST':
        try:
            user = keycloak_admin.get_user(user_id)
            if not user:
                messages.error(request, "User not found.")
                return redirect('keycloak_admin:user_list')

            # Security Check 1: Prevent self-deletion
            if user_id == current_user_id:
                messages.error(request, "You cannot delete your own account.")
                logger.warning(f"User {current_user_info.get('username')} attempted to delete their own account.")
                return redirect('keycloak_admin:user_detail', user_id=user_id)

            # Security Check 2: Prevent deletion of other admins
            target_user_roles = keycloak_admin.get_user_roles(user_id)
            target_is_admin = any(role in ['admin', 'keycloak-admin'] for role in target_user_roles)
            current_is_admin = any(role in ['admin', 'keycloak-admin'] for role in current_user_roles)

            if target_is_admin and current_is_admin:
                messages.error(request, "You cannot delete another admin user. First remove their admin role.")
                logger.warning(f"Admin {current_user_info.get('username')} attempted to delete admin {user.get('username')}.")
                return redirect('keycloak_admin:user_detail', user_id=user_id)

            # Proceed with deletion if security checks pass
            if keycloak_admin.delete_user(user_id):
                messages.success(request, f"User '{user.get('username', 'Unknown')}' deleted successfully.")
                logger.info(f"User {current_user_info.get('username')} deleted user {user.get('username')}.")
            else:
                messages.error(request, "Failed to delete user from Keycloak.")

        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            messages.error(request, f"Error deleting user: {str(e)}")

    return redirect('keycloak_admin:user_list')


# Role Management Views
def role_list(request):
    """
    List all roles in Keycloak.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    try:
        roles = keycloak_admin.get_roles()

        # Separate regular roles and permission roles
        regular_roles = [role for role in roles if not role['name'].startswith('permission_')]
        permission_roles = [
            {
                'name': role['name'].replace('permission_', ''),
                'description': role.get('description', ''),
                'original_name': role['name']
            }
            for role in roles if role['name'].startswith('permission_')
        ]

        context = {
            'regular_roles': regular_roles,
            'permission_roles': permission_roles,
            'page_title': 'Roles - Keycloak Admin',
        }

        return render(request, 'keycloak_admin/roles/list.html', context)

    except Exception as e:
        logger.error(f"Error listing roles: {e}")
        messages.error(request, "Error loading roles.")
        return redirect('keycloak_admin:dashboard')


def role_create(request):
    """
    Create a new role in Keycloak.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            try:
                role = keycloak_admin.create_role(
                    form.cleaned_data['name'],
                    form.cleaned_data.get('description', '')
                )

                if role:
                    messages.success(request, f"Role '{form.cleaned_data['name']}' created successfully.")
                    return redirect('keycloak_admin:role_list')
                else:
                    messages.error(request, "Failed to create role in Keycloak.")

            except Exception as e:
                logger.error(f"Error creating role: {e}")
                messages.error(request, f"Error creating role: {str(e)}")
    else:
        form = RoleForm()

    context = {
        'form': form,
        'page_title': 'Create Role - Keycloak Admin',
        'action': 'Create',
    }

    return render(request, 'keycloak_admin/roles/form.html', context)


def role_delete(request, role_name):
    """
    Delete a role from Keycloak.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    if request.method == 'POST':
        try:
            if keycloak_admin.delete_role(role_name):
                messages.success(request, f"Role '{role_name}' deleted successfully.")
            else:
                messages.error(request, "Failed to delete role from Keycloak.")

        except Exception as e:
            logger.error(f"Error deleting role: {e}")
            messages.error(request, f"Error deleting role: {str(e)}")

    return redirect('keycloak_admin:role_list')


# Permission Management Views
def permission_list(request):
    """
    List all permissions in Keycloak.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    try:
        permissions = keycloak_admin.get_permissions()

        context = {
            'permissions': permissions,
            'page_title': 'Permissions - Keycloak Admin',
        }

        return render(request, 'keycloak_admin/permissions/list.html', context)

    except Exception as e:
        logger.error(f"Error listing permissions: {e}")
        messages.error(request, "Error loading permissions.")
        return redirect('keycloak_admin:dashboard')




# User-Role Assignment Views
@csrf_exempt
@require_http_methods(["POST"])
def assign_role_to_user(request, user_id):
    """
    Assign a role to a user (AJAX endpoint).
    """
    if not request.session.get('user_info'):
        return JsonResponse({'success': False, 'error': 'Not authenticated'})

    try:
        data = json.loads(request.body)
        role_name = data.get('role_name')

        if keycloak_admin.assign_role_to_user(user_id, role_name):
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Failed to assign role'})

    except Exception as e:
        logger.error(f"Error assigning role to user: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


@csrf_exempt
@require_http_methods(["POST"])
def remove_role_from_user(request, user_id):
    """
    Remove a role from a user (AJAX endpoint) with security checks.
    """
    if not request.session.get('user_info'):
        return JsonResponse({'success': False, 'error': 'Not authenticated'})

    try:
        data = json.loads(request.body)
        role_name = data.get('role_name')

        # Get current logged-in user info
        current_user_info = request.session.get('user_info', {})
        current_user_id = current_user_info.get('sub')  # Keycloak user ID
        current_user_roles = current_user_info.get('roles', [])

        # Security Check: Prevent removing own admin role
        if user_id == current_user_id and role_name in ['admin', 'keycloak-admin']:
            logger.warning(f"User {current_user_info.get('username')} attempted to remove their own admin role: {role_name}")
            return JsonResponse({'success': False, 'error': 'You cannot remove your own admin role'})

        # Additional check: Ensure at least one admin remains
        if role_name in ['admin', 'keycloak-admin']:
            # Check if this would leave the user without admin access
            target_user_roles = keycloak_admin.get_user_roles(user_id)
            remaining_admin_roles = [role for role in target_user_roles if role in ['admin', 'keycloak-admin'] and role != role_name]

            if not remaining_admin_roles:
                # This user would lose all admin access
                if user_id == current_user_id:
                    return JsonResponse({'success': False, 'error': 'You cannot remove your last admin role'})
                else:
                    # For other users, this might be allowed but warn about admin access
                    logger.warning(f"Admin {current_user_info.get('username')} removing last admin role from user {user_id}")

        if keycloak_admin.remove_role_from_user(user_id, role_name):
            logger.info(f"User {current_user_info.get('username')} removed role {role_name} from user {user_id}")
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Failed to remove role'})

    except Exception as e:
        logger.error(f"Error removing role from user: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


@csrf_exempt
@require_http_methods(["POST"])
def assign_permission_to_role(request):
    """
    Assign a permission to a role (AJAX endpoint).
    """
    if not request.session.get('user_info'):
        return JsonResponse({'success': False, 'error': 'Not authenticated'})

    try:
        data = json.loads(request.body)
        role_name = data.get('role_name')
        permission_name = data.get('permission_name')

        if keycloak_admin.assign_permission_to_role(role_name, permission_name):
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Failed to assign permission'})

    except Exception as e:
        logger.error(f"Error assigning permission to role: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


def role_permissions(request, role_name):
    """
    Show permissions assigned to a specific role.
    """
    if not request.session.get('user_info'):
        return redirect('login')

    try:
        # Get role permissions
        role_permissions = keycloak_admin.get_role_permissions(role_name)

        # Get all available permissions
        all_permissions = keycloak_admin.get_permissions()
        available_permissions = [
            perm for perm in all_permissions
            if perm['name'] not in [rp['name'] for rp in role_permissions]
        ]

        context = {
            'role_name': role_name,
            'role_permissions': role_permissions,
            'available_permissions': available_permissions,
            'page_title': f"Permissions for Role {role_name} - Keycloak Admin",
        }

        return render(request, 'keycloak_admin/roles/permissions.html', context)

    except Exception as e:
        logger.error(f"Error getting role permissions: {e}")
        messages.error(request, "Error loading role permissions.")
        return redirect('keycloak_admin:role_list')


# API Endpoints for Ajax calls
@require_view_admin_permission
def api_user_detail(request, user_id):
    """
    API endpoint to get user details.
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        user = keycloak_admin.get_user(user_id)
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)

        # Get user permissions
        user_roles = keycloak_admin.get_user_roles(user_id)
        user_permissions = [
            role['name'].replace('permission_', '')
            for role in user_roles
            if role['name'].startswith('permission_')
        ]

        # Get session info
        from app.session_manager import SessionManager
        user_sessions = SessionManager.get_user_sessions(user_id=user_id, username=user.get('username', ''))

        user_data = {
            'id': user.get('id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'first_name': user.get('firstName'),
            'last_name': user.get('lastName'),
            'enabled': user.get('enabled', True),
            'created_timestamp': user.get('createdTimestamp'),
            'permissions': user_permissions,
            'session_count': len(user_sessions),
        }

        return JsonResponse({'success': True, 'user': user_data})

    except Exception as e:
        logger.error(f"Error getting user detail: {e}")
        return JsonResponse({'error': 'Failed to get user details'}, status=500)


@require_view_admin_permission
def api_user_sessions(request, user_id):
    """
    API endpoint to get user sessions.
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        # Get user info
        user = keycloak_admin.get_user(user_id)
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)

        # Get user sessions
        from app.session_manager import SessionManager
        user_sessions = SessionManager.get_user_sessions(user_id=user_id, username=user.get('username', ''))

        sessions_data = []
        for session in user_sessions:
            sessions_data.append({
                'id': session.get('session_id', session.get('id', '')),
                'ip_address': session.get('ip_address', 'N/A'),
                'start_time': session.get('created_at'),
                'last_activity': session.get('last_accessed'),
                'is_active': (timezone.now().timestamp() - session.get('last_accessed', 0)) < 300,
                'user_agent': session.get('user_agent', 'N/A'),
            })

        return JsonResponse({'success': True, 'sessions': sessions_data})

    except Exception as e:
        logger.error(f"Error getting user sessions: {e}")
        return JsonResponse({'error': 'Failed to get user sessions'}, status=500)


@csrf_exempt
@require_manage_admin_permission
@require_http_methods(["POST"])
def api_user_update(request, user_id):
    """
    API endpoint to update user.
    """

    try:
        # Get current user info for permission check
        current_user_info = request.session.get('user_info', {})

        # Prevent self-modification of admin status
        if user_id == current_user_info.get('sub'):
            return JsonResponse({'error': 'Cannot modify your own account through this interface'}, status=400)

        # Get form data
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        permissions = request.POST.getlist('permissions')

        if not username:
            return JsonResponse({'error': 'Username is required'}, status=400)

        # Prepare user data
        user_data = {
            'username': username,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'enabled': True,
        }

        # Update user in Keycloak
        success = keycloak_admin.update_user(user_id, user_data)
        if not success:
            return JsonResponse({'error': 'Failed to update user in Keycloak'}, status=500)

        # Update password if provided
        if password:
            keycloak_admin.reset_password(user_id, password, temporary=False)

        # Update permissions
        # First, remove all existing permission roles
        user_roles = keycloak_admin.get_user_roles(user_id)
        for role in user_roles:
            if role['name'].startswith('permission_'):
                keycloak_admin.remove_role_from_user(user_id, role['name'])

        # Add new permissions
        for permission_name in permissions:
            permission_role_id = keycloak_admin._get_role_id(f"permission_{permission_name}")
            if permission_role_id:
                keycloak_admin._assign_role_to_user(user_id, permission_role_id)

        return JsonResponse({'success': True, 'message': 'User updated successfully'})

    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return JsonResponse({'error': 'Failed to update user'}, status=500)


@csrf_exempt
@require_manage_admin_permission
@require_http_methods(["POST"])
def api_user_activate(request, user_id):
    """
    API endpoint to activate a user.
    """

    try:
        current_user_info = request.session.get('user_info', {})

        # Prevent self-activation/deactivation
        if user_id == current_user_info.get('sub'):
            return JsonResponse({'error': 'Cannot modify your own account status'}, status=400)

        # Enable user
        user_data = {'enabled': True}
        success = keycloak_admin.update_user(user_id, user_data)

        if success:
            return JsonResponse({'success': True, 'message': 'User activated successfully'})
        else:
            return JsonResponse({'error': 'Failed to activate user'}, status=500)

    except Exception as e:
        logger.error(f"Error activating user: {e}")
        return JsonResponse({'error': 'Failed to activate user'}, status=500)


@csrf_exempt
@require_manage_admin_permission
@require_http_methods(["POST"])
def api_user_deactivate(request, user_id):
    """
    API endpoint to deactivate a user.
    """

    try:
        current_user_info = request.session.get('user_info', {})

        # Prevent self-deactivation
        if user_id == current_user_info.get('sub'):
            return JsonResponse({'error': 'Cannot deactivate your own account'}, status=400)

        # Disable user
        user_data = {'enabled': False}
        success = keycloak_admin.update_user(user_id, user_data)

        if success:
            return JsonResponse({'success': True, 'message': 'User deactivated successfully'})
        else:
            return JsonResponse({'error': 'Failed to deactivate user'}, status=500)

    except Exception as e:
        logger.error(f"Error deactivating user: {e}")
        return JsonResponse({'error': 'Failed to deactivate user'}, status=500)


@csrf_exempt
@require_manage_admin_permission
@require_http_methods(["POST"])
def api_user_delete(request, user_id):
    """
    API endpoint to delete a user.
    """

    try:
        current_user_info = request.session.get('user_info', {})

        # Prevent self-deletion
        if user_id == current_user_info.get('sub'):
            return JsonResponse({'error': 'Cannot delete your own account'}, status=400)

        # Delete user from Keycloak
        success = keycloak_admin.delete_user(user_id)

        if success:
            return JsonResponse({'success': True, 'message': 'User deleted successfully'})
        else:
            return JsonResponse({'error': 'Failed to delete user'}, status=500)

    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return JsonResponse({'error': 'Failed to delete user'}, status=500)


@csrf_exempt
@require_manage_admin_permission
@require_http_methods(["POST"])
def api_session_logout(request, session_id):
    """
    API endpoint to logout a specific session.
    """

    try:
        from app.session_manager import SessionManager

        # Check if trying to logout current admin session
        current_session_key = request.session.session_key
        if session_id == current_session_key:
            return JsonResponse({'error': 'Cannot logout your own current session using this method. Use the logout button instead.'}, status=400)

        # Invalidate session
        success = SessionManager.invalidate_session(session_id)

        if success:
            return JsonResponse({'success': True, 'message': 'Session logged out successfully'})
        else:
            return JsonResponse({'error': 'Failed to logout session'}, status=500)

    except Exception as e:
        logger.error(f"Error logging out session: {e}")
        return JsonResponse({'error': 'Failed to logout session'}, status=500)


@require_manage_admin_permission
@require_http_methods(["POST"])
def api_user_create(request):
    """
    API endpoint to create a new user (from dashboard form).
    """

    try:
        # Get form data
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        permissions = request.POST.getlist('permissions')

        if not username or not password:
            return JsonResponse({'error': 'Username and password are required'}, status=400)

        # Prepare user data
        user_data = {
            'username': username,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'enabled': True,
            'credentials': [{
                'type': 'password',
                'value': password,
                'temporary': False
            }]
        }

        # Create user in Keycloak
        user_id = keycloak_admin.create_user(user_data)
        if not user_id:
            return JsonResponse({'error': 'Failed to create user in Keycloak'}, status=500)

        # Assign permissions
        for permission_name in permissions:
            permission_role_id = keycloak_admin._get_role_id(f"permission_{permission_name}")
            if permission_role_id:
                keycloak_admin._assign_role_to_user(user_id, permission_role_id)

        return JsonResponse({'success': True, 'message': 'User created successfully'})

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return JsonResponse({'error': 'Failed to create user'}, status=500)
