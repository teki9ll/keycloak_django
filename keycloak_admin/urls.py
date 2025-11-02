"""
URL configuration for Keycloak Admin Dashboard

This module defines URL patterns for the Keycloak administration interface.
"""

from django.urls import path
from . import views

app_name = 'keycloak_admin'

urlpatterns = [
    # Dashboard
    path('', views.keycloak_dashboard, name='dashboard'),

    # User Management
    path('users/', views.user_list, name='user_list'),
    path('users/<str:user_id>/', views.user_detail, name='user_detail'),
    path('users/<str:user_id>/delete/', views.user_delete, name='user_delete'),

    # Role Management
    path('roles/', views.role_list, name='role_list'),
    path('roles/create/', views.role_create, name='role_create'),
    path('roles/<str:role_name>/delete/', views.role_delete, name='role_delete'),
    path('roles/<str:role_name>/permissions/', views.role_permissions, name='role_permissions'),

    # Permission Management
    path('permissions/', views.permission_list, name='permission_list'),

    # AJAX Endpoints for Role Assignment
    path('api/users/<str:user_id>/assign-role/', views.assign_role_to_user, name='assign_role_to_user'),
    path('api/users/<str:user_id>/remove-role/', views.remove_role_from_user, name='remove_role_from_user'),
    path('api/roles/assign-permission/', views.assign_permission_to_role, name='assign_permission_to_role'),

    # User Session Management
    path('users/<str:user_id>/logout/', views.logout_user, name='logout_user'),
]