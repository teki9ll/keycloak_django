"""
URL configuration for keycloak_demo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from app import views

urlpatterns = [
    # Web interface
    path('', views.public_info, name='public_info'),
    path('login/', views.login, name='login'),
    path('callback/', views.callback, name='callback'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Custom authentication
    path('auth/custom-login/', views.custom_login_submit, name='custom_login_submit'),
    path('auth/logout/', views.logout, name='django_logout'),
    path('auth/keycloak-logout/', views.keycloak_logout, name='keycloak_logout'),

    # API endpoints
    path('api/public/', views.public_info, name='public_api'),
    path('api/dashboard/', views.dashboard, name='dashboard_api'),
    path('api/admin/', views.admin_panel, name='admin_panel'),
    path('api/manager/', views.manager_panel, name='manager_panel'),
    path('api/profile/', views.update_profile, name='update_profile'),
    path('api/auth/status/', views.auth_status, name='auth_status'),

      # Easytask User Management
    path('admin/', include('keycloak_admin.urls')),

    # Admin site (if needed)
    # path('admin/', admin.site.urls),
]
