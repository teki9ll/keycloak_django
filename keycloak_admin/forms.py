"""
Forms for Keycloak Admin Dashboard

This module contains Django forms for managing Keycloak users, roles, and permissions
through the admin interface.
"""

from django import forms
from django.core.exceptions import ValidationError


class UserForm(forms.Form):
    """
    Form for creating and updating users.
    """
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter username'
        }),
        help_text="Unique username for the user"
    )

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter email address'
        }),
        help_text="User's email address"
    )

    first_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter first name'
        })
    )

    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter last name'
        })
    )

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password'
        }),
        required=False,
        help_text="Leave empty to keep current password"
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm password'
        }),
        required=False
    )

    enabled = forms.BooleanField(
        required=False,
        initial=True,  # Default to enabled
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text="User account is enabled"
    )

    permissions = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-check-input'
        }),
        help_text="Select permissions to assign to this user"
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and password != confirm_password:
            raise ValidationError("Passwords do not match")

        if password and len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")

        return cleaned_data

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            # Basic username validation
            if not username.replace('-', '').replace('_', '').isalnum():
                raise ValidationError("Username can only contain letters, numbers, hyphens, and underscores")
        return username


class RoleForm(forms.Form):
    """
    Form for creating roles.
    """
    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter role name'
        }),
        help_text="Unique name for the role"
    )

    description = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Enter role description'
        }),
        required=False,
        help_text="Optional description of the role"
    )

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if name:
            # Role name validation
            if not name.replace('-', '').replace('_', '').isalnum():
                raise ValidationError("Role name can only contain letters, numbers, hyphens, and underscores")
        return name


class PermissionForm(forms.Form):
    """
    Form for creating permissions.
    """
    name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter permission name'
        }),
        help_text="Name of the permission (e.g., manage_tasks, view_admin)"
    )

    description = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Enter permission description'
        }),
        required=False,
        help_text="Description of what this permission allows"
    )

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if name:
            # Permission name validation
            if not name.replace('_', '').isalnum():
                raise ValidationError("Permission name can only contain letters, numbers, and underscores")
        return name


class UserRoleForm(forms.Form):
    """
    Form for assigning roles to users.
    """
    user_id = forms.CharField(
        widget=forms.HiddenInput()
    )

    role = forms.ChoiceField(
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text="Select role to assign"
    )

    def __init__(self, available_roles, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['role'].choices = [('', '-- Select Role --')] + [
            (role['name'], role['name']) for role in available_roles
        ]


class RolePermissionForm(forms.Form):
    """
    Form for assigning permissions to roles.
    """
    role_name = forms.CharField(
        widget=forms.HiddenInput()
    )

    permission = forms.ChoiceField(
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text="Select permission to assign"
    )

    def __init__(self, available_permissions, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['permission'].choices = [('', '-- Select Permission --')] + [
            (perm['name'], f"{perm['name']} - {perm.get('description', '')}")
            for perm in available_permissions
        ]


class UserSearchForm(forms.Form):
    """
    Form for searching users.
    """
    search = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search users...'
        })
    )

    search_type = forms.ChoiceField(
        choices=[
            ('username', 'Username'),
            ('email', 'Email'),
            ('first_name', 'First Name'),
            ('last_name', 'Last Name'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        initial='username'
    )

    enabled = forms.ChoiceField(
        choices=[
            ('', 'All'),
            ('true', 'Enabled'),
            ('false', 'Disabled'),
        ],
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )


class PasswordResetForm(forms.Form):
    """
    Form for resetting user passwords.
    """
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password'
        }),
        help_text="New password for the user"
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password'
        }),
        help_text="Confirm the new password"
    )

    temporary = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text="User must change password on next login"
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password != confirm_password:
            raise ValidationError("Passwords do not match")

        if len(new_password) < 8:
            raise ValidationError("Password must be at least 8 characters long")

        return cleaned_data