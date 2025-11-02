class KeycloakUser:
    def __init__(self, username, email=None, roles=None):
        self.username = username
        self.email = email
        self.roles = roles or []

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def is_staff(self):
        return 'admin' in self.roles

    @property
    def is_superuser(self):
        return 'admin' in self.roles

    def has_role(self, role_name):
        return role_name in self.roles

    def has_perm(self, perm, obj=None):
        return self.is_staff

    def has_module_perms(self, app_label):
        return self.is_staff

    def __str__(self):
        return self.username