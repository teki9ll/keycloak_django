from django.http import JsonResponse
from functools import wraps


class AnonymousUser:
    def __init__(self):
        self.username = ''
        self.email = ''
        self.roles = []

    @property
    def is_authenticated(self):
        return False

    @property
    def is_anonymous(self):
        return True

    def has_role(self, role_name):
        return False


def keycloak_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if isinstance(request.user, AnonymousUser) or not getattr(request.user, "is_authenticated", False):
            return JsonResponse({"error": "Authentication required"}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


def require_role(role_name):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            if not user or not getattr(user, "is_authenticated", False):
                return JsonResponse({"error": "Authentication required"}, status=401)
            if not user.has_role(role_name):
                return JsonResponse({"error": f"Access denied. '{role_name}' role required."}, status=403)
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_any_role(role_names):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = getattr(request, "user", None)
            if not user or not getattr(user, "is_authenticated", False):
                return JsonResponse({"error": "Authentication required"}, status=401)

            if not any(user.has_role(role) for role in role_names):
                return JsonResponse({
                    "error": f"Access denied. One of these roles required: {', '.join(role_names)}"
                }, status=403)
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator