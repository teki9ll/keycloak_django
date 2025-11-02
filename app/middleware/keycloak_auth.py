import jwt
import requests
from django.conf import settings
from django.http import JsonResponse
from app.auth.keycloak_user import KeycloakUser
from app.decorators import AnonymousUser


class KeycloakAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip authentication for certain paths
        skip_paths = ['/login/', '/callback/', '/logout/', '/']
        if request.path in skip_paths:
            request.user = AnonymousUser()
            return self.get_response(request)

        # Try to get token from session first (for web interface)
        token = request.session.get('access_token')

        # If no session token, try Authorization header (for API calls)
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            print(f"No token found for {request.path} - session_token: {bool(request.session.get('access_token'))}, auth_header: {bool(request.headers.get('Authorization'))}")
            request.user = AnonymousUser()
            return self.get_response(request)

        try:
            # Decode the token (for web interface, we can be less strict)
            if request.path.startswith('/api/'):
                # Check if this is an API call from the web interface (has session)
                if request.session.get('access_token') == token:
                    # This is a web interface API call, use less strict verification
                    print(f"API call from web interface, using relaxed verification")
                    payload = jwt.decode(token, options={"verify_signature": False})
                else:
                    # This is a direct API call, verify the token signature
                    print(f"Direct API call, verifying JWT signature")
                    unverified_header = jwt.get_unverified_header(token)
                    kid = unverified_header.get('kid')
                    public_key = self.get_public_key_from_keycloak(kid)

                    payload = jwt.decode(
                        token,
                        public_key,
                        algorithms=["RS256"],
                        audience=settings.KEYCLOAK_CLIENT_ID,
                        issuer=f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}",
                    )
            else:
                # For web interface, decode without verification (we trust Keycloak)
                print(f"Web interface request, decoding token without verification")
                payload = jwt.decode(token, options={"verify_signature": False})

            roles = payload.get("realm_access", {}).get("roles", [])
            username = payload.get("preferred_username", "unknown")
            email = payload.get("email", "")

            request.user = KeycloakUser(username=username, email=email, roles=roles)
            print(f"Successfully authenticated {username} for {request.path} with roles: {roles}")

        except jwt.ExpiredSignatureError:
            # Clear expired token from session
            if 'access_token' in request.session:
                del request.session['access_token']
            request.user = AnonymousUser()
        except jwt.InvalidTokenError:
            request.user = AnonymousUser()
        except Exception:
            request.user = AnonymousUser()

        return self.get_response(request)

    def get_public_key_from_keycloak(self, kid=None):
        """Get the public key from Keycloak's JWKS endpoint"""
        jwks_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"

        try:
            response = requests.get(jwks_url)
            response.raise_for_status()
            jwks = response.json()

            if kid:
                # Find the key with the matching key ID
                for key in jwks.get('keys', []):
                    if key.get('kid') == kid:
                        return jwt.algorithms.RSAAlgorithm.from_jwk(key)

            # If no kid specified or not found, use the first key
            if jwks.get('keys'):
                return jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])

        except Exception as e:
            print(f"Error fetching public key from Keycloak: {e}")

        # Fallback to configured public key
        return settings.KEYCLOAK_PUBLIC_KEY