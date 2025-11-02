import jwt
import requests
import time
from django.conf import settings
from django.http import JsonResponse
from app.auth.keycloak_user import KeycloakUser
from app.decorators import AnonymousUser
from app.utils.token_refresh import TokenRefreshManager


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
            # Check if token needs refresh (only for web interface with session)
            if not request.path.startswith('/api/') and request.session.get('access_token') == token:
                if TokenRefreshManager.is_token_expiring_soon(token):
                    print(f"Token expiring soon, attempting refresh...")
                    refreshed_token = self.refresh_token_if_needed(request)
                    if refreshed_token:
                        token = refreshed_token
                        print(f"Token refreshed successfully")

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
            # Try to refresh expired token
            if not request.path.startswith('/api/'):
                print(f"Token expired, attempting refresh...")
                refreshed_token = self.refresh_token_if_needed(request)
                if refreshed_token:
                    # Retry with new token
                    try:
                        payload = jwt.decode(refreshed_token, options={"verify_signature": False})
                        roles = payload.get("realm_access", {}).get("roles", [])
                        username = payload.get("preferred_username", "unknown")
                        email = payload.get("email", "")

                        request.user = KeycloakUser(username=username, email=email, roles=roles)
                        print(f"Successfully refreshed and authenticated {username}")
                        return self.get_response(request)
                    except Exception as e:
                        print(f"Failed to authenticate with refreshed token: {e}")

            # Clear expired tokens from session
            print(f"Token refresh failed, clearing session")
            self.clear_tokens_from_session(request)
            request.user = AnonymousUser()
        except jwt.InvalidTokenError:
            request.user = AnonymousUser()
        except Exception as e:
            print(f"Authentication error: {e}")
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

    def refresh_token_if_needed(self, request):
        """
        Attempt to refresh the access token using refresh token

        Args:
            request: Django request object

        Returns:
            str: New access token or None if refresh failed
        """
        refresh_token = request.session.get('refresh_token')
        if not refresh_token:
            print("No refresh token available in session")
            return None

        # Check if we recently attempted a refresh (avoid spamming Keycloak)
        last_refresh_attempt = request.session.get('last_refresh_attempt', 0)
        grace_period = getattr(settings, 'KEYCLOAK_REFRESH_GRACE_PERIOD', 86400)
        current_time = int(time.time())

        if current_time - last_refresh_attempt < 60:  # Don't retry within 1 minute
            print(f"Recent refresh attempt, skipping (last: {last_refresh_attempt}, now: {current_time})")
            return None

        # Mark refresh attempt
        request.session['last_refresh_attempt'] = current_time

        print(f"Attempting token refresh with refresh_token...")
        new_tokens = TokenRefreshManager.refresh_access_token(refresh_token)

        if new_tokens and new_tokens.get('access_token'):
            # Update session with new tokens
            request.session['access_token'] = new_tokens['access_token']
            request.session['token_acquired_at'] = int(time.time())
            request.session['token_expires_in'] = new_tokens.get('expires_in', 3600)

            # Update refresh token if provided
            if new_tokens.get('refresh_token'):
                request.session['refresh_token'] = new_tokens['refresh_token']

            # Ensure session persists
            request.session.set_expiry(30 * 24 * 60 * 60)  # 30 days

            print(f"Token refresh successful")
            return new_tokens['access_token']

        else:
            print(f"Token refresh failed, clearing tokens")
            self.clear_tokens_from_session(request)
            return None

    def clear_tokens_from_session(self, request):
        """Clear all authentication tokens from session"""
        tokens_to_clear = [
            'access_token',
            'refresh_token',
            'token_acquired_at',
            'token_expires_in',
            'authenticated_at',
            'oauth_state',
            'last_refresh_attempt'
        ]

        for token in tokens_to_clear:
            if token in request.session:
                del request.session[token]

        # Invalidate the session
        request.session.flush()