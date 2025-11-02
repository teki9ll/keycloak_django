import time
import requests
import jwt
from django.conf import settings
from django.core.cache import cache


class TokenRefreshManager:
    """Handles JWT token refresh logic for persistent sessions"""

    @staticmethod
    def is_token_expiring_soon(token, threshold_seconds=None):
        """
        Check if a token is expiring soon (within threshold)

        Args:
            token: JWT token to check
            threshold_seconds: Seconds before expiry to consider "expiring soon"

        Returns:
            bool: True if token is expiring soon or already expired
        """
        if threshold_seconds is None:
            threshold_seconds = getattr(settings, 'KEYCLOAK_TOKEN_REFRESH_THRESHOLD', 300)

        try:
            # Decode token without verification to get exp claim
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get('exp')

            if not exp_timestamp:
                return True  # No expiry claim, consider it expired

            current_timestamp = int(time.time())
            time_until_expiry = exp_timestamp - current_timestamp

            return time_until_expiry <= threshold_seconds

        except jwt.InvalidTokenError:
            return True  # Invalid token, needs refresh

    @staticmethod
    def refresh_access_token(refresh_token):
        """
        Use refresh token to get new access token from Keycloak

        Args:
            refresh_token: The refresh token from Keycloak

        Returns:
            dict: New token data or None if refresh failed
        """
        token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"

        refresh_data = {
            'grant_type': 'refresh_token',
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'refresh_token': refresh_token
        }

        try:
            print(f"Refreshing token at: {token_url}")
            print(f"Client ID: {settings.KEYCLOAK_CLIENT_ID}")
            print(f"Refresh token (first 20 chars): {refresh_token[:20]}...")

            response = requests.post(token_url, data=refresh_data, timeout=10)

            print(f"Response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")
            print(f"Response body: {response.text[:500]}...")  # First 500 chars

            response.raise_for_status()

            token_data = response.json()
            print(f"Token refresh successful - got new access token")
            return token_data

        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error during token refresh: {e}")
            print(f"Response status: {e.response.status_code}")
            print(f"Response body: {e.response.text}")
            return None
        except requests.RequestException as e:
            print(f"Token refresh failed: {e}")
            return None

    @staticmethod
    def get_cached_public_key():
        """
        Get Keycloak public key with caching to avoid repeated requests

        Returns:
            str: Public key or None if not available
        """
        cache_key = f"keycloak_public_key_{settings.KEYCLOAK_REALM}"
        public_key = cache.get(cache_key)

        if not public_key:
            jwks_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"

            try:
                response = requests.get(jwks_url, timeout=5)
                response.raise_for_status()
                jwks = response.json()

                # Use the first available key
                if jwks.get('keys'):
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])
                    # Cache for 1 hour
                    cache.set(cache_key, public_key, 3600)

            except Exception as e:
                print(f"Error fetching public key from Keycloak: {e}")
                # Fallback to configured static key
                public_key = getattr(settings, 'KEYCLOAK_PUBLIC_KEY', None)

        return public_key

    @staticmethod
    def validate_token_integrity(token):
        """
        Validate that the token is issued for our application

        Args:
            token: JWT token to validate

        Returns:
            bool: True if token is valid for our application
        """
        try:
            # Get public key for signature verification
            public_key = TokenRefreshManager.get_cached_public_key()

            if public_key:
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256"],
                    audience=settings.KEYCLOAK_CLIENT_ID,
                    issuer=f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}",
                    options={"verify_exp": False}  # Don't check expiry here
                )
            else:
                # Fallback to no signature verification (development)
                payload = jwt.decode(token, options={"verify_signature": False})

            # Check that token is for our client
            azp = payload.get('azp')  # Authorized party
            aud = payload.get('aud')  # Audience

            return (azp == settings.KEYCLOAK_CLIENT_ID or
                   (isinstance(aud, list) and settings.KEYCLOAK_CLIENT_ID in aud) or
                   aud == settings.KEYCLOAK_CLIENT_ID)

        except jwt.InvalidTokenError:
            return False

    @staticmethod
    def extract_user_info(token):
        """
        Extract user information from JWT token

        Args:
            token: JWT token

        Returns:
            dict: User information or None if invalid
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})

            return {
                'username': payload.get("preferred_username", "unknown"),
                'email': payload.get("email", ""),
                'roles': payload.get("realm_access", {}).get("roles", []),
                'name': payload.get("name", ""),
                'exp': payload.get("exp", 0)
            }

        except jwt.InvalidTokenError:
            return None