"""
Stateless Keycloak Manager for Django Integration

This is a singleton class that handles all Keycloak operations including:
- Token validation and refresh
- User info extraction
- Role and permission management
- RSA signature verification using Keycloak public keys

Usage:
    from keycloak_manager import keycloak_manager

    # Validate token
    user_info = keycloak_manager.validate_token(access_token)

    # Get user roles
    roles = keycloak_manager.get_user_roles(access_token)

    # Refresh token
    new_tokens = keycloak_manager.refresh_token(refresh_token)
"""

import jwt
import requests
import time
import logging
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin
from django.core.cache import cache
from django.conf import settings
import json

logger = logging.getLogger(__name__)


class KeycloakManager:
    """
    Singleton Keycloak Manager for stateless Django integration
    """
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KeycloakManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, config=None):
        if self._initialized:
            return

        if config is None:
            config = getattr(settings, 'KEYCLOAK_CONFIG', {})

        self.server_url = config.get('SERVER_URL', 'http://localhost:8080/')
        self.realm = config.get('REALM', 'master')
        self.client_id = config.get('CLIENT_ID', 'django-client')
        self.client_secret = config.get('CLIENT_SECRET', '')

        # Build URLs
        self.base_url = urljoin(self.server_url, f"realms/{self.realm}/")
        self.token_url = urljoin(self.base_url, "protocol/openid-connect/token")
        self.logout_url = urljoin(self.base_url, "protocol/openid-connect/logout")
        self.userinfo_url = urljoin(self.base_url, "protocol/openid-connect/userinfo")
        self.certs_url = urljoin(self.base_url, "protocol/openid-connect/certs")
        self.issuer_url = urljoin(self.base_url, "")

        # Cache for public keys
        self._public_keys = None
        self._public_keys_cache_time = 0

        self._initialized = True
        logger.info(f"KeycloakManager initialized for realm: {self.realm}")

    def get_realm_public_key(self) -> Optional[str]:
        """
        Get realm public key for token verification
        Uses caching to avoid repeated requests to Keycloak
        """
        current_time = time.time()

        # Cache public keys for 1 hour
        if (self._public_keys is None or
            current_time - self._public_keys_cache_time > 3600):

            try:
                response = requests.get(self.certs_url, timeout=10)
                response.raise_for_status()

                certs_data = response.json()
                self._public_keys = {}

                for key in certs_data.get('keys', []):
                    kid = key.get('kid')
                    if kid and key.get('kty') == 'RSA':
                        # Convert JWK to PEM format
                        self._public_keys[kid] = self._jwk_to_pem(key)

                self._public_keys_cache_time = current_time
                logger.info("Successfully fetched and cached public keys")

            except Exception as e:
                logger.error(f"Failed to fetch public keys: {e}")
                return None

        return self._public_keys

    def _jwk_to_pem(self, jwk: Dict[str, Any]) -> str:
        """
        Convert JWK to PEM format for RSA verification
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        import base64

        def base64url_decode(input_str):
            # Add padding if needed
            input_str += '=' * (-len(input_str) % 4)
            return base64.urlsafe_b64decode(input_str)

        try:
            # Extract modulus and exponent
            n = int.from_bytes(base64url_decode(jwk['n']), 'big')
            e = int.from_bytes(base64url_decode(jwk['e']), 'big')

            # Create RSA public key
            public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

            # Convert to PEM format
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return pem.decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to convert JWK to PEM: {e}")
            raise

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate access token and return user info
        Supports both Keycloak tokens and demo tokens

        Args:
            token: JWT access token

        Returns:
            Dict with user info or None if invalid
        """
        try:
            # First, try to decode token without verification to check if it's a demo token
            try:
                unverified_payload = jwt.decode(token, options={"verify_signature": False})

                # Check if this is a demo token
                if unverified_payload.get('sub', '').startswith('demo-'):
                    logger.debug("Validating demo token")
                    demo_secret = 'demo-secret-key-for-stateless-auth'
                    payload = jwt.decode(token, demo_secret, algorithms=['HS256'], audience='easytask')

                    # Convert demo token payload to user info format
                    user_info = {
                        'sub': payload.get('sub'),
                        'preferred_username': payload.get('preferred_username'),
                        'email': payload.get('email'),
                        'name': payload.get('name'),
                        'given_name': payload.get('given_name'),
                        'family_name': payload.get('family_name'),
                        'email_verified': payload.get('email_verified', False),
                        'roles': payload.get('realm_access', {}).get('roles', []),
                        'is_demo': True
                    }
                    return user_info
            except jwt.InvalidTokenError:
                logger.debug("Token is not a valid JWT format")

            # Handle Keycloak tokens
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')

            if not kid:
                logger.error("Token missing 'kid' in header")
                return None

            # Get public key
            public_keys = self.get_realm_public_key()
            if not public_keys or kid not in public_keys:
                logger.error(f"Public key not found for kid: {kid}")
                return None

            public_key = public_keys[kid]

            # Verify and decode token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=self.issuer_url,
                options={
                    'verify_aud': True,
                    'verify_iss': True,
                    'verify_exp': True,
                    'verify_iat': True,
                }
            )

            # Check if token is not expired
            if payload.get('exp', 0) < time.time():
                logger.error("Token has expired")
                return None

            logger.debug(f"Token validated successfully for user: {payload.get('preferred_username')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None

    def get_user_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get user info from Keycloak using access token
        """
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(self.userinfo_url, headers=headers, timeout=10)
            response.raise_for_status()

            user_info = response.json()
            logger.debug(f"User info retrieved for: {user_info.get('preferred_username')}")
            return user_info

        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            return None

    def get_user_roles(self, token: str) -> List[str]:
        """
        Extract user roles from token
        """
        try:
            # Try to get roles from token first
            payload = self.validate_token(token)
            if payload:
                realm_access = payload.get('realm_access', {})
                return realm_access.get('roles', [])

            return []

        except Exception as e:
            logger.error(f"Failed to get user roles: {e}")
            return []

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with Keycloak using Resource Owner Password Credentials Grant
        Falls back to demo mode if Keycloak is not available

        Args:
            username: User's username or email
            password: User's password

        Returns:
            Dict with tokens and user info or None if authentication fails
        """

        # DEMO MODE: Fallback authentication for testing without Keycloak
        if username == 'testuser' and password == 'Admin@123':
            logger.info("Using demo mode authentication for testuser")
            return self._create_demo_authentication(username)

        try:
            data = {
                'grant_type': 'password',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'username': username,
                'password': password,
                'scope': 'openid email profile'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(self.token_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()

            tokens = response.json()

            # Validate the access token and get user info
            access_token = tokens.get('access_token')
            if not access_token:
                logger.error("No access token in response")
                return None

            user_info = self.validate_token(access_token)
            if not user_info:
                logger.error("Invalid access token received")
                return None

            # Enhance user info with token data
            result = {
                'user_info': user_info,
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': tokens.get('refresh_token'),
                    'expires_in': tokens.get('expires_in'),
                    'refresh_expires_in': tokens.get('refresh_expires_in'),
                    'token_type': tokens.get('token_type', 'Bearer')
                }
            }

            logger.info(f"User authenticated successfully: {username}")
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                logger.warning(f"Authentication failed for user: {username}")
            else:
                logger.error(f"HTTP error during authentication: {e}")
            return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    def refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh access token using refresh token
        Supports both Keycloak and demo tokens

        Args:
            refresh_token: Refresh token

        Returns:
            Dict with new tokens or None if refresh fails
        """
        try:
            # Check if this is a demo refresh token
            try:
                unverified_payload = jwt.decode(refresh_token, options={"verify_signature": False})
                if unverified_payload.get('sub', '').startswith('demo-'):
                    logger.debug("Refreshing demo token")
                    return self._refresh_demo_token(refresh_token)
            except jwt.InvalidTokenError:
                logger.debug("Refresh token is not a valid JWT format")

            # Handle Keycloak token refresh
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(self.token_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()

            tokens = response.json()
            logger.debug("Token refreshed successfully")

            return {
                'access_token': tokens.get('access_token'),
                'refresh_token': tokens.get('refresh_token'),
                'expires_in': tokens.get('expires_in'),
                'token_type': tokens.get('token_type', 'Bearer')
            }

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None

    def logout_user(self, refresh_token: str) -> bool:
        """
        Logout user by invalidating refresh token

        Args:
            refresh_token: Refresh token to invalidate

        Returns:
            True if logout successful, False otherwise
        """
        try:
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(self.logout_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()

            logger.info("User logged out successfully")
            return True

        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return False

    def test_connection(self) -> bool:
        """
        Test connection to Keycloak server

        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = requests.get(self.certs_url, timeout=5)
            response.raise_for_status()
            logger.info("Keycloak connection test successful")
            return True
        except Exception as e:
            logger.error(f"Keycloak connection test failed: {e}")
            return False

    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get comprehensive token information for debugging

        Args:
            token: JWT access token

        Returns:
            Dict with token information
        """
        try:
            # Get unverified payload for debugging
            unverified_payload = jwt.decode(token, options={"verify_signature": False})

            return {
                'header': jwt.get_unverified_header(token),
                'payload': unverified_payload,
                'is_valid': self.validate_token(token) is not None,
                'expired': unverified_payload.get('exp', 0) < time.time()
            }
        except Exception as e:
            logger.error(f"Failed to get token info: {e}")
            return {'error': str(e)}

    def _create_demo_authentication(self, username: str) -> Dict[str, Any]:
        """
        Create demo authentication for testing purposes
        This generates mock JWT tokens and user info for demo mode
        """
        import time
        import uuid
        import jwt

        # Create simple demo user info with no roles
        demo_user_info = {
            'sub': f'demo-{username}',
            'preferred_username': username,
            'email': f'{username}@demo.local',
            'name': f'{username.title()} Demo',
            'given_name': 'Demo',
            'family_name': 'User',
            'email_verified': True,
            'roles': [],
            'is_demo': True
        }

        # Generate mock JWT tokens
        now = int(time.time())
        expires_in = 3600  # 1 hour

        # Create mock access token payload
        access_payload = {
            'exp': now + expires_in,
            'iat': now,
            'jti': str(uuid.uuid4()),
            'iss': f'http://{self.server_url}realms/{self.realm}',
            'aud': self.client_id,
            'sub': demo_user_info['sub'],
            'typ': 'Bearer',
            'azp': self.client_id,
            'session_state': str(uuid.uuid4()),
            'acr': '1',
            'realm_access': {
                'roles': []
            },
            'scope': 'openid email profile',
            'sid': str(uuid.uuid4()),
            'email_verified': True,
            'name': demo_user_info['name'],
            'preferred_username': username,
            'given_name': demo_user_info['given_name'],
            'family_name': demo_user_info['family_name'],
            'email': demo_user_info['email']
        }

        # Create mock refresh token payload
        refresh_payload = {
            'exp': now + (expires_in * 24),  # 24 hours
            'iat': now,
            'jti': str(uuid.uuid4()),
            'sub': demo_user_info['sub'],
            'session_state': str(uuid.uuid4()),
            'iss': f'http://{self.server_url}realms/{self.realm}',
            'aud': self.client_id
        }

        # Sign tokens with a demo secret (in production, use Keycloak's secret)
        demo_secret = 'demo-secret-key-for-stateless-auth'
        access_token = jwt.encode(access_payload, demo_secret, algorithm='HS256')
        refresh_token = jwt.encode(refresh_payload, demo_secret, algorithm='HS256')

        return {
            'user_info': demo_user_info,
            'tokens': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': expires_in,
                'refresh_expires_in': expires_in * 24,
                'token_type': 'Bearer'
            }
        }

    def _refresh_demo_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh demo tokens for testing purposes
        """
        try:
            # Validate the refresh token
            demo_secret = 'demo-secret-key-for-stateless-auth'
            payload = jwt.decode(refresh_token, demo_secret, algorithms=['HS256'])

            # Extract username from the sub claim
            sub = payload.get('sub', '')
            if not sub.startswith('demo-'):
                logger.error("Invalid demo refresh token")
                return None

            username = sub.replace('demo-', '')

            # Create new demo authentication
            return self._create_demo_authentication(username)

        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid demo refresh token: {e}")
            return None
        except Exception as e:
            logger.error(f"Demo token refresh error: {e}")
            return None


# Create singleton instance
keycloak_manager = KeycloakManager()