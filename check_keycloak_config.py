#!/usr/bin/env python3
"""
Keycloak Configuration Checker

This script helps verify that your Keycloak server is properly configured
to work with the Django Keycloak Demo project.
"""

import requests
import sys
import json
from urllib.parse import urlencode

# Configuration (should match your settings)
KEYCLOAK_SERVER_URL = "http://172.28.136.214:8080/"
REALM_NAME = "teki_9"
CLIENT_ID = "easytask"
REDIRECT_URI = "http://localhost:8000/callback/"

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_success(message):
    print(f"✅ {message}")

def print_error(message):
    print(f"❌ {message}")

def print_warning(message):
    print(f"⚠️  {message}")

def print_info(message):
    print(f"ℹ️  {message}")

def test_keycloak_server():
    """Test if Keycloak server is accessible"""
    print_header("Testing Keycloak Server Connection")

    try:
        response = requests.get(f"{KEYCLOAK_SERVER_URL}", timeout=10)
        if response.status_code == 200:
            print_success(f"Keycloak server is accessible at {KEYCLOAK_SERVER_URL}")
            return True
        else:
            print_error(f"Keycloak server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_error(f"Cannot connect to Keycloak server at {KEYCLOAK_SERVER_URL}")
        print_info("Please check:")
        print_info("  - Keycloak server is running")
        print_info("  - Server URL is correct")
        print_info("  - Network connectivity")
        return False
    except requests.exceptions.Timeout:
        print_error("Connection to Keycloak server timed out")
        return False
    except Exception as e:
        print_error(f"Unexpected error connecting to Keycloak: {e}")
        return False

def test_realm_exists():
    """Test if the realm exists"""
    print_header(f"Testing Realm: {REALM_NAME}")

    try:
        # Test realm endpoint
        realm_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/"
        response = requests.get(realm_url, timeout=10)

        if response.status_code == 200:
            realm_data = response.json()
            print_success(f"Realm '{REALM_NAME}' exists and is accessible")
            print_info(f"Realm Display Name: {realm_data.get('displayName', 'N/A')}")
            print_info(f"Realm Enabled: {realm_data.get('enabled', 'N/A')}")
            return True
        elif response.status_code == 404:
            print_error(f"Realm '{REALM_NAME}' not found")
            print_info("Please create the realm in Keycloak admin console")
            return False
        else:
            print_error(f"Realm check failed with status: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error checking realm: {e}")
        return False

def test_client_exists():
    """Test if the client exists in the realm"""
    print_header(f"Testing Client: {CLIENT_ID}")

    try:
        # Try to access client info (this won't work without auth, but will show 401 vs 404)
        client_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth"
        params = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': 'test'
        }

        response = requests.get(client_url, params=params, timeout=10, allow_redirects=False)

        if response.status_code in [302, 200, 401]:
            print_success(f"Client '{CLIENT_ID}' appears to exist in realm '{REALM_NAME}'")
            return True
        elif response.status_code == 400:
            # Check if it's a client configuration error
            if "client" in response.text.lower():
                print_error(f"Client '{CLIENT_ID}' not found or misconfigured")
                print_info("Please check:")
                print_info("  - Client exists in the realm")
                print_info("  - Client is enabled")
                print_info("  - Access Type is set to 'confidential'")
                print_info("  - Standard Flow is enabled")
                return False
            else:
                print_error(f"Client configuration error: {response.status_code}")
                return False
        else:
            print_error(f"Unexpected response status: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error checking client: {e}")
        return False

def test_well_known_endpoint():
    """Test the OIDC well-known endpoint"""
    print_header("Testing OIDC Discovery Endpoint")

    try:
        well_known_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/.well-known/openid_configuration"
        response = requests.get(well_known_url, timeout=10)

        if response.status_code == 200:
            oidc_config = response.json()
            print_success("OIDC discovery endpoint is accessible")

            # Check key endpoints
            auth_endpoint = oidc_config.get('authorization_endpoint', '')
            token_endpoint = oidc_config.get('token_endpoint', '')
            userinfo_endpoint = oidc_config.get('userinfo_endpoint', '')

            print_info(f"Authorization Endpoint: {auth_endpoint}")
            print_info(f"Token Endpoint: {token_endpoint}")
            print_info(f"Userinfo Endpoint: {userinfo_endpoint}")

            return True
        else:
            print_error(f"OIDC discovery endpoint not accessible: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error checking OIDC discovery: {e}")
        return False

def test_jwks_endpoint():
    """Test the JWKS endpoint for public keys"""
    print_header("Testing JWKS (Public Keys) Endpoint")

    try:
        jwks_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/certs"
        response = requests.get(jwks_url, timeout=10)

        if response.status_code == 200:
            jwks_data = response.json()
            keys = jwks_data.get('keys', [])

            print_success(f"JWKS endpoint accessible with {len(keys)} keys")

            for i, key in enumerate(keys):
                kid = key.get('kid', 'N/A')
                kty = key.get('kty', 'N/A')
                use = key.get('use', 'N/A')
                print_info(f"Key {i+1}: KID={kid}, Type={kty}, Use={use}")

            return True
        else:
            print_error(f"JWKS endpoint not accessible: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Error checking JWKS endpoint: {e}")
        return False

def generate_auth_url():
    """Generate the full authorization URL for testing"""
    print_header("Authorization URL for Manual Testing")

    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': REDIRECT_URI,
        'state': 'test_state_123',
    }

    auth_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth?{urlencode(params)}"

    print_success("Authorization URL generated:")
    print(f"\n{auth_url}\n")

    print_info("You can:")
    print_info("1. Copy this URL to your browser")
    print_info("2. Login with your Keycloak credentials")
    print_info("3. You should be redirected to your Django app")
    print_info("4. If Django isn't running, you'll see an error - that's normal")

def main():
    """Run all configuration checks"""
    print_header("Keycloak Configuration Checker")
    print(f"Server: {KEYCLOAK_SERVER_URL}")
    print(f"Realm: {REALM_NAME}")
    print(f"Client: {CLIENT_ID}")

    all_passed = True

    # Run all tests
    tests = [
        test_keycloak_server,
        test_realm_exists,
        test_client_exists,
        test_well_known_endpoint,
        test_jwks_endpoint,
    ]

    for test in tests:
        if not test():
            all_passed = False

    # Generate auth URL
    generate_auth_url()

    # Final summary
    print_header("Configuration Check Summary")
    if all_passed:
        print_success("🎉 All configuration checks passed!")
        print_info("Your Keycloak server appears to be properly configured.")
        print_info("You can now test the Django application integration.")
    else:
        print_error("❌ Some configuration checks failed.")
        print_info("Please review the errors above and fix the issues.")
        print_info("Refer to KEYCLOAK_SETUP.md for detailed setup instructions.")

    print_header("Next Steps")
    print("1. Start your Django application:")
    print("   cd keycloak_demo && python manage.py runserver 0.0.0.0:8000")
    print("\n2. Visit http://localhost:8000/login/")
    print("\n3. Test the complete authentication flow")

if __name__ == "__main__":
    main()