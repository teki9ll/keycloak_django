#!/usr/bin/env python3
"""
Debug script to test Keycloak token exchange
"""

import requests
from decouple import config

# Configuration
KEYCLOAK_SERVER_URL = config('KEYCLOAK_SERVER_URL', default='http://172.28.136.214:8080/')
KEYCLOAK_REALM = config('KEYCLOAK_REALM', default='teki_9')
KEYCLOAK_CLIENT_ID = config('KEYCLOAK_CLIENT_ID', default='easytask')
KEYCLOAK_CLIENT_SECRET = config('KEYCLOAK_CLIENT_SECRET', default='FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa')

def test_token_endpoint():
    """Test the Keycloak token endpoint with various configurations"""

    print("="*60)
    print("Keycloak Token Endpoint Debug")
    print("="*60)

    print(f"Server URL: {KEYCLOAK_SERVER_URL}")
    print(f"Realm: {KEYCLOAK_REALM}")
    print(f"Client ID: {KEYCLOAK_CLIENT_ID}")
    print(f"Client Secret: {'*' * len(KEYCLOAK_CLIENT_SECRET) if KEYCLOAK_CLIENT_SECRET else 'None'}")

    token_url = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    print(f"\nToken URL: {token_url}")

    # Test 1: Check if token endpoint is accessible
    print("\n1. Testing token endpoint accessibility...")
    try:
        response = requests.get(token_url, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Method: GET (should fail with 405 Method Not Allowed)")
    except Exception as e:
        print(f"   Error: {e}")
        return False

    # Test 2: Try client credentials grant
    print("\n2. Testing client credentials grant...")
    client_data = {
        'grant_type': 'client_credentials',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
    }

    try:
        response = requests.post(token_url, data=client_data, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")

        if response.status_code == 200:
            print("   ✅ Client credentials grant works")
            return True
        else:
            print("   ❌ Client credentials grant failed")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 3: Try with a mock authorization code
    print("\n3. Testing with mock authorization code...")
    auth_data = {
        'grant_type': 'authorization_code',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'code': 'mock_code_123',
        'redirect_uri': 'http://localhost:8000/callback/',
        'code_verifier': 'mock_code_verifier',
    }

    try:
        response = requests.post(token_url, data=auth_data, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:300]}")

        if response.status_code == 400:
            print("   ✅ Token endpoint is working (expected failure with mock code)")
            return True
        else:
            print("   ❌ Unexpected response")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 4: Check OIDC configuration
    print("\n4. Testing OIDC discovery endpoint...")
    discovery_url = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/.well-known/openid_configuration"

    try:
        response = requests.get(discovery_url, timeout=10)
        if response.status_code == 200:
            config = response.json()
            print(f"   ✅ Discovery endpoint works")
            print(f"   Token endpoint from config: {config.get('token_endpoint', 'N/A')}")
            return True
        else:
            print(f"   ❌ Discovery endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")

    return False

def test_client_configuration():
    """Test if client configuration is correct"""
    print("\n" + "="*60)
    print("Client Configuration Debug")
    print("="*60)

    # Test if we can get the client configuration info
    # This typically requires admin access, so we'll provide guidance

    print("Common issues and solutions:")
    print("1. Client Access Type should be 'confidential'")
    print("2. 'Standard Flow Enabled' should be ON")
    print("3. Valid Redirect URIs should include:")
    print("   - http://localhost:8000/*")
    print("   - http://localhost:8000/callback/*")
    print("4. Web Origins should include:")
    print("   - http://localhost:8000")
    print("5. Client secret should match exactly")

if __name__ == "__main__":
    success = test_token_endpoint()
    test_client_configuration()

    if success:
        print("\n" + "="*60)
        print("✅ Keycloak token endpoint appears to be working")
        print("The issue might be with:")
        print("1. Client configuration in Keycloak")
        print("2. Authorization code validation")
        print("3. PKCE parameters")
        print("4. Redirect URI mismatch")
        print("="*60)
    else:
        print("\n" + "="*60)
        print("❌ Keycloak configuration issues detected")
        print("Please check:")
        print("1. Keycloak server is running")
        print("2. Realm name is correct")
        print("3. Client exists and is properly configured")
        print("="*60)