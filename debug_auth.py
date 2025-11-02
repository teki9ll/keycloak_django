#!/usr/bin/env python3
"""
Debug script to check authentication state and troubleshoot token refresh issues.
"""

import os
import sys
import django
import requests
import jwt
import json

# Add the project directory to Python path
sys.path.insert(0, '/root/projects/keycloak_demo')

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'keycloak_demo.settings')
django.setup()

from django.conf import settings
from app.utils.token_refresh import TokenRefreshManager

def debug_keycloak_connection():
    """Test connection to Keycloak"""
    print("=== Keycloak Connection Test ===")

    # Test well-known endpoint
    well_known_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/.well-known/openid_configuration"
    print(f"Testing: {well_known_url}")

    try:
        response = requests.get(well_known_url, timeout=5)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            config = response.json()
            print("✅ Keycloak is reachable")
            print(f"Token endpoint: {config.get('token_endpoint')}")
            print(f"Authorization endpoint: {config.get('authorization_endpoint')}")
            return True
        else:
            print(f"❌ Keycloak returned status {response.status_code}")
            print(f"Response: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ Error connecting to Keycloak: {e}")
        return False

def debug_client_configuration():
    """Check Keycloak client configuration"""
    print("\n=== Client Configuration ===")
    print(f"Server URL: {settings.KEYCLOAK_SERVER_URL}")
    print(f"Realm: {settings.KEYCLOAK_REALM}")
    print(f"Client ID: {settings.KEYCLOAK_CLIENT_ID}")
    print(f"Client Secret: {'*' * len(settings.KEYCLOAK_CLIENT_SECRET) if settings.KEYCLOAK_CLIENT_SECRET else 'NOT SET'}")

    if not settings.KEYCLOAK_CLIENT_SECRET:
        print("❌ Client secret is not configured")
        return False

    # Try to get client info from Keycloak admin API
    admin_token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/master/protocol/openid-connect/token"

    try:
        admin_response = requests.post(admin_token_url, data={
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': 'admin',
            'password': 'admin123'
        })

        if admin_response.status_code == 200:
            admin_token = admin_response.json()['access_token']

            # Get client info
            clients_url = f"{settings.KEYCLOAK_SERVER_URL}admin/realms/{settings.KEYCLOAK_REALM}/clients"
            clients_response = requests.get(clients_url, headers={
                'Authorization': f'Bearer {admin_token}'
            })

            if clients_response.status_code == 200:
                clients = clients_response.json()
                client = next((c for c in clients if c['clientId'] == settings.KEYCLOAK_CLIENT_ID), None)

                if client:
                    print(f"✅ Client found: {client['clientId']}")
                    print(f"Client ID: {client['id']}")
                    print(f"Public Client: {client['publicClient']}")
                    print(f"Standard Flow Enabled: {client['standardFlowEnabled']}")
                    print(f"Direct Access Grants Enabled: {client['directAccessGrantsEnabled']}")
                    print(f"Service Accounts Enabled: {client['serviceAccountsEnabled']}")

                    # Check redirect URIs
                    redirect_uris = client.get('redirectUris', [])
                    print(f"Redirect URIs: {redirect_uris}")

                    # Validate configuration
                    if not client['publicClient'] and not client['serviceAccountsEnabled']:
                        print("❌ Client is not properly configured - not public and service accounts disabled")
                        return False

                    return True
                else:
                    print(f"❌ Client '{settings.KEYCLOAK_CLIENT_ID}' not found in realm")
                    return False
            else:
                print(f"❌ Failed to get clients: {clients_response.status_code}")
                return False
        else:
            print(f"❌ Failed to get admin token: {admin_response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Error checking client configuration: {e}")
        return False

def debug_token_refresh():
    """Test token refresh process"""
    print("\n=== Token Refresh Test ===")

    # Test token endpoint URL
    token_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    print(f"Token URL: {token_url}")

    # First, get a fresh token using password grant
    print("\n1. Testing password grant...")
    try:
        token_data = {
            'grant_type': 'password',
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'username': 'testuser',
            'password': 'user123'
        }

        response = requests.post(token_url, data=token_data)
        print(f"Password grant status: {response.status_code}")

        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')

            print(f"✅ Got access token: {access_token[:20]}...")
            print(f"✅ Got refresh token: {refresh_token[:20]}...")

            # Decode access token to check expiry
            try:
                payload = jwt.decode(access_token, options={"verify_signature": False})
                exp = payload.get('exp')
                print(f"Token expires at: {exp}")
                print(f"Time until expiry: {exp - int(__import__('time').time())} seconds")
            except:
                print("❌ Could not decode access token")

            # Test refresh token
            print("\n2. Testing refresh token...")
            refresh_data = {
                'grant_type': 'refresh_token',
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
                'refresh_token': refresh_token
            }

            refresh_response = requests.post(token_url, data=refresh_data)
            print(f"Refresh grant status: {refresh_response.status_code}")
            print(f"Refresh response: {refresh_response.text[:500]}")

            if refresh_response.status_code == 200:
                print("✅ Token refresh successful!")
                new_tokens = refresh_response.json()
                print(f"New access token: {new_tokens.get('access_token', 'NOT PROVIDED')[:20]}...")
                return True
            else:
                print("❌ Token refresh failed")
                print("Response details:")
                try:
                    error_json = refresh_response.json()
                    print(f"Error: {error_json.get('error')}")
                    print(f"Description: {error_json.get('error_description')}")
                except:
                    print(f"Raw response: {refresh_response.text}")
                return False
        else:
            print(f"❌ Password grant failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error during token refresh test: {e}")
        return False

def debug_current_session():
    """Check current Django session state"""
    print("\n=== Current Django Session ===")

    # Create a mock request to check session
    from django.test import RequestFactory
    factory = RequestFactory()
    request = factory.get('/')

    # Try to load session (this won't work without actual browser session)
    # But we can show what should be stored
    print("Expected session keys:")
    expected_keys = [
        'access_token',
        'refresh_token',
        'token_acquired_at',
        'token_expires_in',
        'authenticated_at',
        'oauth_state'
    ]

    for key in expected_keys:
        print(f"  - {key}")

def main():
    """Run all debug checks"""
    print("🔍 Django Keycloak Authentication Debug Script")
    print("=" * 50)

    # Run all tests
    keycloak_ok = debug_keycloak_connection()
    client_ok = debug_client_configuration()
    token_ok = debug_token_refresh()
    debug_current_session()

    print("\n" + "=" * 50)
    print("📊 SUMMARY:")
    print(f"Keycloak Connection: {'✅ OK' if keycloak_ok else '❌ FAILED'}")
    print(f"Client Configuration: {'✅ OK' if client_ok else '❌ FAILED'}")
    print(f"Token Refresh: {'✅ OK' if token_ok else '❌ FAILED'}")

    if not (keycloak_ok and client_ok and token_ok):
        print("\n🔧 RECOMMENDATIONS:")
        if not keycloak_ok:
            print("- Check Keycloak is running on http://172.28.136.214:8080")
            print("- Verify network connectivity to Keycloak")

        if not client_ok:
            print("- Check client configuration in Keycloak admin console")
            print("- Ensure client secret is configured correctly")
            print("- Verify redirect URIs match your application")

        if not token_ok:
            print("- Check client authentication settings (public vs confidential)")
            print("- Verify user has appropriate roles in Keycloak")
            print("- Ensure client has 'Service Accounts' enabled if needed")
    else:
        print("\n🎉 All checks passed! Authentication system should be working correctly.")

if __name__ == "__main__":
    main()