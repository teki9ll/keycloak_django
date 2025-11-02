#!/usr/bin/env python3
"""
Simple OAuth2 test without PKCE to isolate the issue
"""

import base64
import secrets
import requests
from decouple import config
from urllib.parse import urlencode

# Configuration
KEYCLOAK_SERVER_URL = config('KEYCLOAK_SERVER_URL', default='http://172.28.136.214:8080/')
KEYCLOAK_REALM = config('KEYCLOAK_REALM', default='teki_9')
KEYCLOAK_CLIENT_ID = config('KEYCLOAK_CLIENT_ID', default='easytask')
KEYCLOAK_CLIENT_SECRET = config('KEYCLOAK_CLIENT_SECRET', default='FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa')

def generate_auth_url():
    """Generate a Keycloak authorization URL without PKCE"""

    # Generate state parameter for security
    state = secrets.token_urlsafe(16)

    # Build Keycloak authorization URL without PKCE
    auth_params = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': 'http://localhost:8000/simple-callback/',
        'state': state,
    }

    auth_url = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{urlencode(auth_params)}"

    print("Authorization URL (without PKCE):")
    print(auth_url)
    print(f"\nState: {state}")
    print("\nInstructions:")
    print("1. Copy the URL above and paste it in your browser")
    print("2. Login with your Keycloak credentials")
    print("3. You'll be redirected to a 404 page - that's expected")
    print("4. Copy the full URL from your browser address bar")
    print("5. Run: python simple_auth_test.py --callback 'YOUR_FULL_CALLBACK_URL'")

    return state

def exchange_code_for_token(code, redirect_uri):
    """Exchange authorization code for access token"""

    print(f"\nExchanging code for token...")
    print(f"Code: {code[:50]}...")
    print(f"Redirect URI: {redirect_uri}")

    token_data = {
        'grant_type': 'authorization_code',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'code': code,
        'redirect_uri': redirect_uri,
    }

    token_url = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

    try:
        print(f"Token URL: {token_url}")
        print(f"Request data: {token_data}")

        response = requests.post(token_url, data=token_data, timeout=10)

        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response body: {response.text}")

        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get('access_token')

            print(f"\n✅ SUCCESS! Token obtained:")
            print(f"Access Token: {access_token[:50]}...")
            print(f"Token Type: {token_info.get('token_type')}")
            print(f"Expires In: {token_info.get('expires_in')} seconds")

            if 'id_token' in token_info:
                print(f"ID Token: {token_info['id_token'][:50]}...")

            return True
        else:
            print(f"\n❌ Token exchange failed!")
            return False

    except Exception as e:
        print(f"❌ Exception during token exchange: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--callback':
        # Handle callback URL
        if len(sys.argv) < 3:
            print("Usage: python simple_auth_test.py --callback 'FULL_CALLBACK_URL'")
            return

        callback_url = sys.argv[2]

        # Parse callback URL
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(callback_url)
        query_params = parse_qs(parsed.query)

        code = query_params.get('code', [None])[0]
        state = query_params.get('state', [None])[0]
        error = query_params.get('error', [None])[0]

        if error:
            print(f"❌ Keycloak returned error: {error}")
            error_description = query_params.get('error_description', [None])[0]
            if error_description:
                print(f"Description: {error_description}")
            return

        if not code:
            print("❌ No authorization code found in callback URL")
            return

        print(f"Received callback with code and state")

        # Exchange code for token
        success = exchange_code_for_token(code, 'http://localhost:8000/simple-callback/')

        if success:
            print("\n🎉 Token exchange successful!")
            print("The basic OAuth2 flow is working.")
            print("The issue might be with PKCE or Django session handling.")
        else:
            print("\n💥 Token exchange failed even without PKCE.")
            print("Check your Keycloak client configuration.")

    else:
        # Generate auth URL
        generate_auth_url()

if __name__ == "__main__":
    main()