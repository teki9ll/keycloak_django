#!/usr/bin/env python3
"""
Session and Token Status Checker
"""

import jwt
from decouple import config
from django.conf import settings
import os
import sys

# Add the project directory to Python path
sys.path.append('/root/projects/keycloak_demo')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'keycloak_demo.settings')

import django
django.setup()

from app.auth.keycloak_user import KeycloakUser

def check_session_status():
    """Check current session and token status"""

    print("🔍 Session and Token Status Checker")
    print("=" * 50)

    # Django Session Settings
    print("📊 Django Configuration:")
    print(f"   SESSION_COOKIE_AGE: {settings.SESSION_COOKIE_AGE} seconds ({settings.SESSION_COOKIE_AGE // 3600} hours)")
    print(f"   SESSION_SAVE_EVERY_REQUEST: {settings.SESSION_SAVE_EVERY_REQUEST}")
    print(f"   SESSION_ENGINE: {settings.SESSION_ENGINE}")
    print("")

    # Keycloak Configuration
    print("🔐 Keycloak Configuration:")
    print(f"   Server URL: {settings.KEYCLOAK_SERVER_URL}")
    print(f"   Realm: {settings.KEYCLOAK_REALM}")
    print(f"   Client ID: {settings.KEYCLOAK_CLIENT_ID}")
    print("")

    # Session Data (simulated - would need actual session to check)
    print("📋 Session Status:")
    print("   Note: This shows configuration, not live session data")
    print("   To check live session:")
    print("   1. Login to dashboard")
    print("   2. Look at 'Session Information' section")
    print("   3. Click 'Check Auth Status' button")
    print("")

def test_token_expiration():
    """Test JWT token expiration logic"""

    print("🕐 Token Expiration Test")
    print("=" * 50)

    # Sample token structure (not a real token)
    sample_payload = {
        "exp": 1732031800,  # Unix timestamp
        "iat": 1732031200,  # Issued at
        "preferred_username": "testuser",
        "realm_access": {"roles": ["user", "admin"]}
    }

    print("📋 Token Lifecycle:")
    print(f"   Issued At: {sample_payload['iat']}")
    print(f"   Expires At: {sample_payload['exp']}")
    print(f"   Duration: {sample_payload['exp'] - sample_payload['iat']} seconds (1 hour)")
    print("")

    # Current time check
    import time
    current_time = int(time.time())
    time_until_expiry = sample_payload['exp'] - current_time

    if time_until_expiry > 0:
        print(f"✅ Token Status: Valid")
        print(f"   Time until expiry: {time_until_expiry} seconds ({time_until_expiry // 60} minutes)")
    else:
        print(f"❌ Token Status: Expired")
        print(f"   Expired {-time_until_expiry} seconds ago")

def show_session_timeline():
    """Show visual timeline of session behavior"""

    print("\n📅 Session Timeline")
    print("=" * 50)

    timeline = [
        (0, "🔑 Login", "Session created, token issued"),
        (15, "📱 Activity", "Session extended by user interaction"),
        (30, "🔍 API Call", "Session extended, token still valid"),
        (45, "📊 Dashboard", "Session extended, token still valid"),
        (60, "⚠️  Token Expires", "API calls fail, dashboard still works"),
        (75, "📱 Activity", "Session still extended by activity"),
        (90, "🔄 Dashboard Refresh", "Session still active"),
        (120, "🚪 Session Expires", "Redirect to login required")
    ]

    for minute, event, description in timeline:
        bar = "━" * (minute // 5)
        print(f"   {minute:3d}m {event:12} {bar:24} {description}")

    print("\n📊 Key Points:")
    print("   • Django session: Extended by activity (configurable)")
    print("   • Keycloak token: Fixed 1 hour from login")
    print("   • API access: Requires valid token")
    print("   • Dashboard access: Requires valid session")

def show_configuration_options():
    """Show options for changing session duration"""

    print("\n⚙️ Configuration Options")
    print("=" * 50)

    print("📝 To change Django session duration:")
    print("   Edit keycloak_demo/settings.py:")
    print("   SESSION_COOKIE_AGE = 3600  # Current: 1 hour")
    print("   # Examples:")
    print("   # SESSION_COOKIE_AGE = 7200   # 2 hours")
    print("   # SESSION_COOKIE_AGE = 14400  # 4 hours")
    print("   # SESSION_COOKIE_AGE = 28800  # 8 hours")
    print("")

    print("🔐 To change Keycloak token duration:")
    print("   1. Go to Keycloak admin console")
    print("   2. Navigate to Realm Settings → Tokens")
    print("   3. Adjust 'Access Token Lifespan'")
    print("   4. Save changes")
    print("")

    print("⚠️  Recommendations:")
    print("   • Development: 1-4 hours is fine")
    print("   • Production: Consider token refresh implementation")
    print("   • Security: Shorter tokens for sensitive applications")

def main():
    check_session_status()
    test_token_expiration()
    show_session_timeline()
    show_configuration_options()

    print("\n🎯 Summary:")
    print("   • Your session will be active for **1 hour of inactivity**")
    print("   • API access stops after **exactly 1 hour from login**")
    print("   • Each user interaction extends the Django session")
    print("   • Token expiration is fixed and cannot be extended")
    print("\n📱 To check your current session status:")
    print("   Visit http://172.28.136.214:8010/dashboard/")
    print("   Look at 'Session Information' section")

if __name__ == "__main__":
    main()