#!/usr/bin/env python3
"""
Test script to verify global logout functionality across multiple browsers.
This script simulates multiple sessions and tests the global logout feature.
"""

import requests
import json
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8010"
LOGIN_URL = f"{BASE_URL}/auth/custom-login/"
DASHBOARD_URL = f"{BASE_URL}/dashboard/"
LOGOUT_URL = f"{BASE_URL}/auth/keycloak-logout/"

def test_global_logout():
    """Test global logout functionality"""

    print("🧪 Testing Global Logout Functionality")
    print("=" * 50)

    # Create two sessions (simulating two browsers)
    session1 = requests.Session()
    session2 = requests.Session()

    print("\n1️⃣ Creating Session 1...")
    # Login with session 1
    login_data1 = {
        'username': 'testuser',
        'password': 'user123',
        'csrfmiddlewaretoken': 'test'
    }

    response1 = session1.post(LOGIN_URL, data=login_data1)
    print(f"Session 1 login status: {response1.status_code}")

    if response1.status_code == 200:
        result1 = response1.json()
        if result1.get('success'):
            print("✅ Session 1 login successful")
            print(f"Redirect URL: {result1.get('redirect_url')}")
        else:
            print(f"❌ Session 1 login failed: {result1.get('error')}")
            return False
    else:
        print(f"❌ Session 1 login HTTP error: {response1.status_code}")
        return False

    print("\n2️⃣ Creating Session 2...")
    # Login with session 2
    login_data2 = {
        'username': 'testuser',
        'password': 'user123',
        'csrfmiddlewaretoken': 'test'
    }

    response2 = session2.post(LOGIN_URL, data=login_data2)
    print(f"Session 2 login status: {response2.status_code}")

    if response2.status_code == 200:
        result2 = response2.json()
        if result2.get('success'):
            print("✅ Session 2 login successful")
            print(f"Redirect URL: {result2.get('redirect_url')}")
        else:
            print(f"❌ Session 2 login failed: {result2.get('error')}")
            return False
    else:
        print(f"❌ Session 2 login HTTP error: {response2.status_code}")
        return False

    print("\n3️⃣ Testing both sessions can access dashboard...")

    # Test session 1 dashboard access
    dashboard1 = session1.get(DASHBOARD_URL)
    print(f"Session 1 dashboard access: {dashboard1.status_code}")
    if "Welcome back" in dashboard1.text:
        print("✅ Session 1 can access dashboard")
    else:
        print("❌ Session 1 cannot access dashboard")

    # Test session 2 dashboard access
    dashboard2 = session2.get(DASHBOARD_URL)
    print(f"Session 2 dashboard access: {dashboard2.status_code}")
    if "Welcome back" in dashboard2.text:
        print("✅ Session 2 can access dashboard")
    else:
        print("❌ Session 2 cannot access dashboard")

    print("\n4️⃣ Performing GLOBAL LOGOUT from Session 1...")

    # Perform global logout from session 1
    logout_response = session1.post(LOGOUT_URL)
    print(f"Global logout status: {logout_response.status_code}")

    if logout_response.status_code == 302:  # Redirect to login
        print("✅ Global logout initiated successfully")
    else:
        print(f"⚠️ Global logout response: {logout_response.status_code}")

    print("\n5️⃣ Testing Session 1 after global logout...")

    # Test session 1 after logout
    dashboard1_after = session1.get(DASHBOARD_URL)
    print(f"Session 1 dashboard access after logout: {dashboard1_after.status_code}")
    if "login" in dashboard1_after.url or dashboard1_after.status_code == 302:
        print("✅ Session 1 correctly redirected to login")
    else:
        print("❌ Session 1 still has access")

    print("\n6️⃣ Testing Session 2 after global logout...")

    # Test session 2 after logout (should be logged out too)
    dashboard2_after = session2.get(DASHBOARD_URL)
    print(f"Session 2 dashboard access after global logout: {dashboard2_after.status_code}")
    if "login" in dashboard2_after.url or dashboard2_after.status_code == 302:
        print("✅ Session 2 correctly redirected to login (GLOBAL LOGOUT WORKING!)")
        return True
    else:
        print("❌ Session 2 still has access (global logout failed)")
        return False

def check_django_admin():
    """Check if we can view active sessions in Django admin"""
    print("\n🔍 Checking Session Tracking (Manual Verification Needed)")
    print("-" * 60)
    print("To verify session tracking works:")
    print("1. Login in two different browsers with the same user")
    print("2. Check Django admin for UserSession records:")
    print(f"   {BASE_URL}/admin/")
    print("3. Perform global logout from one browser")
    print("4. Check that both sessions are invalidated in admin")
    print("5. Verify the other browser is redirected to login on next request")

if __name__ == "__main__":
    print(f"🚀 Starting Global Logout Test at {datetime.now()}")

    try:
        success = test_global_logout()
        if success:
            print("\n🎉 GLOBAL LOGOUT TEST PASSED!")
            print("✅ All sessions properly invalidated")
        else:
            print("\n❌ GLOBAL LOGOUT TEST FAILED!")
            print("❌ Some sessions remained active")

        check_django_admin()

    except Exception as e:
        print(f"\n💥 Test error: {e}")
        print("Make sure Django server is running on localhost:8010")

    print(f"\n🏁 Test completed at {datetime.now()}")