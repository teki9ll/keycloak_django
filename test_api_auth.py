#!/usr/bin/env python3
"""
Test API authentication from the browser session
"""

import requests
import json

def test_api_endpoints():
    """Test API endpoints to see authentication status"""

    base_url = "http://172.28.136.214:8010"

    print("🔍 Testing API Authentication")
    print("=" * 50)

    # Test endpoints
    endpoints = [
        "/api/dashboard/",
        "/api/auth/status/",
        "/api/admin/",
        "/api/manager/",
    ]

    for endpoint in endpoints:
        url = base_url + endpoint
        print(f"\n📍 Testing: {url}")

        try:
            response = requests.get(url, timeout=10)
            print(f"   Status: {response.status_code}")

            try:
                data = response.json()
                if 'error' in data:
                    print(f"   Error: {data['error']}")
                elif 'authenticated' in data:
                    print(f"   Authenticated: {data['authenticated']}")
                    if data['authenticated']:
                        print(f"   Username: {data.get('username', 'N/A')}")
                        print(f"   Roles: {data.get('roles', [])}")
                else:
                    print(f"   Response: {json.dumps(data, indent=2)}")
            except:
                print(f"   Response: {response.text[:200]}")

        except requests.exceptions.RequestException as e:
            print(f"   Request failed: {e}")

def test_with_session():
    """Test API with session cookie (simulating browser)"""
    print("\n\n🍪 Testing with Session Cookie Simulation")
    print("=" * 50)

    # Create a session to simulate browser
    session = requests.Session()

    # First, try to access dashboard (should redirect to login if not authenticated)
    print("1. Testing dashboard access...")
    response = session.get("http://172.28.136.214:8010/dashboard/", allow_redirects=False)
    print(f"   Status: {response.status_code}")

    if response.status_code == 302:
        print("   → Redirected to login (expected for unauthenticated)")

    print("\n2. Testing API without authentication...")
    response = session.get("http://172.28.136.214:8010/api/dashboard/")
    print(f"   Status: {response.status_code}")
    try:
        print(f"   Response: {response.json()}")
    except:
        print(f"   Response: {response.text[:100]}")

if __name__ == "__main__":
    test_api_endpoints()
    test_with_session()

    print("\n\n💡 Debugging Tips:")
    print("1. Check Django console for debug messages")
    print("2. Try logging in via browser first")
    print("3. Then test API endpoints in browser")
    print("4. Look for 'Successfully authenticated' messages in console")