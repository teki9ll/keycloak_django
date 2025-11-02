# 🔧 Troubleshooting Guide

This guide helps diagnose and fix common issues with the Django Keycloak integration, particularly the "Failed to obtain access token" error.

## 🚨 Common Issue: "Failed to obtain access token"

### 📋 Quick Diagnosis

1. **Check Server Logs**: Look for detailed error messages in Django console output
2. **Run Debug Script**: `python debug_token_exchange.py` to test Keycloak connectivity
3. **Verify Configuration**: Run `python check_keycloak_config.py` for full validation

### 🔥 Quick Fix: PKCE Issue

If you see "PKCE verification failed: Code mismatch", run this fix:

```bash
# Apply the PKCE fix (for development/testing)
python fix_pkce_issue.py

# Then restart Django server
python manage.py runserver 0.0.0.0:8000

# To restore original PKCE later:
python fix_pkce_issue.py --restore
```

This fix:
- ✅ Disables PKCE (removes the code mismatch issue)
- ✅ Fixes redirect URI port conflicts
- ✅ Allows login to work immediately
- ⚠️ Should be re-enabled for production

### 🔍 Most Common Causes

#### 1. **PKCE (Proof Key for Code Exchange) Issues**

**Problem**: Django generates a PKCE code verifier, but Keycloak isn't configured to handle it properly.

**Solution**: Ensure the Keycloak client supports PKCE:
```bash
# Check if client has PKCE enabled (Keycloak 15+)
# In Keycloak admin: Clients → easytask → Advanced → Proof Key for Code Exchange Challenge Method
# Should be set to "S256" or left default
```

#### 2. **Redirect URI Mismatch**

**Problem**: The redirect URI in the token request doesn't exactly match what's configured in Keycloak.

**Check**: Compare these values:
- Django generates: `http://localhost:8000/callback/`
- Keycloak expects: `http://localhost:8000/callback/*` (or exact match)

**Solution**: In Keycloak admin → Clients → easytask → Settings → Valid Redirect URIs:
```
http://localhost:8000/*
http://localhost:8000/callback/*
```

#### 3. **Session Issues**

**Problem**: Session data is lost between login and callback.

**Debug**: Check server logs for "Code verifier present: False"

**Solution**: Ensure session middleware is properly configured:
- Django sessions should be working
- Browser must accept cookies
- No conflicting session settings

#### 4. **Client Secret Mismatch**

**Problem**: Client secret in `.env` doesn't match Keycloak.

**Debug**: Look for "Client Secret: None" in debug output

**Solution**:
1. Go to Keycloak admin → Clients → easytask → Credentials
2. Copy the exact client secret
3. Update `.env` file
4. Restart Django server

#### 5. **Authorization Code Expiration**

**Problem**: Authorization code expires before token exchange.

**Solution**: Token exchange should happen immediately after callback. If it's taking too long, the code might expire.

### 🛠️ Step-by-Step Debugging

#### Step 1: Enable Debug Logging

The Django app now includes enhanced debug logging. When you attempt to login, check the console output for:
```
Keycloak token URL: http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/token
Token request data: {...}
Client ID: easytask
Client Secret: ***************************
Code verifier present: True/False
Token response status: XXX
Token response body: {...}
```

#### Step 2: Run Configuration Checks

```bash
# Test basic Keycloak connectivity
python check_keycloak_config.py

# Test token endpoint specifically
python debug_token_exchange.py
```

#### Step 3: Manual Token Exchange Test

Create a simple test script to isolate the issue:

```python
import requests

# Test the exact same request Django is making
token_url = "http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/token"
token_data = {
    'grant_type': 'authorization_code',
    'client_id': 'easytask',
    'client_secret': 'FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa',
    'code': 'YOUR_AUTHORIZATION_CODE',  # Get this from browser URL
    'redirect_uri': 'http://localhost:8000/callback/',
    'code_verifier': 'YOUR_CODE_VERIFIER',  # Get this from Django session
}

response = requests.post(token_url, data=token_data)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

### 📊 Expected vs Actual Behavior

#### Expected Flow:
1. User clicks login → Django generates PKCE parameters
2. Redirect to Keycloak with `code_challenge`
3. User authenticates → Keycloak redirects back with `code`
4. Django exchanges `code` + `code_verifier` for `access_token`
5. Success: User redirected to dashboard

#### Current Issue:
- Steps 1-3 work (we see the callback with auth code)
- Step 4 fails with "Failed to obtain access token"

### 🔧 Specific Solutions

#### Solution 1: Disable PKCE for Testing

If PKCE is causing issues, temporarily disable it to test basic auth flow:

**In `app/views.py`, modify the login function:**
```python
def login(request):
    if getattr(request.user, 'is_authenticated', False):
        return redirect('dashboard')

    if request.method == 'POST':
        # Disable PKCE for testing
        # code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        # request.session['pkce_code_verifier'] = code_verifier

        # code_challenge = base64.urlsafe_b64encode(
        #     code_verifier.encode('utf-8')
        # ).decode('utf-8').rstrip('=')

        # Build Keycloak authorization URL without PKCE
        auth_params = {
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': request.build_absolute_uri('/callback/'),
            'state': state,
            # 'code_challenge': code_challenge,
            # 'code_challenge_method': 'S256',
        }

        auth_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/auth?{urlencode(auth_params)}"
        return redirect(auth_url)

    return render(request, 'app/login.html')
```

**In `app/views.py`, modify the callback function:**
```python
def callback(request):
    # ... existing code ...

    try:
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': request.build_absolute_uri('/callback/'),
            # 'code_verifier': request.session.get('pkce_code_verifier'),  # Remove this
        }
        # ... rest of the code
```

#### Solution 2: Check Keycloak Client Configuration

In Keycloak admin console:

1. **Go to Clients → easytask**
2. **Settings tab**:
   - Access Type: `confidential`
   - Standard Flow Enabled: `ON`
   - Direct Access Grants Enabled: `ON`
   - Service Accounts Enabled: `OFF`
   - Authorization Enabled: `OFF`

3. **Valid Redirect URIs**:
   ```
   http://localhost:8000/*
   http://localhost:8000/callback/*
   ```

4. **Web Origins**:
   ```
   http://localhost:8000
   ```

5. **Fine Grain OpenID Connect Configuration**:
   - Application Type: `web app`
   - ID Token Signature Algorithm: `RS256`
   - Request Object Signature Algorithm: `RS256`

#### Solution 3: Check Realm Settings

In Keycloak admin → Realm Settings → Login:

- Require SSL: `none` (for development)
- Registration: Turn off email verification for testing
- Forgot Password: Turn off for testing
- Remember Me: Enable if needed

### 🧪 Test Scenarios

#### Test 1: Simple Authorization Code Flow

1. Visit: `http://localhost:8000/login/`
2. Click "Sign in with Keycloak"
3. Authenticate with Keycloak
4. **Stop here** - copy the full callback URL from browser
5. Extract the `code` parameter
6. Test the token exchange manually

#### Test 2: Client Credentials Flow

The debug script already confirmed this works, proving:
- ✅ Client ID is correct
- ✅ Client secret is correct
- ✅ Token endpoint is accessible
- ✅ Basic Keycloak configuration is working

#### Test 3: Remove PKCE Completely

If PKCE continues to cause issues, the application can work without it for development purposes.

### 📞 Getting Help

If the issue persists:

1. **Collect Debug Information**:
   - Full Django console output during login attempt
   - Keycloak server logs (if accessible)
   - Browser developer tools output

2. **Verify Environment**:
   - Keycloak server version
   - Django version
   - Network connectivity between Django and Keycloak

3. **Isolate the Issue**:
   - Test with a fresh browser/incognito window
   - Clear browser cookies and cache
   - Restart Django server
   - Restart Keycloak server (if possible)

### ✅ Success Indicators

You'll know it's working when you see:
```
Keycloak token URL: http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/token
Token request data: {...}
Token response status: 200
Token response body: {"access_token":"eyJ...", "token_type":"Bearer", ...}
```

And then get redirected to the dashboard with user information displayed!