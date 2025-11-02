# 🔍 Debug Guide for Token Issues

This guide provides quick steps to diagnose and fix the "Failed to obtain access token" error.

## 🚀 Quick Debugging Steps

### Step 1: Check Server Output
The Django app now includes enhanced debug logging. Try to login and check the console for detailed error messages.

### Step 2: Run Configuration Checks
```bash
# Check overall configuration
python check_keycloak_config.py

# Test token endpoint specifically
python debug_token_exchange.py
```

### Step 3: Test OAuth2 Flow Without PKCE
```bash
# Generate test URL
python simple_auth_test.py

# Follow the instructions, then:
python simple_auth_test.py --callback 'FULL_CALLBACK_URL_FROM_BROWSER'
```

## 📊 Most Likely Issues & Solutions

### Issue: PKCE (Proof Key for Code Exchange) Problems
**Symptoms**: Token exchange fails during callback processing
**Quick Fix**: Try the simple OAuth2 test without PKCE

### Issue: Redirect URI Mismatch
**Symptoms**: "Invalid parameter: redirect_uri" error
**Fix**: Ensure Keycloak client has `http://localhost:8000/*` in Valid Redirect URIs

### Issue: Client Secret Mismatch
**Symptoms**: "Unauthorized" or "Client authentication failed" error
**Fix**: Copy the exact client secret from Keycloak admin console

### Issue: Session Problems
**Symptoms**: "Code verifier present: False" in debug output
**Fix**: Check browser cookies, restart Django server

## 🛠️ Debug Tools Created

### 1. Enhanced Django Logging
The Django app now logs detailed information during authentication:
- Token URL and request data
- Client configuration details
- PKCE parameters
- Keycloak response details

### 2. Configuration Checker (`check_keycloak_config.py`)
Tests:
- Keycloak server connectivity
- Realm existence
- Client accessibility
- OIDC discovery endpoint
- JWKS public keys

### 3. Token Endpoint Debugger (`debug_token_exchange.py`)
Tests:
- Token endpoint accessibility
- Client credentials grant
- Mock authorization code exchange
- OIDC configuration retrieval

### 4. Simple OAuth2 Test (`simple_auth_test.py`)
Provides:
- Authorization URL without PKCE
- Manual code exchange testing
- Isolates PKCE from basic OAuth2 flow

## 🎯 Expected Debug Output

### Successful Token Exchange:
```
Keycloak token URL: http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/token
Token request data: {...}
Client ID: easytask
Client Secret: ***************************
Code verifier present: True
Token response status: 200
Token response body: {"access_token":"eyJ...", "token_type":"Bearer", ...}
```

### Common Error Messages and Solutions:

#### "invalid_client_credentials"
**Problem**: Client secret is wrong
**Solution**: Copy exact secret from Keycloak admin → Clients → easytask → Credentials

#### "invalid_grant"
**Problem**: Authorization code is invalid/expired or redirect URI mismatch
**Solution**: Check redirect URI in Keycloak client configuration

#### "unauthorized_client"
**Problem**: Client not configured for authorization code flow
**Solution**: Ensure "Standard Flow Enabled" is ON in Keycloak client settings

#### "invalid_redirect_uri"
**Problem**: Redirect URI doesn't match Keycloak configuration
**Solution**: Add exact redirect URI to Keycloak client's Valid Redirect URIs

## 📋 Quick Diagnosis Checklist

When you get "Failed to obtain access token":

- [ ] Run `python check_keycloak_config.py` - all checks pass?
- [ ] Run `python debug_token_exchange.py` - client credentials work?
- [ ] Try `python simple_auth_test.py` - basic OAuth2 flow works?
- [ ] Check Django console for detailed error messages
- [ ] Verify Keycloak client configuration matches requirements
- [ ] Check that browser isn't blocking cookies
- [ ] Try with incognito/private browser window

## 🔧 If All Else Fails

### Temporary Fix: Disable PKCE
For development/testing, you can temporarily disable PKCE:

1. Comment out PKCE-related code in `app/views.py`
2. Remove `code_challenge` and `code_challenge_method` from auth_params
3. Remove `code_verifier` from token exchange request

This will help isolate whether PKCE is the issue or something else.

### Production Considerations
- Always use PKCE in production
- Ensure HTTPS is configured
- Use strong client secrets
- Enable proper token expiration policies

## 🎉 Success Indicators

You'll know it's working when:
1. ✅ Configuration checker passes all tests
2. ✅ Token endpoint debugger shows success
3. ✅ Django console shows 200 status for token exchange
4. ✅ You're redirected to dashboard with user information

Good luck debugging! The tools provided should help identify and resolve any token exchange issues.