# 🧪 Testing the Login Flow

This document provides step-by-step instructions for testing the complete Keycloak authentication flow.

## 📋 Prerequisites

1. **Keycloak Server**: Make sure your Keycloak server is running at `http://172.28.136.214:8080/`
2. **Django Server**: The Django demo should be running at `http://localhost:8000/`
3. **Valid User**: You need a valid user account in the `teki_9` realm with appropriate roles

## 🌐 Web Interface Testing

### Step 1: Welcome Page
1. Open your browser and navigate to: `http://localhost:8000/`
2. You should see a welcome page with:
   - Keycloak Demo branding
   - Feature overview
   - Sign In button

### Step 2: Login Page
1. Click the "Sign In" button or navigate to: `http://localhost:8000/login/`
2. You should see a login form with:
   - "Sign in with Keycloak" button
   - Demo instructions
   - Loading indicator

### Step 3: Keycloak Authentication
1. Click "Sign in with Keycloak"
2. You'll be redirected to Keycloak's login page
3. Enter your Keycloak credentials:
   - Username: `your_username`
   - Password: `your_password`
4. Complete any required authentication steps (MFA, etc.)

### Step 4: Dashboard Access
1. After successful authentication, you'll be redirected back to the dashboard
2. The dashboard should display:
   - Welcome message with your username
   - User information (email, full name, user ID)
   - Assigned roles with visual badges
   - Permission matrix showing what you can access
   - Session information
   - Quick action buttons to test API endpoints

### Step 5: Logout
1. Click the "Logout" button in the top navigation
2. You'll be redirected to Keycloak's logout page
3. After logout, you'll be returned to the public welcome page

## 🔧 API Testing (After Web Login)

Once you've logged in via the web interface, you can test API endpoints:

### Test Authentication Status
```bash
curl http://localhost:8000/api/auth/status/
```
Expected response:
```json
{
  "authenticated": true,
  "username": "your_username",
  "email": "your_email@example.com",
  "roles": ["user", "admin"]
}
```

### Test Protected Endpoints
```bash
# User dashboard
curl http://localhost:8000/api/dashboard/

# Admin panel (if you have admin role)
curl http://localhost:8000/api/admin/

# Manager panel (if you have admin or manager role)
curl http://localhost:8000/api/manager/
```

## 🔍 Common Issues & Solutions

### Issue: "Authentication failed" error
**Cause**: Invalid credentials or realm configuration
**Solution**:
- Verify your username and password
- Check that the realm name `teki_9` is correct
- Ensure the client `easytask` is properly configured

### Issue: "Invalid state parameter" error
**Cause**: Session state mismatch during OAuth flow
**Solution**:
- Clear browser cookies and cache
- Start the login flow again from the beginning

### Issue: "No authorization code received" error
**Cause**: Keycloak didn't return an authorization code
**Solution**:
- Check Keycloak client configuration
- Ensure redirect URI is properly set to `http://localhost:8000/callback/`

### Issue: Dashboard shows "No valid authentication token found"
**Cause**: Session expired or token invalid
**Solution**:
- Logout and login again
- Check session timeout settings

## 📊 Expected Results

### Successful Login Flow
1. ✅ Welcome page loads correctly
2. ✅ Login page displays with proper styling
3. ✅ Redirect to Keycloak works
4. ✅ Keycloak authentication succeeds
5. ✅ Redirect back to dashboard works
6. ✅ Dashboard shows user information
7. ✅ Roles and permissions display correctly
8. ✅ API endpoints work with session
9. ✅ Logout flow completes successfully

### Security Features Verified
1. ✅ PKCE implementation for secure code exchange
2. ✅ State parameter for CSRF protection
3. ✅ Proper token validation
4. ✅ Session management
5. ✅ Role-based access control
6. ✅ Secure logout implementation

## 🎯 Advanced Testing

### Test Different User Roles
1. **Regular User**: Should see user dashboard, but not admin/manager panels
2. **Manager**: Should see user and manager panels, but not admin panel
3. **Admin**: Should see all panels and have full access

### Test Token Expiration
1. Wait for token to expire (default 1 hour)
2. Try accessing protected endpoints
3. Should be redirected to login automatically

### Test Concurrent Sessions
1. Login in multiple browser tabs
2. Verify session state is consistent
3. Test logout in one tab affects all tabs

This comprehensive testing ensures the Keycloak integration works correctly and securely.