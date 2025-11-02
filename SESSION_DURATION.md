# ⏰ Session Duration Guide

## 📊 Current Session Configuration

### Django Session Settings
- **SESSION_COOKIE_AGE**: `3600` seconds = **1 hour**
- **SESSION_SAVE_EVERY_REQUEST**: `True` (extends session on each activity)
- **SESSION_ENGINE**: Database-backed sessions

### Keycloak Token Settings
- **Access Token**: Default **1 hour** (configurable in Keycloak)
- **ID Token**: Default **1 hour** (configurable in Keycloak)
- **Refresh Token**: Not used in this implementation

## 🔄 How Session Duration Works

### Session Timeline:
```
Login → Django Session Created → 1 Hour Countdown
│
├─ User Activity (clicking, API calls) → Session Extended
│
└─ 1 Hour of Inactivity → Session Expired → Redirect to Login
```

### Key Factors:

#### 1. **Django Session Timeout** (1 hour)
- Session expires after **1 hour of inactivity**
- `SESSION_SAVE_EVERY_REQUEST = True` means any activity resets the timer
- **Activity includes**: Page refreshes, API calls, button clicks

#### 2. **Keycloak Access Token** (1 hour)
- JWT token expires after **1 hour from issuance**
- Token is stored in Django session
- When token expires, API calls will fail

#### 3. **Automatic Session Extension**
- Each user interaction extends the session
- Session timer resets to 1 hour
- Token timer does NOT reset (fixed at 1 hour from login)

## 🎯 Actual User Experience

### **First Hour** (0-60 minutes):
- ✅ Full access to dashboard and APIs
- ✅ Session continuously extended by activity
- ✅ API calls work normally

### **After 1 Hour** (if active):
- ✅ **Django session**: Still active (extended by activity)
- ❌ **Keycloak token**: Expired → API calls fail
- 🔄 **Result**: Dashboard loads, but API buttons return authentication errors

### **After 1 Hour** (if inactive):
- ❌ **Django session**: Expired → Redirected to login
- ❌ **Keycloak token**: Expired
- 🔄 **Result**: Must login again

## 📋 Session Status Indicators

### Dashboard Shows:
```
Session Information:
├─ Authenticated: Yes
├─ Session Token: Active (Django)
└─ Token Present: Yes (Keycloak)
```

### After Token Expiration:
```
API calls return: "Authentication required"
Dashboard still loads (Django session active)
```

### After Session Expiration:
```
Redirected to login page
Must authenticate again
```

## ⚠️ Current Limitations

### **Token Refresh Not Implemented**
- When Keycloak token expires (after 1 hour), user must login again
- No automatic token refresh mechanism
- Django session may outlive the Keycloak token

### **Recommended Improvements**:
1. **Token Refresh**: Implement refresh token flow
2. **Token Validation**: Check token expiration before use
3. **Graceful Logout**: Redirect to login when token expires

## 🔧 Checking Session Status

### Manual Check:
1. Visit dashboard: `http://172.28.136.214:8010/dashboard/`
2. Look at "Session Information" section
3. Check "Session Token" and "Token Present" status

### API Status Check:
1. Click "Check Auth Status" button in dashboard
2. Shows current authentication status
3. Returns `{"authenticated": true, ...}` or `{"authenticated": false, ...}`

### Console Debug:
Check browser console (F12) for middleware logs:
```
Successfully authenticated username for /api/auth/status/ with roles: [...]
```

## 🚀 Session Duration Options

### **Option 1: Keep Current** (1 hour)
- ✅ Simple and secure
- ✅ Works for development
- ❌ Requires re-login after 1 hour

### **Option 2: Extend Django Session**
```python
# In settings.py
SESSION_COOKIE_AGE = 7200  # 2 hours
SESSION_COOKIE_AGE = 14400  # 4 hours
SESSION_COOKIE_AGE = 28800  # 8 hours
```

### **Option 3: Implement Token Refresh**
- Complex but seamless user experience
- Requires refresh token implementation
- Recommended for production

### **Option 4: Longer Keycloak Tokens**
- Configure in Keycloak admin console
- Navigate: Realm Settings → Tokens
- Adjust "Access Token Lifespan"

## 🔄 Current Behavior Summary

| Time Since Login | Django Session | Keycloak Token | User Experience |
|------------------|----------------|-----------------|-----------------|
| 0-60 minutes     | ✅ Active      | ✅ Valid        | Full access |
| 60+ minutes      | ✅ Extended*    | ❌ Expired      | Dashboard works, APIs fail |
| 60+ minutes (idle)| ❌ Expired      | ❌ Expired      | Redirect to login |

*Only if user has been active (clicking, refreshing)

## 💡 Quick Test

To test session behavior:
1. **Login to dashboard**
2. **Wait 1+ hour** (or modify settings to test faster)
3. **Try API buttons** → Should fail after token expiration
4. **Refresh dashboard** → May still work (Django session)
5. **Wait for inactivity** → Should redirect to login

## 🎯 Recommendation

For **development**: Current 1-hour setup is fine
For **production**: Implement token refresh for better UX

**Your session will be active for 1 hour of inactivity, but API access will stop after exactly 1 hour from login due to Keycloak token expiration.**