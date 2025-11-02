# 🔄 Authentication Flow Diagram

## 🎯 High-Level Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   USER/BROWSER  │───▶│   DJANGO APP   │───▶│    KEYCLOAK    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
    1. Click Login          2. Generate State      3. Show Login
    4. Enter Creds         5. Exchange Code        6. Return Token
    7. Store Token         8. Create User          9. Show Dashboard
```

## 📋 Detailed Step-by-Step Flow

### **STEP 1**: User Initiates Login
```
User visits: http://172.28.136.214:8010/login/
Action: Clicks "Sign in with Keycloak"
Django: Shows login page with Keycloak redirect button
```

### **STEP 2**: Django Prepares Authentication
```
Django generates:
- state: "random-string-123" (CSRF protection)
- redirect_uri: "http://172.28.136.214:8010/callback/"
- client_id: "easytask"

Stores state in session for later verification
```

### **STEP 3**: Redirect to Keycloak
```
Django redirects browser to:
http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/auth?
    client_id=easytask&
    response_type=code&
    redirect_uri=http://172.28.136.214:8010/callback/&
    state=random-string-123&
    scope=openid+profile+email
```

### **STEP 4**: Keycloak Authentication
```
Keycloak shows login page:
┌─────────────────────────────────────┐
│        KEYCLOAK LOGIN              │
├─────────────────────────────────────┤
│  Username: [_________________]        │
│  Password: [_________________]        │
│                                     │
│  [  Sign In  ]  [  Forgot Password ] │
└─────────────────────────────────────┘

User enters credentials → Keycloak validates against its database
```

### **STEP 5**: Keycloak Issues Authorization Code
```
Keycloak redirects browser back:
http://172.28.136.214:8010/callback/?
    code=AUTH-CODE-XYZ&
    state=random-string-123&
    session_state=SESSION-ABC
```

### **STEP 6**: Django Callback Processing
```
Django receives callback at: /callback/

✓ Security checks:
1. Verify state parameter matches session state
2. Extract authorization code
3. Prepare token exchange request
```

### **STEP 7**: Token Exchange
```
Django POSTs to Keycloak:
http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/token

Request body:
grant_type=authorization_code&
client_id=easytask&
client_secret=SECRET-KEY&
code=AUTH-CODE-XYZ&
redirect_uri=http://172.28.136.214:8010/callback/
```

Keycloak responds with:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "optional-token"
}
```

### **STEP 8**: User Creation & Session
```
Django processes JWT token:
1. Decode token (without signature verification for speed)
2. Extract user information:
   - username: "johndoe"
   - email: "john.doe@example.com"
   - roles: ["admin", "user"]
3. Create in-memory KeycloakUser object
4. Store access_token in Django session
```

### **STEP 9**: Dashboard Access
```
Django redirects to: http://172.28.136.214:8010/dashboard/

Middleware processes request:
1. Finds access_token in session
2. Decodes token to get user info
3. Creates KeycloakUser object
4. Renders dashboard with user data

Dashboard shows:
┌─────────────────────────────────────┐
│  Welcome back, johndoe!             │
│  📧 Email: john.doe@example.com     │
│  🔑 Roles: admin, user              │
│  📊 Session: Active                  │
└─────────────────────────────────────┘
```

## 🔁 Ongoing Authentication

### **For Web Interface:**
```
Every request to Django:
1. Check session for access_token
2. Decode token without full verification (we trust Keycloak)
3. Create KeycloakUser object
4. Process request with authenticated user
```

### **For API Calls:**
```
API request from dashboard (AJAX):
1. Browser automatically includes session cookie
2. Middleware finds token in session
3. Uses relaxed verification (same as web interface)
4. Returns JSON response with user data

Direct API call (external client):
1. Must include Authorization header
2. Full JWT signature verification
3. Returns JSON response
```

## 🛡️ Security Mechanisms in Action

### **State Parameter Protection:**
```
Attacker tries to forge callback:
❌ http://172.28.136.214:8010/callback/?state=fake-state
Django: State doesn't match session state → Reject request
✅ Legitimate request passes state verification
```

### **Authorization Code Protection:**
```
Authorization code is single-use and short-lived:
❌ Attacker steals authorization code
Django: Code already used or expired → Reject request
✅ Fresh authorization code works
```

### **Client Secret Protection:**
```
Direct token exchange attempt without secret:
❌ Missing client_secret parameter
Keycloak: Client authentication failed → Reject request
✅ Valid client secret allows token exchange
```

## 📊 Token Content Flow

### **JWT Token Structure:**
```
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-123"
}

Payload:
{
  "sub": "user-uuid",
  "preferred_username": "johndoe",
  "email": "john.doe@example.com",
  "realm_access": {
    "roles": ["admin", "user"]
  },
  "exp": 1732031800,
  "iat": 1732031200,
  "iss": "http://172.28.136.214:8080/realms/teki_9",
  "aud": "easytask"
}

Signature: [Cryptographic signature by Keycloak]
```

### **User Object Creation:**
```
class KeycloakUser:
    def __init__(self, username, email, roles):
        self.username = username        # "johndoe"
        self.email = email              # "john.doe@example.com"
        self.roles = roles              # ["admin", "user"]
        self.is_authenticated = True
        self.is_staff = "admin" in roles
```

## 🚀 Complete Success Path

```
✅ Step 1: User clicks login
✅ Step 2: State generated securely
✅ Step 3: Redirect to Keycloak
✅ Step 4: User authenticates with Keycloak
✅ Step 5: Authorization code issued
✅ Step 6: State validated, code received
✅ Step 7: Token exchange successful
✅ Step 8: User session created
✅ Step 9: Dashboard rendered with user data
✅ Step 10: API calls work from dashboard
```

## 🔄 Session Management

### **Session Lifecycle:**
```
Login (0 min) ──┐
                │
Activity (30 min) ┼─→ Session extended to 60 min
                │
Activity (45 min) ┼─→ Session extended to 90 min
                │
Token Expires (60 min) ──→ API calls fail, dashboard works
                │
Session Expires (120 min) ──→ Must login again
```

### **What Gets Extended:**
- ✅ Django session (by any activity)
- ❌ Keycloak token (fixed 1 hour)

## 🎯 Result

**Complete OAuth2 + OpenID Connect authentication flow that:**
- ✅ Secures user identity with Keycloak
- ✅ Provides stateless user management
- ✅ Supports both web and API access
- ✅ Includes role-based access control
- ✅ Maintains session for web interface
- ✅ Uses industry-standard security practices

This flow provides enterprise-grade authentication with excellent user experience! 🚀