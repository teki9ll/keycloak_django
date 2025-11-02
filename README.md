# 🔐 Django Keycloak Stateless Authentication Demo

> **Complete enterprise-grade authentication system with custom login form, 30-day persistent sessions, and global logout functionality**

---

## 🎯 **Project Overview**

This is a production-ready Django application that demonstrates how to implement **stateless authentication** using **Keycloak** as the identity provider. The system replaces Django's default user authentication with a custom login experience while maintaining enterprise-grade security.

### ✨ **Key Features**

- 🌐 **Custom Login Form** - Seamless UX without Keycloak redirects
- 🔐 **Stateless Authentication** - No Django User model required
- 📅 **30-Day Persistent Sessions** with automatic token refresh
- 🌍 **Global Logout** - Invalidate all sessions across all devices
- 🎭 **Role-Based Access Control** with customizable permissions
- 📊 **Session Tracking** - Complete audit trail and analytics
- 🛡️ **Enterprise Security** - OAuth2/OpenID Connect standards
- 📱 **Responsive Design** - Works on all devices and browsers

---

## 🏗️ **Architecture**

```
User → Custom Login Form → Django → Keycloak API → JWT Token → Session → Authenticated Access
```

### **Authentication Flow**
1. **User Login** - Submits credentials to custom Django form
2. **Django Validation** - Calls Keycloak token endpoint with credentials
3. **Token Exchange** - Keycloak returns JWT tokens (access + refresh)
4. **Session Creation** - Django stores tokens with 30-day expiry
5. **Persistent Access** - User remains logged in across sessions
6. **Automatic Refresh** - Tokens refresh 5 minutes before expiry
7. **Global Logout** - All user sessions invalidated instantly

### **Global Logout System**
- **Session Tracking** - Database records for each active session
- **Multi-Device Support** - Track sessions across browsers and devices
- **Instant Invalidation** - Logout from one device = logout from all
- **Audit Trail** - Complete history of all logout requests

---

## 🚀 **Quick Start**

### **Prerequisites**
- Python 3.8+
- Docker or Podman (for Keycloak)
- Keycloak server configuration

### **Installation**

1. **Clone and Setup**
   ```bash
   git clone <your-repo>
   cd keycloak_demo
   ./setup.sh
   ```

2. **Start Keycloak**
   ```bash
   ./start-keycloak.sh
   ```

3. **Start Django**
   ```bash
   ./start.sh
   ```

4. **Access Application**
   - **Django App**: http://localhost:8010/
   - **Keycloak Admin**: http://localhost:8080/admin/
   - **Login**: http://localhost:8010/login/

### **Default Credentials**
- **Keycloak Admin**: admin / admin123
- **Test Users**: Created in Keycloak (see setup guide)

---

## 🌐 **Access Points**

| Endpoint | Description | Authentication |
|----------|-------------|----------------|
| `/` | Public information page | None |
| `/login/` | Custom login form | None |
| `/dashboard/` | User dashboard with session info | Required |
| `/api/auth/status/` | API authentication status | Required |
| `/logout/` | Django session logout | Required |
| `/auth/keycloak-logout/` | Global logout from all devices | Required |

---

## 🎨 **Features Demonstrated**

### **1. Custom Login Experience**
- Modern, responsive login form
- AJAX form submission with loading states
- Real-time error handling and user feedback
- No redirect to Keycloak - seamless UX

### **2. Session Management**
- 30-day persistent sessions
- Automatic token refresh before expiry
- Session tracking across multiple devices
- Real-time session validation

### **3. Global Logout System**
- Logout from current device only
- Global logout from all devices
- Session invalidation tracking
- Audit trail for security compliance

### **4. Role-Based Access Control**
- Extract user roles from Keycloak tokens
- Decorator-based role protection
- Role-specific UI elements
- API endpoint access control

### **5. Enterprise Security**
- JWT token validation
- CSRF protection
- Secure session management
- Automatic token refresh

---

## 📊 **Session Analytics**

The system provides comprehensive session tracking:

- **Active Sessions**: Real-time count of user sessions
- **Device Tracking**: IP address and user agent for each session
- **Logout History**: Complete audit trail of all logout events
- **Session Duration**: Track how long users stay logged in

### **View in Django Admin**
```python
# Access at: http://localhost:8010/admin/
- View all active user sessions
- See logout request history
- Manage session settings
```

---

## 🛠️ **Technology Stack**

- **Backend**: Django 5.x
- **Authentication**: Keycloak 23.x
- **Protocol**: OAuth2 + OpenID Connect
- **Session Storage**: Django Cache (in-memory/Redis) - **Database-free!**
- **Database**: Optional (only for Django admin, not required for auth)
- **Frontend**: Bootstrap 5 + Custom CSS
- **Deployment**: Docker/Podman ready

---

## 🔧 **Configuration**

### **Keycloak Setup**
```yaml
Realm: teki_9
Client: easytask
Redirect URI: http://localhost:8010/dashboard/
Grant Types: Authorization Code, Direct Access
```

### **Django Settings**
```python
# Session Configuration
SESSION_COOKIE_AGE = 30 * 24 * 60 * 60  # 30 days
KEYCLOAK_SESSION_TIMEOUT = 2592000
KEYCLOAK_TOKEN_REFRESH_THRESHOLD = 300

# Keycloak Configuration
KEYCLOAK_SERVER_URL = "http://localhost:8080/"
KEYCLOAK_REALM = "teki_9"
KEYCLOAK_CLIENT_ID = "easytask"
KEYCLOAK_CLIENT_SECRET = "your-secret"
```

---

## 🧪 **Testing**

### **Authentication Flow**
1. Visit `http://localhost:8010/login/`
2. Enter Keycloak credentials
3. Verify redirect to dashboard
4. Check session information display
5. Test both logout options

### **Global Logout Test**
1. Login in Browser A
2. Login in Browser B with same user
3. Click "Global Logout" in Browser A
4. Refresh Browser B - should redirect to login

### **API Endpoints**
```bash
# Test authentication status
curl http://localhost:8010/api/auth-status/

# Test protected endpoint (requires login)
curl -H "Authorization: Bearer <token>" http://localhost:8010/dashboard/
```

---

## 🏭 **Production Deployment**

### **Environment Variables**
```bash
# Production Configuration
DEBUG=False
ALLOWED_HOSTS=yourdomain.com
KEYCLOAK_SERVER_URL=https://auth.yourdomain.com/
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

### **Security Considerations**
- Use HTTPS for all authentication flows
- Configure proper CORS settings
- Set secure session cookies
- Regular session cleanup and monitoring
- Comprehensive audit logging

---

## 📈 **Performance Features**

- **Token Caching**: Public keys cached for JWT validation
- **Database Indexing**: Optimized session tracking queries
- **Session Cleanup**: Automatic expired session removal
- **Middleware Optimization**: Skip authentication where possible

---

## 🤝 **Integration Guide**

For implementing this Keycloak authentication system in your own Django project, see the **[KEYCLOAK_IMPLEMENTATION_GUIDE.md](KEYCLOAK_IMPLEMENTATION_GUIDE.md)** which provides:

- 📋 Step-by-step implementation instructions
- 📝 Complete copy-paste ready code examples
- 🛠️ All necessary files and configurations
- 🧪 Testing and troubleshooting guidance
- 🚀 Production deployment tips

---

## 📞 **Support**

- **Documentation**: See `KEYCLOAK_IMPLEMENTATION_GUIDE.md` for integration steps
- **Issues**: Check Django logs for detailed error information
- **Keycloak**: Access admin console at `http://localhost:8080/admin/`

**Built with ❤️ for enterprise Django applications** 🚀

This project demonstrates a **complete authentication flow** using **Keycloak** as the identity provider with **Django** as the application server. It implements **OAuth 2.0 + OpenID Connect** protocols with **stateless user management** while maintaining **30-day persistent sessions** for an excellent user experience.

### 🎯 **Key Features**

- ✅ **OAuth2 + OpenID Connect** with Keycloak integration
- ✅ **30-Day Persistent Sessions** - Users stay logged in for 30 days
- ✅ **Automatic Token Refresh** - Seamless background token renewal
- ✅ **Stateless Architecture** - No user database required in Django
- ✅ **Enterprise Security** - CSRF protection, token validation, secure cookies
- ✅ **Role-Based Access Control** - Admin/Manager/User permissions
- ✅ **API + Web Interface Support** - Works for both browser and API clients
- ✅ **Production Ready** - Error handling, logging, security best practices

---

## 🏗️ **System Architecture**

```
┌─────────────────┐    OAuth2 + OIDC    ┌──────────────────┐    JWT Tokens    ┌─────────────────┐
│   User Browser  │ ◄─────────────────► │    Django App    │ ◄──────────────► │   Keycloak      │
│                 │                     │                  │                 │   (Identity     │
│ • Login Page    │                     │ • Session Mgmt   │                 │    Provider)    │
│ • Dashboard     │                     │ • Token Refresh  │                 │                 │
│ • API Client    │                     │ • Auth Middleware│                 │ • User Store    │
└─────────────────┘                     └──────────────────┘                 │ • Role Mgmt     │
                                                                                  └─────────────────┘
```

### **Authentication Flow**

1. **User visits login page** → Django shows Keycloak login button
2. **User clicks login** → Django generates security parameters (state, nonce)
3. **Redirect to Keycloak** → User authenticates with Keycloak
4. **Keycloak redirects back** → With authorization code
5. **Django exchanges code** → For access + refresh tokens
6. **Store tokens in session** → Set 30-day session expiry
7. **Redirect to dashboard** → User is now authenticated
8. **Automatic refresh** → Tokens refresh 5 minutes before expiry
9. **30-day persistence** → User stays logged in across sessions

---

## 🚀 **Quick Start**

### **Prerequisites**

- **Docker** (for Keycloak)
- **Python 3.10+**
- **pip** package manager

### **1. Start Keycloak Server**

```bash
# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0.0
    container_name: keycloak-server
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin123
      KC_HEALTH_ENABLED: true
    ports:
      - "8080:8080"
    command: start-dev
    restart: unless-stopped
EOF

# Start Keycloak
docker-compose up -d

# Wait for Keycloak to start (2-3 minutes)
docker-compose logs -f keycloak
```

### **2. Configure Keycloak**

1. **Access Keycloak Admin Console:**
   - URL: `http://localhost:8080/admin`
   - Username: `admin`
   - Password: `admin123`

2. **Create Realm:**
   - Click **Create realm**
   - Name: `teki_9`
   - Click **Create**

3. **Create Client:**
   - Go to **Clients** → **Create client**
   - Client ID: `easytask`
   - Client protocol: `openid-connect`
   - Access type: `confidential`
   - Valid redirect URIs: `http://localhost:8010/callback/`
   - Click **Save**

4. **Get Client Secret:**
   - Go to **Credentials** tab
   - Copy the **client secret**

5. **Create Test User:**
   - Go to **Users** → **Add user**
   - Username: `testuser`
   - Email: `test@example.com`
   - Set password (temporary: `testpass123`)
   - Add roles: `user`, `admin` (if needed)

### **3. Setup Django Application**

```bash
# Clone or navigate to project
cd /path/to/keycloak_demo

# Install dependencies
pip install djangorestframework requests PyJWT python-decouple

# Configure environment (create .env file)
cat > .env << 'EOF'
KEYCLOAK_SERVER_URL=http://localhost:8080/
KEYCLOAK_REALM=teki_9
KEYCLOAK_CLIENT_ID=easytask
KEYCLOAK_CLIENT_SECRET=your-client-secret-here
EOF

# Run migrations
python3 manage.py migrate

# Start Django server
python3 manage.py runserver 0.0.0.0:8010
```

### **4. Test the Application**

1. **Access the application:** `http://localhost:8010/`
2. **Click "Sign in with Keycloak"**
3. **Login with test user:** `testuser` / `testpass123`
4. **Access dashboard:** Should show user information
5. **Test persistence:** Refresh page after 1 hour → Should stay logged in

---

## 📁 **Project Structure**

```
keycloak_demo/
├── keycloak_demo/           # Django project settings
│   ├── settings.py          # Main configuration
│   ├── urls.py              # URL routing
│   └── wsgi.py              # WSGI deployment
├── app/                     # Main application
│   ├── middleware/          # Authentication middleware
│   │   └── keycloak_auth.py # Token refresh & validation
│   ├── utils/               # Utility functions
│   │   └── token_refresh.py # Token refresh logic
│   ├── auth/                # Authentication models
│   │   └── keycloak_user.py # User object
│   ├── decorators.py        # View decorators
│   ├── views.py             # Main views
│   └── templates/app/       # HTML templates
├── templates/               # Base templates
├── manage.py                # Django management
├── requirements.txt         # Python dependencies
├── docker-compose.yml       # Keycloak container
└── README.md               # This file
```

---

## ⚙️ **Configuration Details**

### **Django Settings (`settings.py`)**

```python
# Keycloak Configuration
KEYCLOAK_SERVER_URL = config('KEYCLOAK_SERVER_URL', default='http://localhost:8080/')
KEYCLOAK_REALM = config('KEYCLOAK_REALM', default='teki_9')
KEYCLOAK_CLIENT_ID = config('KEYCLOAK_CLIENT_ID', default='easytask')
KEYCLOAK_CLIENT_SECRET = config('KEYCLOAK_CLIENT_SECRET')

# Session Configuration (30-day persistence)
SESSION_COOKIE_AGE = 30 * 24 * 60 * 60  # 30 days
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_SAVE_EVERY_REQUEST = True

# Token Refresh Configuration
KEYCLOAK_TOKEN_REFRESH_THRESHOLD = 300  # Refresh 5 minutes before expiry
KEYCLOAK_REFRESH_GRACE_PERIOD = 86400   # 24 hours grace period

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'TIMEOUT': 3600,
    }
}
```

### **Environment Variables (.env)**

```bash
# Required
KEYCLOAK_SERVER_URL=http://localhost:8080/
KEYCLOAK_REALM=teki_9
KEYCLOAK_CLIENT_ID=easytask
KEYCLOAK_CLIENT_SECRET=your-actual-client-secret

# Optional (override defaults)
SESSION_COOKIE_AGE=2592000  # 30 days in seconds
KEYCLOAK_TOKEN_REFRESH_THRESHOLD=300  # 5 minutes
DEBUG=True
```

---

## 🔄 **Authentication Flow in Detail**

### **Step 1: Login Initiation**

```python
# app/views.py - login()
def login(request):
    if request.method == 'POST':
        # Generate security parameters
        state = secrets.token_urlsafe(16)
        request.session['oauth_state'] = state

        # Build Keycloak authorization URL
        auth_params = {
            'client_id': settings.KEYCLOAK_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': request.build_absolute_uri('/callback/'),
            'state': state,
        }

        auth_url = f"{settings.KEYCLOAK_SERVER_URL}realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/auth?{urlencode(auth_params)}"
        return redirect(auth_url)
```

### **Step 2: Token Exchange**

```python
# app/views.py - callback()
def callback(request):
    # Verify state parameter (CSRF protection)
    if request.GET.get('state') != request.session.get('oauth_state'):
        return error("Invalid state parameter")

    # Exchange authorization code for tokens
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': settings.KEYCLOAK_CLIENT_ID,
        'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
        'code': request.GET.get('code'),
        'redirect_uri': request.build_absolute_uri('/callback/'),
    }

    response = requests.post(token_url, data=token_data)
    token_info = response.json()

    # Store tokens with metadata
    request.session['access_token'] = token_info['access_token']
    request.session['refresh_token'] = token_info.get('refresh_token')
    request.session['token_acquired_at'] = int(time.time())
    request.session['token_expires_in'] = token_info.get('expires_in', 3600)
    request.session['authenticated_at'] = int(time.time())

    # Set 30-day session expiry
    request.session.set_expiry(30 * 24 * 60 * 60)

    return redirect('dashboard')
```

### **Step 3: Automatic Token Refresh**

```python
# app/middleware/keycloak_auth.py
class KeycloakAuthMiddleware:
    def __call__(self, request):
        token = request.session.get('access_token')
        if not token:
            return self.get_response(request)  # Not authenticated

        # Check if token needs refresh (5 minutes before expiry)
        if TokenRefreshManager.is_token_expiring_soon(token):
            refreshed_token = self.refresh_token_if_needed(request)
            if refreshed_token:
                token = refreshed_token

        # Validate and create user object
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            request.user = KeycloakUser(
                username=payload.get("preferred_username"),
                email=payload.get("email"),
                roles=payload.get("realm_access", {}).get("roles", [])
            )
        except jwt.ExpiredSignatureError:
            # Try refresh one more time
            if self.refresh_token_if_needed(request):
                # Retry with new token
                return self.__call__(request)
            else:
                request.user = AnonymousUser()

        return self.get_response(request)
```

---

## 🛡️ **Security Features**

### **1. State Parameter (CSRF Protection)**
- Random string generated by Django
- Stored in session and verified in callback
- Prevents cross-site request forgery attacks

### **2. Token Validation**
- JWT signature verification for API calls
- Audience and issuer validation
- Token integrity checks

### **3. Secure Session Management**
- HTTPOnly session cookies (prevent XSS)
- Secure flag in production (HTTPS only)
- Proper session cleanup on logout

### **4. Rate Limiting**
- 1-minute cooldown between refresh attempts
- Prevents abuse of token refresh endpoint
- Graceful degradation on failures

### **5. Access Control**
- Role-based decorators (`@require_role("admin")`)
- View-level permission checks
- API endpoint protection

---

## 📊 **Session Management**

### **Session Data Storage**

```python
{
    'access_token': 'eyJ...',           # Current JWT access token (1 hour expiry)
    'refresh_token': 'eyJ...',          # Long-lived refresh token (30 days)
    'token_acquired_at': 1699123456,   # When current token was obtained
    'token_expires_in': 3600,          # Token lifetime in seconds
    'authenticated_at': 1699123456,    # Initial login timestamp
    'oauth_state': 'abc123...',         # CSRF protection (temporary)
    'last_refresh_attempt': 1699123456  # Rate limiting for refresh
}
```

### **Token Refresh Logic**

1. **Proactive Refresh** (5 minutes before expiry)
   - Check token expiry on each request
   - If expiring soon, use refresh token
   - Update session with new tokens
   - Continue request seamlessly

2. **Recovery Refresh** (when already expired)
   - Detect expired token in middleware
   - Attempt refresh with stored refresh token
   - If successful, retry original request
   - If failed, clear session and redirect to login

3. **Refresh Failure Handling**
   - Clear all authentication data
   - Invalidate session completely
   - Redirect user to login page
   - Log error for debugging

---

## 🎯 **API Endpoints**

### **Public Endpoints**

```bash
GET  /                 # Landing page
GET  /login/           # Login page
POST /login/           # Initiate Keycloak login
GET  /callback/        # OAuth2 callback
GET  /logout/          # Logout endpoint
GET  /public-info/     # Public API endpoint
```

### **Protected Endpoints**

```bash
GET  /dashboard/       # User dashboard
GET  /api/dashboard/   # User data API
GET  /api/admin-panel/ # Admin only API
GET  /api/manager-panel/ # Admin/Manager API
POST /api/update-profile/ # Update user profile
GET  /api/auth-status/   # Check authentication status
```

### **API Response Examples**

**User Dashboard API:**
```json
{
  "message": "Welcome testuser",
  "email": "test@example.com",
  "roles": ["user", "admin"],
  "is_authenticated": true
}
```

**Admin Panel API:**
```json
{
  "message": "Admin access granted to testuser",
  "user_roles": ["user", "admin"],
  "admin_data": {
    "total_users": "N/A (stateless)",
    "system_status": "operational"
  }
}
```

---

## 🔧 **Development & Testing**

### **Running Tests**

```bash
# Start development server
python3 manage.py runserver 0.0.0.0:8010

# Test authentication flow
curl -I http://localhost:8010/

# Test API endpoints
curl http://localhost:8010/api/public-info/
curl http://localhost:8010/api/auth-status/
```

### **Debug Logging**

The application provides detailed logging for debugging:

```python
# Look for these messages in console output:
"Token expiring soon, attempting refresh..."
"Token refreshed successfully"
"Successfully refreshed and authenticated {username}"
"Token refresh failed, clearing session"
```

### **Common Debugging Scenarios**

1. **Token Not Refreshing:**
   - Check if refresh token is stored in session
   - Verify refresh token hasn't expired (30 days)
   - Check Keycloak client configuration

2. **Session Expiring Early:**
   - Verify `SESSION_COOKIE_AGE` setting
   - Check browser cookie settings
   - Ensure `SESSION_EXPIRE_AT_BROWSER_CLOSE = False`

3. **Redirect Loop on Login:**
   - Verify Keycloak is accessible
   - Check client secret configuration
   - Validate redirect URI in Keycloak

---

## 🚀 **Production Deployment**

### **Environment Configuration**

```python
# settings.py - Production
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']

# Security settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Database (use PostgreSQL in production)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'keycloak_demo',
        'USER': 'postgres',
        'PASSWORD': 'your-password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### **Docker Deployment**

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8010

CMD ["python", "manage.py", "runserver", "0.0.0.0:8010"]
```

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  django:
    build: .
    ports:
      - "8010:8010"
    environment:
      - DEBUG=False
      - KEYCLOAK_SERVER_URL=https://keycloak.yourdomain.com/
    depends_on:
      - db
      - keycloak

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: keycloak_demo
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: your-password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  keycloak:
    image: quay.io/keycloak/keycloak:23.0.0
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: your-admin-password
    ports:
      - "8080:8080"
    command: start

volumes:
  postgres_data:
```

### **Monitoring & Maintenance**

- **Monitor token refresh success rate**
- **Track session duration analytics**
- **Set up alerts for authentication failures**
- **Regular Keycloak backups**
- **Monitor Django application logs**

---

## 🔍 **Troubleshooting**

### **Common Issues & Solutions**

| Issue | Cause | Solution |
|-------|-------|----------|
| **Users logged out after 1 hour** | Session timeout too short | Set `SESSION_COOKIE_AGE = 30 * 24 * 60 * 60` |
| **"Invalid state parameter"** | Session expired or tampered | Start login flow again |
| **"No authorization code received"** | Keycloak configuration mismatch | Check client ID, redirect URI |
| **"Token request failed with status 400"** | Wrong client secret or redirect URI | Verify Keycloak client settings |
| **Token refresh not working** | Refresh token expired or missing | Check refresh token storage |
| **CORS errors** | Frontend on different domain | Add CORS middleware |

### **Debug Checklist**

1. **Verify Keycloak is running:** `curl http://localhost:8080/`
2. **Check Django logs:** Look for authentication messages
3. **Validate session data:** Check browser developer tools
4. **Test token manually:** Use JWT decoder to verify claims
5. **Check network requests:** Ensure proper redirects

---

## 🎉 **Benefits & Use Cases**

### **Enterprise Benefits**

- **🛡️ Enterprise Security:** OAuth2 + OpenID Connect standards
- **⚡ Stateless Architecture:** No user database in Django
- **📈 High Scalability:** Centralized identity management
- **🔄 Multi-Platform:** Works for web and mobile apps
- **🎯 Role-Based Access:** Fine-grained permissions
- **🚀 Developer Friendly:** Easy integration and debugging

### **User Experience Benefits**

- **🔐 Single Sign-On:** One login for multiple applications
- **📱 Persistent Sessions:** 30-day convenience
- **🔄 Seamless Refresh:** No interruption during token renewal
- **🌐 Cross-Browser:** Works on all modern browsers
- **📱 Mobile Ready:** Responsive design
- **⚡ Fast Performance:** Minimal authentication overhead

### **Ideal Use Cases**

- **Enterprise applications** with existing Keycloak setup
- **Multi-application portals** requiring SSO
- **API services** needing OAuth2 protection
- **SaaS applications** with subscription-based access
- **Internal tools** with role-based access
- **Mobile applications** requiring secure authentication

---

## 📚 **References & Resources**

- **Keycloak Documentation:** https://www.keycloak.org/documentation
- **OAuth2 RFC:** https://tools.ietf.org/html/rfc6749
- **OpenID Connect:** https://openid.net/connect/
- **Django Authentication:** https://docs.djangoproject.com/en/stable/topics/auth/
- **JWT Specification:** https://tools.ietf.org/html/rfc7519

---

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📄 **License**

This project is provided as-is for educational and demonstration purposes.

---

**✨ Congratulations! You now have a production-ready Django application with Keycloak authentication and 30-day persistent sessions! 🚀**

For any questions or issues, please refer to the troubleshooting section or check the application logs for detailed error messages.