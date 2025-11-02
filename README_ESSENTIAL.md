# 🔐 Django Keycloak Authentication Demo

> **Complete OAuth2 + OpenID Connect integration with 30-day persistent sessions**

---

## 🚀 **Quick Start**

### **1. Start Keycloak**
```bash
# Start Keycloak container
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin123 \
  quay.io/keycloak/keycloak:23.0.0 \
  start-dev
```

### **2. Configure Environment**
```bash
# Copy environment template
cp .env.example .env
# Edit .env with your Keycloak settings
```

### **3. Run Django**
```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start server
python manage.py runserver 0.0.0.8010
```

---

## 📋 **Configuration**

### **Keycloak Setup**
1. **Access Admin Console:** http://localhost:8080/admin
2. **Create Realm:** `teki_9`
3. **Create Client:** `easytask`
4. **Configure Redirect URI:** `http://localhost:8010/callback/`

### **Environment Variables (.env)**
```bash
# Required
KEYCLOAK_SERVER_URL=http://172.28.136.214:8080/
KEYCLOAK_REALM=teki_9
KEYCLOAK_CLIENT_ID=easytask
KEYCLOAK_CLIENT_SECRET=your-secret-here

# Optional
KEYCLOAK_SESSION_TIMEOUT=2592000  # 30 days
KEYCLOAK_TOKEN_REFRESH_THRESHOLD=300  # 5 minutes
```

---

## 🎯 **Features**

- ✅ **OAuth2 + OpenID Connect** with Keycloak
- ✅ **30-Day Persistent Sessions** with automatic refresh
- ✅ **Stateless Users** - No Django database needed
- ✅ **Role-Based Access Control** (admin, manager, user)
- ✅ **API + Web Interface** support
- ✅ **Automatic Token Refresh** 5 minutes before expiry
- ✅ **CSRF Protection** and security best practices

---

## 🌐 **Access Points**

- **Django App:** http://localhost:8010/
- **Dashboard:** http://localhost:8010/dashboard/
- **API Status:** http://localhost:8010/api/auth-status/
- **Keycloak Admin:** http://localhost:8080/admin/

**Test Users:**
- **Admin:** admin / admin123
- **User:** testuser / user123
- **Manager:** manager / manager123

---

## 🔧 **Architecture**

```
User → Django → Keycloak → Token → Session → Authenticated
```

1. **User clicks login** → Django generates state
2. **Redirect to Keycloak** → User authenticates
3. **Token exchange** → Django gets access + refresh tokens
4. **Session created** → 30-day persistence
5. **Auto refresh** → Tokens refreshed automatically
6. **Authenticated access** → Full application functionality

---

## 🛠️ **Project Structure**

```
keycloak_demo/
├── app/                          # Main application
│   ├── views.py                  # Django views
│   ├── middleware/               # Authentication middleware
│   ├── utils/                   # Token management
│   └── templates/               # HTML templates
├── django_keycloak_auth/          # Pluggable auth module
├── keycloak_demo/                 # Django project
├── manage.py                     # Django management
├── requirements.txt               # Python dependencies
├── .env                          # Environment variables
└── README.md                     # This file
```

---

## 🧪 **Testing**

```bash
# Test authentication flow
curl http://localhost:8010/api/auth-status/

# Test protected endpoint
curl -H "Authorization: Bearer <token>" http://localhost:8010/api/status/
```

---

## 🔍 **Troubleshooting**

### **Token Refresh Issues**
- Check Keycloak client configuration
- Verify client secret in settings
- Ensure realm exists and client is properly configured

### **Template Errors**
- Check user object attributes in templates
- Use `.default:"N/A"` filters for optional fields
- Check template context in views

### **Session Issues**
- Verify `SESSION_COOKIE_AGE` is set to 30 days
- Check session middleware configuration
- Ensure browser cookies are enabled

---

## 📞 **Support**

For issues with:
- **Keycloak Setup:** Check Keycloak admin console
- **Django Configuration:** Check settings.py
- **Authentication Flow:** Check Django logs

---

**🎉 Ready to authenticate with Keycloak! The application provides enterprise-grade authentication with automatic session management.**