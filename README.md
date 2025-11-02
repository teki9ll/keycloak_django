# Django Keycloak Demo Project

A Django application with Keycloak integration using stateless, in-memory authentication. This project demonstrates how to implement JWT-based authentication with Keycloak without relying on Django's built-in user database.

## 🚀 Quick Start

**1. Setup Keycloak First** → See [`KEYCLOAK_SETUP.md`](KEYCLOAK_SETUP.md)
**2. Test Configuration** → `python check_keycloak_config.py`
**3. Run Django** → `python manage.py runserver 0.0.0.0:8010`
**4. Visit** → `http://172.28.136.214:8010/login/`

## 📋 Documentation Files

- **[`KEYCLOAK_SETUP.md`](KEYCLOAK_SETUP.md)** - Complete Keycloak configuration guide
- **[`test_login_flow.md`](test_login_flow.md)** - Step-by-step testing instructions
- **[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)** - Debug guide for "Failed to obtain access token" issues
- **[`requirements.txt`](requirements.txt)** - Python dependencies
- **[`check_keycloak_config.py`](check_keycloak_config.py)** - Configuration validation script
- **[`debug_token_exchange.py`](debug_token_exchange.py)** - Token endpoint debugging tool
- **[`simple_auth_test.py`](simple_auth_test.py)** - Simple OAuth2 flow test without PKCE

## Features

- **Stateless Authentication**: No database dependency for user management
- **Keycloak Integration**: JWT token validation with automatic public key fetching
- **Role-based Access Control**: Custom decorators for role-based permissions
- **RESTful API**: JSON-based API endpoints with different access levels
- **Development Ready**: Configured with hot-reload and debugging enabled

## Project Structure

```
keycloak_demo/
├── keycloak_demo/          # Django project configuration
│   ├── settings.py         # Django settings with Keycloak config
│   ├── urls.py            # URL routing
│   └── wsgi.py            # WSGI configuration
├── app/                   # Main Django app
│   ├── auth/              # Authentication logic
│   │   └── keycloak_user.py   # Custom user model
│   ├── middleware/        # Custom middleware
│   │   └── keycloak_auth.py   # Keycloak authentication middleware
│   ├── views.py           # API endpoints
│   └── decorators.py      # Authentication decorators
├── .env                   # Environment variables
└── README.md             # This file
```

## Web Interface

### Public Pages
- `GET /` - Welcome page with project information and login link
- `GET /login/` - Login page that redirects to Keycloak for authentication

### Protected Pages
- `GET /dashboard/` - User dashboard with detailed Keycloak user information
- `GET /logout/` - Logout page that clears session and redirects to Keycloak

### OAuth2 Flow
- `GET /callback/` - OAuth2 callback endpoint (handles Keycloak redirect)

## API Endpoints

### Public Endpoints
- `GET /api/public/` - Public information (no auth required)
- `GET /api/auth/status/` - Check authentication status

### Protected Endpoints
- `GET /api/dashboard/` - User dashboard JSON (requires authentication)
- `POST /api/profile/` - Update user profile (requires authentication)
- `GET /api/admin/` - Admin panel (requires "admin" role)
- `GET /api/manager/` - Manager panel (requires "admin" or "manager" role)

## Configuration

The project uses the following Keycloak configuration (from your `keycloak_configs.ini`):

```ini
KEYCLOAK_SERVER_URL=http://172.28.136.214:8080/
KEYCLOAK_REALM=teki_9
KEYCLOAK_CLIENT_ID=easytask
KEYCLOAK_CLIENT_SECRET=FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa
```

## Installation & Setup

### Prerequisites
- **Keycloak Server**: A running Keycloak instance
- **Django Setup**: Complete Keycloak configuration first (see below)

### Step 1: Configure Keycloak
⚠️ **Important**: You must configure Keycloak **before** running the Django application.

**Follow the complete setup guide**: See [`KEYCLOAK_SETUP.md`](KEYCLOAK_SETUP.md) for detailed instructions.

**Quick Setup Checklist**:
- [ ] Create realm `teki_9` in Keycloak
- [ ] Create client `easytask` with confidential access type
- [ ] Configure redirect URIs: `http://172.28.136.214:8010/*`
- [ ] Create test users with roles (`admin`, `manager`, `user`)
- [ ] Get client secret and update `.env` file

**Test your Keycloak configuration**:
```bash
python check_keycloak_config.py
```

### Step 2: Setup Django Application

1. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or manually:
   ```bash
   pip install django djangorestframework pyjwt python-decouple requests
   ```

3. **Configure environment variables:**
   Copy the `.env` file and adjust the Keycloak settings as needed.

4. **Run database migrations:**
   ```bash
   cd keycloak_demo
   python manage.py migrate
   ```

5. **Run the development server:**
   ```bash
   python manage.py runserver 0.0.0.0:8000
   ```

## Usage Examples

### Web Interface Flow
1. **Visit the welcome page**: Open `http://localhost:8000/` in your browser
2. **Click "Sign In"**: Navigate to `http://localhost:8000/login/`
3. **Authenticate with Keycloak**: You'll be redirected to your Keycloak server
4. **View Dashboard**: After successful login, you'll see your user dashboard with:
   - User information (username, email, full name)
   - Assigned roles and permissions
   - Session information
   - Quick access to API endpoints
5. **Logout**: Click the logout button to clear the session

### Testing without Authentication
```bash
# Public endpoint - should work
curl http://localhost:8000/api/public/

# Protected endpoint - should return 401
curl http://localhost:8000/api/dashboard/
```

### Testing with Authentication
1. **Via Web Interface**: Login through the web interface first, then use session-based API calls
2. **Via JWT Token**: Use the Authorization header:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/api/dashboard/
```

### Dashboard Features
The dashboard displays comprehensive user information:
- **User Profile**: Username, email, full name, user ID
- **Role Information**: All assigned roles with visual badges
- **Permission Matrix**: Visual representation of user permissions
- **Session Details**: Authentication status and session information
- **Quick Actions**: Direct links to relevant API endpoints
- **System Information**: Keycloak configuration and authentication flow details

## Authentication Flow

1. **User Authentication**: Users authenticate with Keycloak and receive a JWT token
2. **Token Validation**: Middleware extracts the Bearer token and validates it using Keycloak's public keys
3. **User Creation**: A lightweight `KeycloakUser` object is created in memory
4. **Role-based Access**: Custom decorators check user roles for protected endpoints

## Key Components

### KeycloakUser Class
- Represents an in-memory user object
- Provides `is_authenticated`, `is_staff`, `is_superuser` properties
- Includes role-based permission methods

### KeycloakAuthMiddleware
- Validates JWT tokens using Keycloak's JWKS endpoint
- Creates `KeycloakUser` objects from valid tokens
- Handles token expiration and invalid token errors

### Custom Decorators
- `@keycloak_login_required`: Requires authentication
- `@require_role("role_name")`: Requires specific role
- `@require_any_role(["role1", "role2"])`: Requires any of specified roles

## Development Notes

- No database migrations needed (stateless design)
- CSRF protection disabled for API usage
- Debug mode enabled for development
- All authentication logic is custom and doesn't use Django's built-in auth system

## Security Considerations

- JWT tokens are validated using Keycloak's public keys
- Token expiration is automatically checked
- No user data is stored in the database
- All authentication logic happens in memory

## Testing

The project includes multiple endpoints for testing different authentication scenarios:

1. **Public access**: Test endpoints without authentication
2. **Authentication required**: Test with valid/invalid tokens
3. **Role-based access**: Test with different user roles
4. **Mixed authentication**: Test endpoints with multiple role requirements

## License

This project is provided as a demo for Django + Keycloak integration.