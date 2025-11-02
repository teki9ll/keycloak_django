# 🔧 Keycloak Setup Guide for Django Demo

This guide provides step-by-step instructions to configure Keycloak to work with the Django Keycloak Demo project.

## 📋 Prerequisites

- **Keycloak Server**: Running Keycloak instance (version 15+ recommended)
- **Admin Access**: Access to Keycloak admin console
- **Network Access**: Ability to configure clients and realms

## 🎯 Target Configuration

Our Django project expects these settings:
- **Server URL**: `http://172.28.136.214:8080/`
- **Realm Name**: `teki_9`
- **Client ID**: `easytask`
- **Client Secret**: `FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa`

## 🚀 Step-by-Step Setup

### Step 1: Access Keycloak Admin Console

1. Open your browser and navigate to:
   ```
   http://172.28.136.214:8080/
   ```

2. Click **Administration Console** or go to:
   ```
   http://172.28.136.214:8080/admin/
   ```

3. Sign in with your Keycloak admin credentials

### Step 2: Create the Realm

1. **Select Realm**: Click on the realm name dropdown (usually "Master") in the top-left corner
2. **Add Realm**: Click **Add realm**
3. **Realm Details**:
   - **Name**: `teki_9`
   - **Enabled**: ✅ Check this box
   - Click **Create**

### Step 3: Create the Client

1. **Navigate to Clients**: In the left menu, click **Clients**
2. **Create Client**: Click **Create**
3. **Client Settings**:
   - **Client ID**: `easytask`
   - **Client Protocol**: `openid-connect`
   - **Root URL**: `http://localhost:8000/`
   - Click **Save**

4. **Configure Client Details**:
   - **Access Type**: `confidential`
   - **Standard Flow Enabled**: ✅ ON
   - **Direct Access Grants Enabled**: ✅ ON (optional, for direct token access)
   - **Service Accounts Enabled**: ✅ OFF (for this demo)
   - **Authorization Enabled**: ✅ OFF

5. **Valid Redirect URIs** (under **Settings → Valid Redirect URIs**):
   ```
   http://localhost:8000/*
   http://localhost:8000/callback/*
   http://127.0.0.1:8000/*
   ```

6. **Web Origins** (under **Settings → Web Origins**):
   ```
   http://localhost:8000
   http://127.0.0.1:8000
   ```

7. **Save** the client configuration

### Step 4: Get Client Secret

1. **Navigate to Credentials Tab**: Click on the **Credentials** tab for the `easytask` client
2. **Client Secret**: Copy the **Value** field - this is your client secret
3. **Update Django Project**: If different from expected, update your `.env` file:
   ```env
   KEYCLOAK_CLIENT_SECRET=your_actual_client_secret
   ```

### Step 5: Create User Roles

1. **Navigate to Roles**: In the left menu, click **Roles**
2. **Add Role**: Click **Add Role**
3. **Create Roles**:
   - **Role 1**: `admin`
   - **Role 2**: `manager`
   - **Role 3**: `user` (optional)

4. **Create each role** with default settings (no composite roles needed)

### Step 6: Create Test Users

1. **Navigate to Users**: In the left menu, click **Users**
2. **Add User**: Click **Add user**
3. **User Details**:
   - **Username**: `testuser`
   - **Email**: `testuser@example.com`
   - **First Name**: `Test`
   - **Last Name**: `User`
   - **Enabled**: ✅ ON
   - Click **Save**

4. **Set Password**:
   - Go to **Credentials** tab
   - Set a password
   - **Temporary**: ❌ OFF (for easier testing)

5. **Assign Roles**:
   - Go to **Role Mappings** tab
   - Select `admin` role from **Available Roles**
   - Click **Add selected** → assign to user

6. **Create Additional Users**:
   - **Manager User**: `manager` with `manager` role
   - **Regular User**: `regularuser` with `user` role (or no specific role)

### Step 7: Verify Configuration

1. **Test Client Configuration**:
   - Go to **Clients → easytask**
   - Click on the **Installation** tab
   - Format: **Keycloak OIDC JSON**
   - You should see JSON with your configuration

2. **Test User Access**:
   - Go to **Users → testuser → Credentials**
   - Note the password for testing

## 🔧 Advanced Configuration (Optional)

### Enable Email Verification

1. **Realm Settings → Login**:
   - **Require SSL**: `none` (for development)
   - **Registration**: Turn on email verification if desired
   - **Remember Me**: Enable as needed

### Configure Token Settings

1. **Realm Settings → Tokens**:
   - **Access Token Lifespan**: `60 minutes` (default)
   - **SSO Session Idle**: `30 minutes` (default)
   - **Offline Session Idle**: `604800 seconds` (1 week)

### Configure Fine-Grained Permissions

1. **Enable Authorization**:
   - Go to **Clients → easytask → Authorization**
   - Click **Enable** (optional, for advanced use cases)

## 🧪 Test the Configuration

### 1. Test Keycloak Direct Access

1. Open the following URL in your browser:
   ```
   http://172.28.136.214:8080/realms/teki_9/protocol/openid-connect/auth?client_id=easytask&response_type=code&scope=openid profile email&redirect_uri=http://localhost:8000/callback/&state=test
   ```

2. You should see the Keycloak login page
3. Login with your test user credentials
4. You should be redirected (will show error since Django isn't listening yet, but confirms flow works)

### 2. Test with Django Application

1. Start your Django application:
   ```bash
   cd keycloak_demo
   source ../venv/bin/activate
   python manage.py runserver 0.0.0.0:8000
   ```

2. Visit `http://localhost:8000/login/`
3. Click "Sign in with Keycloak"
4. Login with your test user
5. You should be redirected to the dashboard

## 🚨 Common Issues & Solutions

### Issue: "Invalid parameter: redirect_uri"
**Solution**:
- Verify the redirect URI exactly matches what's configured in Keycloak
- Check for trailing slashes and protocol (http vs https)

### Issue: "Client not enabled"
**Solution**:
- Ensure the client is enabled
- Check that Standard Flow is turned ON

### Issue: "Unauthorized" or "Access denied"
**Solution**:
- Verify client secret is correct
- Check that Access Type is set to `confidential`

### Issue: CORS errors
**Solution**:
- Add your Django URL to Web Origins
- Ensure Valid Redirect URIs include your callback URL

### Issue: User can't see dashboard
**Solution**:
- Verify user is enabled
- Check user has appropriate role assignments
- Ensure JWT tokens include realm_access.roles

## 📋 Configuration Checklist

- [ ] Realm `teki_9` created and enabled
- [ ] Client `easytask` created with confidential access type
- [ ] Valid Redirect URIs configured correctly
- [ ] Web Origins configured correctly
- [ ] Client secret obtained and configured in Django
- [ ] Test users created with appropriate roles
- [ ] Role mappings assigned to users
- [ ] Login flow tested end-to-end
- [ ] Django dashboard displays user information correctly

## 🔐 Security Considerations

### For Development
- SSL not required (but recommended)
- Client secret should be kept private
- Use strong passwords for test users

### For Production
- **Enable SSL**: Always use HTTPS in production
- **Strong Client Secret**: Use a cryptographically strong secret
- **Limited Redirect URIs**: Be specific about allowed redirect URLs
- **Token Lifespans**: Configure appropriate token expiration times
- **User Security**: Enable email verification, password policies, etc.

## 📞 Support

If you encounter issues:

1. **Check Keycloak Logs**: Look for error messages in Keycloak server logs
2. **Verify Network**: Ensure Keycloak server is accessible from Django server
3. **Test Components**: Test Keycloak and Django separately before integration
4. **Review Configuration**: Double-check all configuration values match exactly

## 🎯 Success Criteria

You'll know the setup is successful when:

1. ✅ Keycloak login page loads when clicking "Sign in with Keycloak"
2. ✅ User can authenticate with Keycloak credentials
3. ✅ Redirect back to Django works correctly
4. ✅ Dashboard displays user information and roles
5. ✅ API endpoints work with authenticated session
6. ✅ Different users see appropriate content based on roles

Once configured, your Keycloak server will seamlessly provide authentication and authorization for the Django application!