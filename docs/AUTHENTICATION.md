# Authentication System

## Overview

Malsift includes a comprehensive authentication system with support for internal user management, Azure Active Directory integration, and multi-factor authentication (MFA) using Google Authenticator and Microsoft Authenticator.

## 🔐 Authentication Methods

### 1. Internal Authentication
- Username/password authentication
- Secure password hashing with bcrypt
- Session management with JWT tokens
- Role-based access control

### 2. Azure Active Directory Integration
- Single Sign-On (SSO) with Azure AD
- Automatic user provisioning
- Enterprise-grade security
- Seamless integration with existing AD infrastructure

### 3. Multi-Factor Authentication (MFA)
- TOTP (Time-based One-Time Password) support
- Google Authenticator compatibility
- Microsoft Authenticator compatibility
- Backup codes for account recovery
- Rate limiting and security measures

## 🏗️ Architecture

### Backend Components

#### Models (`backend/app/models/auth.py`)
- **User**: Core user model with authentication fields
- **Role**: Role-based permissions system
- **UserSession**: Session tracking and management
- **MFAAttempt**: MFA attempt logging for rate limiting
- **AzureADConfig**: Azure AD configuration storage

#### Services (`backend/app/services/auth_service.py`)
- **AuthService**: Core authentication logic
- Password hashing and verification
- JWT token management
- MFA setup and verification
- Azure AD integration
- Session management

#### API Endpoints (`backend/app/api/v1/endpoints/auth.py`)
- Login/logout endpoints
- MFA setup and verification
- Azure AD authentication
- User management
- Session management

### Frontend Components

#### Context (`frontend/src/contexts/AuthContext.tsx`)
- Authentication state management
- Token storage and refresh
- User session handling
- Error management

#### Components
- **Login**: Multi-method login interface
- **ProtectedRoute**: Route protection with permissions
- **Layout**: User info and logout integration

## 🚀 Getting Started

### 1. Environment Configuration

Add these variables to your `.env` file:

```bash
# Authentication
SECRET_KEY=your-secret-key-here-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Azure AD (Optional)
AZURE_AD_TENANT_ID=your-tenant-id
AZURE_AD_CLIENT_ID=your-client-id
AZURE_AD_CLIENT_SECRET=your-client-secret
AZURE_AD_REDIRECT_URI=http://localhost:3000/auth/callback
```

### 2. Database Setup

Run database migrations to create authentication tables:

```bash
cd backend
alembic upgrade head
```

### 3. Create Default Roles

```python
# Create default roles
from app.models.auth import Role
from app.core.database import SessionLocal

db = SessionLocal()

# Admin role
admin_role = Role(
    name="admin",
    description="Administrator with full access",
    permissions='["*"]'
)

# Analyst role
analyst_role = Role(
    name="analyst",
    description="Security analyst with read/write access",
    permissions='["read:indicators", "write:indicators", "read:feeds", "read:sources"]'
)

# User role
user_role = Role(
    name="user",
    description="Basic user with read access",
    permissions='["read:indicators"]'
)

db.add_all([admin_role, analyst_role, user_role])
db.commit()
```

### 4. Create Admin User

```python
from app.services.auth_service import AuthService
from app.schemas.auth import UserCreate, AuthMethod

auth_service = AuthService()
db = SessionLocal()

admin_user = UserCreate(
    username="admin",
    email="admin@example.com",
    password="secure-password-123",
    auth_method=AuthMethod.INTERNAL,
    is_active=True,
    is_verified=True
)

user = auth_service.create_user(db, admin_user)
db.close()
```

## 📋 API Endpoints

### Authentication Endpoints

#### Login
```bash
POST /api/v1/auth/login
{
  "username": "admin",
  "password": "password123",
  "auth_method": "internal"
}
```

#### MFA Login
```bash
POST /api/v1/auth/mfa/login
{
  "session_token": "temp-session-token",
  "mfa_code": "123456",
  "use_backup_code": false
}
```

#### MFA Setup
```bash
POST /api/v1/auth/mfa/setup
# Returns QR code and backup codes
```

#### MFA Verification
```bash
POST /api/v1/auth/mfa/verify
{
  "mfa_code": "123456",
  "use_backup_code": false
}
```

#### Azure AD Login URL
```bash
GET /api/v1/auth/azure-ad/login-url
# Returns Azure AD login URL
```

#### Azure AD Login
```bash
POST /api/v1/auth/azure-ad/login
{
  "code": "authorization-code",
  "state": "state-parameter"
}
```

#### Refresh Token
```bash
POST /api/v1/auth/refresh
{
  "refresh_token": "refresh-token"
}
```

#### Logout
```bash
POST /api/v1/auth/logout
{
  "refresh_token": "refresh-token"
}
```

#### Get Current User
```bash
GET /api/v1/auth/me
Authorization: Bearer <access-token>
```

#### Authentication Status
```bash
GET /api/v1/auth/status
Authorization: Bearer <access-token>
```

### User Management Endpoints

#### Create User (Admin Only)
```bash
POST /api/v1/auth/users
Authorization: Bearer <access-token>
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "auth_method": "internal"
}
```

#### Update User
```bash
PUT /api/v1/auth/users/{user_id}
Authorization: Bearer <access-token>
{
  "username": "updated-username",
  "email": "updated@example.com"
}
```

#### Change Password
```bash
POST /api/v1/auth/change-password
Authorization: Bearer <access-token>
{
  "current_password": "old-password",
  "new_password": "new-password"
}
```

#### Get User Sessions
```bash
GET /api/v1/auth/sessions
Authorization: Bearer <access-token>
```

#### Revoke Session
```bash
DELETE /api/v1/auth/sessions/{session_id}
Authorization: Bearer <access-token>
```

## 🔧 Azure AD Configuration

### 1. Azure AD App Registration

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Configure:
   - Name: "Malsift"
   - Supported account types: "Accounts in this organizational directory only"
   - Redirect URI: Web > `http://localhost:3000/auth/callback`

### 2. Configure Permissions

1. Go to "API permissions"
2. Add permissions:
   - Microsoft Graph > Delegated > User.Read
   - Microsoft Graph > Delegated > email
   - Microsoft Graph > Delegated > profile

### 3. Get Credentials

1. Note down:
   - Application (client) ID
   - Directory (tenant) ID
2. Create a client secret:
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Note the secret value

### 4. Configure Malsift

Update your `.env` file:

```bash
AZURE_AD_TENANT_ID=your-tenant-id
AZURE_AD_CLIENT_ID=your-client-id
AZURE_AD_CLIENT_SECRET=your-client-secret
AZURE_AD_REDIRECT_URI=http://localhost:3000/auth/callback
```

## 🔐 Multi-Factor Authentication

### Setup Process

1. **User initiates MFA setup**
   ```bash
   POST /api/v1/auth/mfa/setup
   Authorization: Bearer <access-token>
   ```

2. **System generates QR code and backup codes**
   ```json
   {
     "qr_code": "data:image/png;base64,...",
     "secret": "JBSWY3DPEHPK3PXP",
     "backup_codes": ["ABCD1234", "EFGH5678", ...],
     "setup_url": "otpauth://totp/Malsift:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Malsift"
   }
   ```

3. **User scans QR code with authenticator app**

4. **User verifies setup**
   ```bash
   POST /api/v1/auth/mfa/verify
   Authorization: Bearer <access-token>
   {
     "mfa_code": "123456"
   }
   ```

### Authentication Flow

1. **User logs in with username/password**
2. **If MFA is enabled:**
   - System returns temporary session token
   - User enters MFA code
   - System verifies code and completes login
3. **If MFA is not enabled:**
   - System returns full access token immediately

### Backup Codes

- 10 backup codes generated during setup
- Each code can be used once
- Codes are removed after use
- New codes can be generated by re-running setup

## 🛡️ Security Features

### Password Security
- bcrypt hashing with salt
- Minimum 8 character requirement
- Password change validation

### Session Security
- JWT tokens with expiration
- Refresh token rotation
- Session tracking with IP and user agent
- Automatic session cleanup

### MFA Security
- Rate limiting (5 attempts per 15 minutes)
- TOTP with 30-second window
- Secure secret generation
- Backup code management

### Azure AD Security
- OAuth 2.0 flow
- State parameter validation
- Secure token exchange
- User information validation

## 📊 Monitoring and Logging

### Authentication Logs
- Login attempts (success/failure)
- MFA attempts
- Session creation/destruction
- Password changes

### Security Metrics
- Failed login attempts
- MFA failure rates
- Session duration statistics
- User activity patterns

## 🔄 Integration Examples

### Frontend Integration

```typescript
import { useAuth } from '../contexts/AuthContext';

function MyComponent() {
  const { state, login, logout } = useAuth();

  const handleLogin = async () => {
    try {
      await login('username', 'password');
      // Redirect to dashboard
    } catch (error) {
      if (error.message === 'MFA_REQUIRED') {
        // Show MFA input
      } else {
        // Show error message
      }
    }
  };

  return (
    <div>
      {state.isAuthenticated ? (
        <div>
          <p>Welcome, {state.user?.username}!</p>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <button onClick={handleLogin}>Login</button>
      )}
    </div>
  );
}
```

### Protected Routes

```typescript
import ProtectedRoute from '../components/ProtectedRoute';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route 
        path="/admin" 
        element={
          <ProtectedRoute requiredPermissions={['admin:access']}>
            <AdminPanel />
          </ProtectedRoute>
        } 
      />
    </Routes>
  );
}
```

### API Integration

```typescript
import { api } from '../services/api';

// API calls automatically include auth headers
const getIndicators = async () => {
  const response = await api.get('/api/v1/indicators');
  return response.data;
};

// Handle 401 responses
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Redirect to login
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
```

## 🚨 Troubleshooting

### Common Issues

1. **MFA Code Not Working**
   - Check time synchronization
   - Verify secret is correct
   - Try backup code

2. **Azure AD Login Fails**
   - Verify tenant ID and client ID
   - Check redirect URI configuration
   - Ensure app has correct permissions

3. **Session Expires Too Quickly**
   - Check ACCESS_TOKEN_EXPIRE_MINUTES setting
   - Implement token refresh logic
   - Verify client-side token storage

4. **Permission Denied**
   - Check user roles and permissions
   - Verify endpoint requires authentication
   - Check API key or token validity

### Debug Mode

Enable debug logging:

```python
# In your .env file
LOG_LEVEL=DEBUG
```

Check logs for authentication events:

```bash
docker-compose logs backend | grep auth
```

## 📚 Additional Resources

- [JWT.io](https://jwt.io/) - JWT token debugging
- [Azure AD Documentation](https://docs.microsoft.com/en-us/azure/active-directory/)
- [TOTP RFC](https://tools.ietf.org/html/rfc6238) - Time-based One-Time Password
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749) - OAuth 2.0 specification
