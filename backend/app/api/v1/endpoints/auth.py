from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.services.auth_service import AuthService
from app.schemas.auth import (
    UserCreate, UserUpdate, User, LoginRequest, LoginResponse,
    RefreshTokenRequest, RefreshTokenResponse, LogoutRequest,
    MFASetupRequest, MFASetupResponse, MFAVerifyRequest, MFAVerifyResponse,
    AzureADLoginRequest, AzureADConfigRequest, AzureADConfigResponse,
    PasswordResetRequest, PasswordResetConfirm, ChangePasswordRequest,
    UserSessionResponse
)

router = APIRouter()
security = HTTPBearer()

def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(db)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service)
) -> User:
    """Get current authenticated user"""
    user = auth_service.get_current_user(credentials.credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return user

@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """User login with username and password"""
    try:
        return auth_service.login(login_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token"""
    try:
        return auth_service.refresh_token(refresh_data.refresh_token)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/logout")
async def logout(
    logout_data: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """User logout"""
    success = auth_service.logout(logout_data.refresh_token)
    if success:
        return {"message": "Logged out successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token"
        )

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    mfa_data: MFASetupRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Setup MFA for user"""
    try:
        return auth_service.setup_mfa(mfa_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup failed"
        )

@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def verify_mfa(
    mfa_data: MFAVerifyRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Verify MFA code"""
    try:
        return auth_service.verify_mfa(mfa_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed"
        )

@router.post("/azure-ad/login", response_model=LoginResponse)
async def azure_ad_login(
    login_data: AzureADLoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Azure AD login"""
    try:
        return await auth_service.azure_ad_login(login_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Azure AD login failed"
        )

@router.get("/azure-ad/config", response_model=AzureADConfigResponse)
async def get_azure_ad_config(
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_user)
):
    """Get Azure AD configuration"""
    config = auth_service.get_azure_ad_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Azure AD not configured"
        )
    return config

@router.post("/azure-ad/config", response_model=AzureADConfigResponse)
async def update_azure_ad_config(
    config_data: AzureADConfigRequest,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_user)
):
    """Update Azure AD configuration"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        return auth_service.update_azure_ad_config(config_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Azure AD configuration"
        )

@router.get("/azure-ad/login-url")
async def get_azure_ad_login_url(
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get Azure AD login URL"""
    config = auth_service.get_azure_ad_config()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Azure AD not configured"
        )
    
    # Generate login URL
    import secrets
    state = secrets.token_urlsafe(32)
    
    login_url = (
        f"https://login.microsoftonline.com/{config.tenant_id}/oauth2/v2.0/authorize?"
        f"client_id={config.client_id}&"
        f"response_type=code&"
        f"redirect_uri={config.redirect_uri}&"
        f"scope=openid%20profile%20email&"
        f"state={state}"
    )
    
    return {"login_url": login_url, "state": state}

@router.post("/register", response_model=User)
async def register_user(
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register new user"""
    try:
        return auth_service.create_user(user_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User registration failed"
        )

@router.get("/me", response_model=User)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    return current_user

@router.put("/me", response_model=User)
async def update_current_user(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Update current user information"""
    try:
        return auth_service.update_user(current_user.id, user_data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User update failed"
        )

@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Change user password"""
    # Verify current password
    if not auth_service.verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    try:
        auth_service.update_user(current_user.id, UserUpdate(password=password_data.new_password))
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@router.post("/password-reset")
async def request_password_reset(
    reset_data: PasswordResetRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Request password reset"""
    user = auth_service.get_user_by_email(reset_data.email)
    if user:
        # In a real implementation, you would send an email with reset link
        # For now, we'll just return success
        return {"message": "Password reset email sent"}
    else:
        # Don't reveal if email exists or not
        return {"message": "Password reset email sent"}

@router.post("/password-reset/confirm")
async def confirm_password_reset(
    confirm_data: PasswordResetConfirm,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Confirm password reset"""
    # In a real implementation, you would verify the token
    # For now, we'll just return success
    return {"message": "Password reset successfully"}

@router.get("/sessions", response_model=List[UserSessionResponse])
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get user sessions"""
    return auth_service.get_user_sessions(current_user.id)

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Revoke a specific session"""
    success = auth_service.revoke_session(session_id)
    if success:
        return {"message": "Session revoked successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

@router.get("/health")
async def auth_health():
    """Authentication service health check"""
    return {"status": "healthy", "service": "authentication"}
