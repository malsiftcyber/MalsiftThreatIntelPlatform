from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
import jwt
import secrets
import pyotp
import qrcode
import io
import base64
import httpx
from fastapi import HTTPException, status

from app.models.auth import User, Role, UserSession, MFAAttempt, AzureADConfig
from app.schemas.auth import (
    UserCreate, UserUpdate, LoginRequest, MFASetupRequest, 
    MFAVerifyRequest, AzureADLoginRequest, AzureADConfigRequest
)
from app.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self, db: Session):
        self.db = db
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
        return encoded_jwt
    
    def create_refresh_token(self, data: dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.PyJWTError:
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.db.query(User).filter(User.username == username).first()
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.db.query(User).filter(User.email == email).first()
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        return user
    
    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user"""
        hashed_password = self.get_password_hash(user_data.password)
        
        # Get default role
        default_role = self.db.query(Role).filter(Role.name == "user").first()
        if not default_role:
            # Create default role if it doesn't exist
            default_role = Role(
                name="user",
                description="Default user role",
                permissions='["read:indicators", "read:feeds"]'
            )
            self.db.add(default_role)
            self.db.commit()
            self.db.refresh(default_role)
        
        user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            is_active=user_data.is_active,
            is_superuser=user_data.is_superuser,
            role_id=default_role.id
        )
        
        try:
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            return user
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )
    
    def update_user(self, user_id: int, user_data: UserUpdate) -> User:
        """Update user information"""
        user = self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        update_data = user_data.dict(exclude_unset=True)
        if "password" in update_data:
            update_data["hashed_password"] = self.get_password_hash(update_data.pop("password"))
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def create_user_session(self, user: User) -> UserSession:
        """Create a new user session"""
        # Invalidate existing sessions for this user
        self.db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True
        ).update({"is_active": False})
        
        # Create new session
        access_token = self.create_access_token(data={"sub": str(user.id)})
        refresh_token = self.create_refresh_token(data={"sub": str(user.id)})
        
        session = UserSession(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session
    
    def login(self, login_data: LoginRequest) -> Dict[str, Any]:
        """Handle user login"""
        user = self.authenticate_user(login_data.username, login_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is disabled"
            )
        
        session = self.create_user_session(user)
        
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user
        }
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token"""
        payload = self.verify_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user_id = payload.get("sub")
        user = self.get_user_by_id(int(user_id))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new session
        session = self.create_user_session(user)
        
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    def logout(self, refresh_token: str) -> bool:
        """Logout user by invalidating session"""
        session = self.db.query(UserSession).filter(
            UserSession.refresh_token == refresh_token,
            UserSession.is_active == True
        ).first()
        
        if session:
            session.is_active = False
            self.db.commit()
            return True
        return False
    
    def setup_mfa(self, mfa_data: MFASetupRequest) -> Dict[str, Any]:
        """Setup MFA for user"""
        user = self.get_user_by_id(mfa_data.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Generate TOTP secret
        secret_key = pyotp.random_base32()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri(
            name=user.email,
            issuer_name="Malsift"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        qr_code = f"data:image/png;base64,{img_str}"
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        # Store MFA attempt
        mfa_attempt = MFAAttempt(
            user_id=user.id,
            secret_key=secret_key,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        
        self.db.add(mfa_attempt)
        self.db.commit()
        
        return {
            "secret_key": secret_key,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        }
    
    def verify_mfa(self, mfa_data: MFAVerifyRequest) -> Dict[str, Any]:
        """Verify MFA code"""
        mfa_attempt = self.db.query(MFAAttempt).filter(
            MFAAttempt.user_id == mfa_data.user_id,
            MFAAttempt.is_verified == False,
            MFAAttempt.expires_at > datetime.utcnow()
        ).first()
        
        if not mfa_attempt:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired MFA setup"
            )
        
        # Verify TOTP code
        totp = pyotp.TOTP(mfa_attempt.secret_key)
        if totp.verify(mfa_data.code):
            mfa_attempt.is_verified = True
            self.db.commit()
            return {"success": True, "message": "MFA verified successfully"}
        else:
            return {"success": False, "message": "Invalid MFA code"}
    
    def get_azure_ad_config(self) -> Optional[AzureADConfig]:
        """Get Azure AD configuration"""
        return self.db.query(AzureADConfig).filter(AzureADConfig.is_enabled == True).first()
    
    def update_azure_ad_config(self, config_data: AzureADConfigRequest) -> AzureADConfig:
        """Update Azure AD configuration"""
        config = self.get_azure_ad_config()
        if config:
            # Update existing config
            for field, value in config_data.dict().items():
                setattr(config, field, value)
        else:
            # Create new config
            config = AzureADConfig(**config_data.dict())
            self.db.add(config)
        
        self.db.commit()
        self.db.refresh(config)
        return config
    
    async def azure_ad_login(self, login_data: AzureADLoginRequest) -> Dict[str, Any]:
        """Handle Azure AD login"""
        config = self.get_azure_ad_config()
        if not config:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Azure AD not configured"
            )
        
        # Exchange code for token
        token_url = f"https://login.microsoftonline.com/{config.tenant_id}/oauth2/v2.0/token"
        token_data = {
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": login_data.code,
            "redirect_uri": config.redirect_uri,
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=token_data)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange Azure AD code"
                )
            
            token_info = response.json()
            access_token = token_info.get("access_token")
            
            # Get user info
            user_info_url = "https://graph.microsoft.com/v1.0/me"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = await client.get(user_info_url, headers=headers)
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user info from Azure AD"
                )
            
            user_info = user_response.json()
            
            # Find or create user
            user = self.get_user_by_email(user_info.get("mail") or user_info.get("userPrincipalName"))
            if not user:
                # Create new user from Azure AD
                user = User(
                    username=user_info.get("userPrincipalName", "").split("@")[0],
                    email=user_info.get("mail") or user_info.get("userPrincipalName"),
                    hashed_password="",  # Azure AD users don't have passwords
                    is_active=True
                )
                self.db.add(user)
                self.db.commit()
                self.db.refresh(user)
            
            # Create session
            session = self.create_user_session(user)
            
            return {
                "access_token": session.access_token,
                "refresh_token": session.refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "user": user
            }
    
    def get_current_user(self, token: str) -> Optional[User]:
        """Get current user from token"""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        return self.get_user_by_id(int(user_id))
    
    def get_user_sessions(self, user_id: int) -> list:
        """Get user sessions"""
        return self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ).all()
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a specific session"""
        session = self.db.query(UserSession).filter(
            UserSession.session_id == session_id,
            UserSession.is_active == True
        ).first()
        
        if session:
            session.is_active = False
            self.db.commit()
            return True
        return False
