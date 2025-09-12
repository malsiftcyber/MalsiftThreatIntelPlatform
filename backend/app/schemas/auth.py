from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr
    is_active: bool = True
    is_superuser: bool = False

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None

class User(UserBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: Optional[str] = None

class RoleCreate(RoleBase):
    pass

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[str] = None

class Role(RoleBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: User

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class RefreshTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class LogoutRequest(BaseModel):
    refresh_token: str

class MFASetupRequest(BaseModel):
    user_id: int

class MFASetupResponse(BaseModel):
    secret_key: str
    qr_code: str
    backup_codes: List[str]

class MFAVerifyRequest(BaseModel):
    user_id: int
    code: str

class MFAVerifyResponse(BaseModel):
    success: bool
    message: str

class AzureADLoginRequest(BaseModel):
    code: str
    state: str

class AzureADConfigRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    is_enabled: bool = True

class AzureADConfigResponse(AzureADConfigRequest):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class UserSessionResponse(BaseModel):
    id: int
    session_id: str
    user_id: int
    expires_at: datetime
    is_active: bool
    created_at: datetime
    last_used: datetime
    
    class Config:
        from_attributes = True
