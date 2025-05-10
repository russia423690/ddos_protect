from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator


class UserBase(BaseModel):
    username: str
    email: EmailStr
    
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None
    
class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True
class APIKeyCreate(BaseModel):
    name: str
    expires_at: Optional[datetime] = None
    
class APIKeyResponse(BaseModel):
    id: int
    name: str
    key: str
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    
class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    ip_address: str
    user_id: Optional[int]
    details: Optional[str]
    severity: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class BlacklistedIPCreate(BaseModel):
    ip_address: str
    reason: str
    expires_at: Optional[datetime] = None
    
class BlacklistedIPResponse(BaseModel):
    id: int
    ip_address: str
    reason: str
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class AccessLogResponse(BaseModel):
    id: int
    endpoint: str
    method: str
    ip_address: str
    user_id: Optional[int]
    status_code: int
    response_time: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

class RateLimitResponse(BaseModel):
    detail: str
    retry_after: int
