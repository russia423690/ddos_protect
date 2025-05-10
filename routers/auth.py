from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database import get_db
from models import User
import schemas
from auth import (
    authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    get_password_hash
)
from security import (
    record_failed_login, check_failed_logins, reset_failed_logins,
    MAX_FAILED_LOGIN_ATTEMPTS, record_security_event
)

router = APIRouter()

@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    
    failed_attempts = check_failed_logins(client_ip, form_data.username)
    if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        record_security_event(
            db=db,
            event_type="login_attempt_limit_exceeded",
            ip_address=client_ip,
            details=f"Too many failed login attempts for user: {form_data.username}",
            severity="high"
        )
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later."
        )
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        attempts = record_failed_login(client_ip, form_data.username)
        
        record_security_event(
            db=db,
            event_type="failed_login",
            ip_address=client_ip,
            details=f"Failed login attempt for user: {form_data.username}",
            severity="low"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    reset_failed_logins(client_ip, form_data.username)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "id": user.id},
        expires_delta=access_token_expires
    )
    
    record_security_event(
        db=db,
        event_type="successful_login",
        ip_address=client_ip,
        user_id=user.id,
        severity="info"
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    request: Request,
    user_create: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        (User.username == user_create.username) | (User.email == user_create.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    hashed_password = get_password_hash(user_create.password)
    
    is_admin = db.query(User).count() == 0
    
    new_user = User(
        username=user_create.username,
        email=user_create.email,
        password_hash=hashed_password,
        is_admin=is_admin
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    client_ip = request.client.host
    record_security_event(
        db=db,
        event_type="user_registration",
        ip_address=client_ip,
        user_id=new_user.id,
        severity="info"
    )
    
    return new_user
