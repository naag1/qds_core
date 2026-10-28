from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError, decode, encode
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.database import User, get_db
from app.settings import get_settings

passwords = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def hash_password(value: str) -> str: return passwords.hash(value)
def verify_password(value: str, hashed: str) -> bool: return passwords.verify(value, hashed)

def create_token(user: User) -> str:
    settings = get_settings()
    return encode({"sub": user.username, "role": user.role, "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)}, settings.jwt_secret, algorithm="HS256")

def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        name = decode(token, get_settings().jwt_secret, algorithms=["HS256"])["sub"]
    except (InvalidTokenError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    user = db.query(User).filter_by(username=name, active=True).first()
    if not user: raise HTTPException(status_code=401, detail="Inactive or unknown user")
    return user

def require_role(*roles: str):
    def guard(user: User = Depends(current_user)) -> User:
        if user.role not in roles: raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return guard
