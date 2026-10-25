import os
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Header, Form, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

import database

BASE_DIR = Path(__file__).resolve().parent

# ==================================================
# JWT CONFIGURATION
# ==================================================

def get_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET_KEY")
    if secret:
        return secret

    secret_file = BASE_DIR / ".jwt_secret"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()

    generated = os.urandom(32).hex()
    try:
        secret_file.write_text(generated, encoding="utf-8")
    except Exception:
        pass
    return generated


JWT_SECRET_KEY = get_jwt_secret()
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.environ.get("JWT_EXPIRATION_MINUTES", "1440"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")


def create_access_token(user_id: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    delta = expires_delta or timedelta(minutes=JWT_EXPIRATION_MINUTES)
    expire = datetime.now(timezone.utc) + delta
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token_from_auth: Optional[str] = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    token = token_from_auth
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing user identity.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = database.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ==================================================
# SCHEMAS
# ==================================================

class RegisterRequest(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., min_length=8, example="SecurePass123")
    full_name: Optional[str] = Field(default="", example="Alex Doe")


class LoginRequest(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., example="SecurePass123")


# ==================================================
# ROUTER
# ==================================================

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/register")
@auth_router.post("/signup")
def register(req: RegisterRequest):
    email = req.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address format.",
        )

    if not PASSWORD_REGEX.match(req.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long and contain both letters and numbers.",
        )

    existing = database.get_user_by_email(email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    user = database.create_user(email, req.password, req.full_name or "")
    token = create_access_token(user["id"], user["email"])

    return {
        "message": "User registered successfully.",
        "access_token": token,
        "token_type": "bearer",
        "user": user,
    }


@auth_router.post("/login")
async def login(
    request: Request,
    login_req: Optional[LoginRequest] = None,
):
    """
    Accepts both JSON body and OAuth2 form data (username/email + password).
    """
    email = ""
    password = ""

    # Check for JSON first
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            email = str(body.get("email") or body.get("username") or "").strip().lower()
            password = str(body.get("password") or "")
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in content_type:
        try:
            form = await request.form()
            email = str(form.get("username") or form.get("email") or "").strip().lower()
            password = str(form.get("password") or "")
        except Exception:
            pass

    if not email and login_req:
        email = login_req.email.strip().lower()
        password = login_req.password

    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required.",
        )

    user = database.get_user_by_email(email)
    if not user or not database.verify_password(password, user["salt"], user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["id"], user["email"])
    return {
        "message": "Login successful.",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "created_at": user.get("created_at", ""),
        },
    }


@auth_router.get("/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "user": current_user
    }
