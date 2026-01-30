# FastAPI Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for FastAPI applications.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [Authentication & Authorization](#authentication--authorization)
3. [Input Validation](#input-validation)
4. [Path Traversal](#path-traversal)
5. [Secrets Management](#secrets-management)
6. [CORS Configuration](#cors-configuration)
7. [Rate Limiting](#rate-limiting)
8. [Insecure Deserialization](#insecure-deserialization)

---

## SQL Injection

### ❌ Vulnerable Patterns

```python
# String formatting in queries
@app.get("/users/{user_id}")
async def get_user(user_id: str, db: Session = Depends(get_db)):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # DANGEROUS
    result = db.execute(query)
    return result.fetchone()

# Even with text(), if you interpolate
from sqlalchemy import text
query = text(f"SELECT * FROM users WHERE name = '{name}'")  # Still dangerous
```

### ✅ Safe Patterns

```python
# SQLAlchemy ORM (parameterized by default)
@app.get("/users/{user_id}")
async def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Raw SQL with bound parameters
from sqlalchemy import text

@app.get("/search")
async def search_users(name: str, db: Session = Depends(get_db)):
    query = text("SELECT * FROM users WHERE name = :name")
    result = db.execute(query, {"name": name})
    return result.fetchall()

# Using bindparams explicitly
query = text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id)
```

---

## Authentication & Authorization

### JWT Authentication Setup

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# Configuration
SECRET_KEY = settings.secret_key  # From environment!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

### Protecting Endpoints

```python
# ❌ Unprotected endpoint
@app.get("/users/me")
async def read_users_me():
    return {"error": "no auth!"}

# ✅ Protected endpoint
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# ✅ Role-based access
async def get_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@app.delete("/users/{user_id}")
async def delete_user(user_id: int, admin: User = Depends(get_admin_user)):
    # Only admins can delete
    pass
```

---

## Input Validation

### Pydantic Models

```python
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional

# ✅ Strong validation with Pydantic
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(..., min_length=12)
    
    @validator('password')
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    # Note: password update should be separate endpoint with current password check

# Usage - FastAPI validates automatically
@app.post("/users")
async def create_user(user: UserCreate):
    # user is already validated
    pass
```

### Path Parameter Validation

```python
from fastapi import Path, Query

@app.get("/users/{user_id}")
async def get_user(
    user_id: int = Path(..., gt=0, description="User ID must be positive")
):
    pass

@app.get("/search")
async def search(
    q: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(10, ge=1, le=100)
):
    pass
```

---

## Path Traversal

### ❌ Vulnerable Patterns

```python
from pathlib import Path

@app.get("/files/{filename}")
async def get_file(filename: str):
    # Attacker: filename = "../../../etc/passwd"
    file_path = f"uploads/{filename}"  # DANGEROUS
    return FileResponse(file_path)
```

### ✅ Safe Patterns

```python
from pathlib import Path
import os

UPLOAD_DIR = Path("uploads").resolve()

@app.get("/files/{filename}")
async def get_file(filename: str):
    # Strip directory components
    safe_name = Path(filename).name
    
    # Resolve and verify within allowed directory
    file_path = (UPLOAD_DIR / safe_name).resolve()
    
    if not str(file_path).startswith(str(UPLOAD_DIR)):
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)
```

---

## Secrets Management

### ❌ Vulnerable Patterns

```python
# Hardcoded secrets
SECRET_KEY = "super-secret-key-123"
DATABASE_URL = "postgresql://user:password@localhost/db"

# Committing .env files
# .gitignore missing .env
```

### ✅ Safe Patterns

```python
# settings.py - Pydantic Settings
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    secret_key: str
    database_url: str
    debug: bool = False
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Usage
from config import settings

SECRET_KEY = settings.secret_key  # Loaded from environment
```

```bash
# .env (never commit this)
SECRET_KEY=your-super-secret-key-generated-with-openssl
DATABASE_URL=postgresql://user:password@localhost/db

# .gitignore
.env
.env.*
!.env.example
```

---

## CORS Configuration

### ❌ Vulnerable Patterns

```python
from fastapi.middleware.cors import CORSMiddleware

# Allowing all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DANGEROUS in production
    allow_credentials=True,  # Especially with credentials!
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### ✅ Safe Patterns

```python
from fastapi.middleware.cors import CORSMiddleware

# Explicit origin allowlist
ALLOWED_ORIGINS = [
    "https://myapp.com",
    "https://www.myapp.com",
]

if settings.debug:
    ALLOWED_ORIGINS.append("http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/login")
@limiter.limit("5/minute")  # Prevent brute force
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    pass

@app.get("/api/data")
@limiter.limit("100/minute")
async def get_data(request: Request):
    pass
```

---

## Insecure Deserialization

### ❌ Vulnerable Patterns

```python
import pickle
import yaml

@app.post("/import")
async def import_data(data: bytes):
    obj = pickle.loads(data)  # DANGEROUS - arbitrary code execution
    return obj

@app.post("/config")
async def load_config(config: str):
    data = yaml.load(config)  # DANGEROUS - unsafe loader
    return data
```

### ✅ Safe Patterns

```python
import json
import yaml

@app.post("/import")
async def import_data(data: str):
    try:
        obj = json.loads(data)  # Safe - limited types
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    return obj

@app.post("/config")
async def load_config(config: str):
    data = yaml.safe_load(config)  # Safe loader
    return data

# For complex objects, use Pydantic
class ImportData(BaseModel):
    items: list[dict]
    metadata: dict

@app.post("/import")
async def import_data(data: ImportData):
    # Pydantic validates structure
    return data
```

---

## Quick Reference

| Vulnerability | FastAPI Protection |
|---------------|-------------------|
| SQL Injection | SQLAlchemy ORM, bound parameters |
| Auth Bypass | `Depends(get_current_user)` |
| Input Validation | Pydantic models |
| Path Traversal | `Path().name` + resolve check |
| CORS | Explicit origin allowlist |
| Rate Limiting | slowapi middleware |

---

*Condensed version: [condensed.md](./condensed.md)*
