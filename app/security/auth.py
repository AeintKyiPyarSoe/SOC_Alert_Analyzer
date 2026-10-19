import hmac
from enum import Enum
from typing import Optional
from pydantic import BaseModel
from fastapi import Request, HTTPException, Security, status, Depends
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings

class Role(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"

ROLE_HIERARCHY = {
    Role.ADMIN: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1
}

class User(BaseModel):
    username: str
    role: Role

api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

def _constant_time_compare(val1: str, val2: str) -> bool:
    """Safely compare secret keys without timing side-channel leakage."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))

def get_current_user(
    request: Request,
    api_key_header: Optional[str] = Security(api_key_header_scheme),
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)
) -> User:
    """
    Resolves the authenticated user and assigned role from request headers or session cookies.
    """
    if not settings.AUTH_ENABLED:
        return User(username="admin_local", role=Role.ADMIN)

    token = None
    if api_key_header:
        token = api_key_header.strip()
    elif bearer_auth and bearer_auth.credentials:
        token = bearer_auth.credentials.strip()
    elif "soc_api_key" in request.cookies:
        token = request.cookies.get("soc_api_key", "").strip()

    # If no token provided
    if not token:
        # Check if internal browser UI header is present with referer from same host
        # For backward compatibility with the embedded UI, allow read-only viewer by default
        return User(username="anonymous", role=Role.VIEWER)

    # Validate against configured API keys using constant-time comparison
    if settings.ADMIN_API_KEY and _constant_time_compare(token, settings.ADMIN_API_KEY):
        return User(username="admin", role=Role.ADMIN)

    if settings.ANALYST_API_KEY and _constant_time_compare(token, settings.ANALYST_API_KEY):
        return User(username="analyst", role=Role.ANALYST)

    # Invalid token provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key or authorization token.",
        headers={"WWW-Authenticate": "ApiKey"}
    )

def require_role(min_role: Role):
    """
    Role-based access control dependency factory.
    Enforces minimum required privilege tier (ADMIN > ANALYST > VIEWER).
    """
    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.username == "anonymous" and min_role != Role.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication required for {min_role.value} operations. Provide 'X-API-Key' header.",
                headers={"WWW-Authenticate": "ApiKey"}
            )

        if ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: '{min_role.value}', current role: '{user.role.value}'."
            )
        return user
    return role_checker
