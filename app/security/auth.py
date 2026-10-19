import hmac
from enum import Enum
from typing import Optional
from pydantic import BaseModel
from fastapi import Request, WebSocket, HTTPException, Security, status, Depends
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

def validate_token(token: Optional[str]) -> Optional[User]:
    """Validates an API token or key and returns the corresponding User, or None."""
    if not token or not isinstance(token, str):
        return None
    token = token.strip()
    if settings.ADMIN_API_KEY and _constant_time_compare(token, settings.ADMIN_API_KEY):
        return User(username="admin", role=Role.ADMIN)
    if settings.ANALYST_API_KEY and _constant_time_compare(token, settings.ANALYST_API_KEY):
        return User(username="analyst", role=Role.ANALYST)
    return None

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
        if settings.DEMO_MODE:
            return User(username="demo_viewer", role=Role.VIEWER)
        return User(username="anonymous", role=Role.VIEWER)

    user = validate_token(token)
    if user:
        return user

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
        if user.username in ("anonymous", "demo_viewer") and min_role != Role.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication required for {min_role.value} operations. Please log in or provide 'X-API-Key' header.",
                headers={"WWW-Authenticate": "ApiKey"}
            )

        if ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: '{min_role.value}', current role: '{user.role.value}'."
            )
        return user
    return role_checker

async def authenticate_websocket(websocket: WebSocket) -> Optional[User]:
    """
    Authenticates a WebSocket connection via cookies or query parameter.
    Allows connection if authenticated, or in DEMO_MODE as VIEWER.
    Returns User on success, or None on authentication failure.
    """
    if not settings.AUTH_ENABLED:
        return User(username="admin_local", role=Role.ADMIN)

    # Check query params (?token=... or ?api_key=...)
    token = websocket.query_params.get("token") or websocket.query_params.get("api_key")
    if not token and "soc_api_key" in websocket.cookies:
        token = websocket.cookies.get("soc_api_key")

    if token:
        user = validate_token(token)
        if user:
            return user

    # In DEMO_MODE, grant read-only stream access
    if settings.DEMO_MODE:
        return User(username="demo_viewer", role=Role.VIEWER)

    # For standalone single-user local loopback connections, allow VIEWER by default
    client_host = websocket.client.host if websocket.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost"):
        return User(username="local_viewer", role=Role.VIEWER)

    return None

