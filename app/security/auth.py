import hmac
import urllib.parse
from enum import Enum
from typing import Optional
from pydantic import BaseModel
from fastapi import Request, WebSocket, HTTPException, Security, status, Depends
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.security.session import session_manager, SessionData

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
    auth_type: str = "anonymous"  # "api_key", "session", or "anonymous"

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
        return User(username="admin", role=Role.ADMIN, auth_type="api_key")
    if settings.ANALYST_API_KEY and _constant_time_compare(token, settings.ANALYST_API_KEY):
        return User(username="analyst", role=Role.ANALYST, auth_type="api_key")
    return None

def get_current_user(
    request: Request,
    api_key_header: Optional[str] = Security(api_key_header_scheme),
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)
) -> User:
    """
    Resolves the authenticated user and assigned role from:
      1. Direct API Key header (X-API-Key or Bearer token for programmatic API clients)
      2. Server-side session token cookie ('soc_session')
      3. Legacy cookie ('soc_api_key' for backward compatibility during transition)
      4. Default to VIEWER (demo mode or unauthenticated guest)
    """
    if not settings.AUTH_ENABLED:
        return User(username="admin_local", role=Role.ADMIN, auth_type="local")

    # 1. Check programmatic API Key headers
    api_key = None
    if api_key_header:
        api_key = api_key_header.strip()
    elif bearer_auth and bearer_auth.credentials:
        api_key = bearer_auth.credentials.strip()

    if api_key:
        user = validate_token(api_key)
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key or authorization token.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # 2. Check server-side opaque session cookie
    session_token = request.cookies.get("soc_session")
    if session_token:
        session = session_manager.get_session(session_token.strip())
        if session:
            try:
                role_enum = Role(session.role)
            except ValueError:
                role_enum = Role.VIEWER
            return User(username=session.username, role=role_enum, auth_type="session")

    # 3. Check legacy cookie for backward compatibility
    legacy_key = request.cookies.get("soc_api_key")
    if legacy_key:
        user = validate_token(legacy_key.strip())
        if user:
            return user

    # 4. Fallback to unauthenticated / demo guest
    if settings.DEMO_MODE:
        return User(username="demo_viewer", role=Role.VIEWER, auth_type="anonymous")
    return User(username="anonymous", role=Role.VIEWER, auth_type="anonymous")

def verify_csrf(request: Request, user: User = Depends(get_current_user)) -> User:
    """
    Enforces Double Submit / Session-bound CSRF validation on state-changing browser requests.
    Only triggered for session-authenticated browser requests; programmatic API key clients
    are exempt as custom headers cannot be forged cross-origin by browsers.
    """
    if request.method in ("POST", "PATCH", "DELETE", "PUT"):
        # If authenticated via session cookie
        if user.auth_type == "session":
            session_token = request.cookies.get("soc_session")
            session = session_manager.get_session(session_token) if session_token else None
            if session:
                client_csrf = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")
                if not session_manager.validate_csrf(session, client_csrf):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="CSRF validation failed: Invalid or missing CSRF token."
                    )
    return user

def require_role(min_role: Role):
    """
    Role-based access control dependency factory.
    Enforces minimum required privilege tier (ADMIN > ANALYST > VIEWER) and CSRF protection.
    """
    def role_checker(request: Request, user: User = Depends(get_current_user)) -> User:
        # Check CSRF first for state-changing operations
        verify_csrf(request, user)

        if user.username in ("anonymous", "demo_viewer") and min_role != Role.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication required: Please sign in with an {min_role.value.capitalize()} access key to perform this action.",
                headers={"WWW-Authenticate": "ApiKey"}
            )

        if ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {min_role.value.capitalize()} privileges required (current level: {user.role.value.capitalize()})."
            )
        return user
    return role_checker

def is_allowed_origin(origin: Optional[str], host_header: Optional[str]) -> bool:
    """
    Validates WebSocket origin header against allowed hosts to prevent cross-site WebSocket hijacking.
    """
    if not origin:
        return True  # Native desktop clients / same-origin without origin header

    try:
        parsed = urllib.parse.urlparse(origin)
        origin_host = parsed.hostname
        if not origin_host:
            return False

        # Always permit loopback / local development
        if origin_host in ("127.0.0.1", "localhost", "::1"):
            return True

        # Check against incoming Host header
        if host_header:
            parsed_host = host_header.split(":")[0]
            if origin_host.lower() == parsed_host.lower():
                return True

        # Check against configured ALLOWED_ORIGINS (excluding wildcard * for WebSocket connections)
        for allowed in settings.ALLOWED_ORIGINS:
            if allowed != "*":
                parsed_allowed = urllib.parse.urlparse(allowed if "://" in allowed else f"http://{allowed}").hostname
                if parsed_allowed and parsed_allowed.lower() == origin_host.lower():
                    return True
        return False
    except Exception:
        return False

async def authenticate_websocket(websocket: WebSocket) -> Optional[User]:
    """
    Authenticates a WebSocket connection via:
      1. Short-lived, single-use connection ticket (?ticket=...)
      2. Server-side session cookie ('soc_session')
      3. Legacy token parameter / cookie (legacy scripts)
      4. Demo mode fallback
    Validates origin header to protect against Cross-Site WebSocket Hijacking (CSWSH).
    Returns User on success, or None on failure (resulting in code 1008 Policy Violation).
    """
    # Validate WebSocket Origin
    origin = websocket.headers.get("origin")
    host_header = websocket.headers.get("host")
    if not is_allowed_origin(origin, host_header):
        return None

    if not settings.AUTH_ENABLED:
        return User(username="admin_local", role=Role.ADMIN, auth_type="local")

    # 1. Single-use short-lived connection ticket
    ticket = websocket.query_params.get("ticket")
    if ticket:
        ticket_data = session_manager.consume_ws_ticket(ticket)
        if ticket_data:
            try:
                role_enum = Role(ticket_data["role"])
            except ValueError:
                role_enum = Role.VIEWER
            return User(username=ticket_data["username"], role=role_enum, auth_type="session")

    # 2. Server-side session cookie
    session_token = websocket.cookies.get("soc_session")
    if session_token:
        session = session_manager.get_session(session_token.strip())
        if session:
            try:
                role_enum = Role(session.role)
            except ValueError:
                role_enum = Role.VIEWER
            return User(username=session.username, role=role_enum, auth_type="session")

    # 3. Legacy token parameter or cookie
    token = websocket.query_params.get("token") or websocket.query_params.get("api_key")
    if not token and "soc_api_key" in websocket.cookies:
        token = websocket.cookies.get("soc_api_key")

    if token:
        user = validate_token(token)
        if user:
            return user

    # 4. In DEMO_MODE, grant read-only demonstration stream access
    if settings.DEMO_MODE:
        return User(username="demo_viewer", role=Role.VIEWER, auth_type="anonymous")

    # 5. Local loopback viewer
    client_host = websocket.client.host if websocket.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost") and settings.DEMO_MODE:
        return User(username="local_viewer", role=Role.VIEWER, auth_type="anonymous")

    return None
