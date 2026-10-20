import hmac
import ipaddress
import urllib.parse
from enum import Enum
from typing import Optional
from pydantic import BaseModel
from fastapi import Request, WebSocket, HTTPException, Security, status, Depends
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.security.session import session_manager

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

def is_local_client(client_host: Optional[str]) -> bool:
    """
    Verifies that a network connection originates strictly from local loopback.
    Does NOT trust client-supplied Host or X-Forwarded-For headers.
    """
    if not client_host or not isinstance(client_host, str):
        return False
    host = client_host.strip().lower()
    if host in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False

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
      3. Default to VIEWER (demo mode or unauthenticated guest)
    
    If AUTH_ENABLED is disabled, administrator privileges are strictly restricted to
    verified local loopback connections. Arbitrary remote clients are rejected.
    """
    if not settings.AUTH_ENABLED:
        client_host = request.client.host if request.client else None
        if not is_local_client(client_host):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Authentication-disabled mode is strictly restricted to verified local loopback connections."
            )
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

    # 3. Fallback to unauthenticated / demo guest
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

def is_allowed_origin(origin: Optional[str], host_header: Optional[str] = None) -> bool:
    """
    Validates WebSocket origin header against allowed hosts to prevent cross-site WebSocket hijacking (CSWSH).
    Validates scheme, hostname, and port strictly.
    Rejects malformed origins (userinfo, paths, queries, fragments), arbitrary localhost ports,
    and untrusted cross-origins. Does not rely on untrusted Host headers.
    """
    if origin is None:
        # RFC 6455: Native desktop applications / CLI clients without browser Origin header
        return True

    origin_str = origin.strip()
    if not origin_str:
        return False

    try:
        parsed = urllib.parse.urlparse(origin_str)
        scheme = parsed.scheme.lower()
        # Scheme MUST be standard HTTP or HTTPS
        if scheme not in ("http", "https"):
            return False

        # Reject malformed origins containing credentials, path components, queries, or fragments
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        if parsed.path and parsed.path not in ("", "/"):
            return False

        origin_host = parsed.hostname
        if not origin_host:
            return False
        origin_host = origin_host.lower()

        # Determine effective port
        default_port = 443 if scheme == "https" else 80
        origin_port = parsed.port if parsed.port is not None else default_port

        # 1. Check configured production ALLOWED_ORIGINS
        for allowed in settings.ALLOWED_ORIGINS:
            allowed_clean = allowed.strip()
            if not allowed_clean or allowed_clean == "*":
                # Wildcards are not accepted for authenticated WebSocket origin validation
                continue
            try:
                allowed_parsed = urllib.parse.urlparse(
                    allowed_clean if "://" in allowed_clean else f"https://{allowed_clean}"
                )
                allowed_scheme = allowed_parsed.scheme.lower() if allowed_parsed.scheme else "https"
                allowed_host = (allowed_parsed.hostname or "").lower()
                allowed_port = allowed_parsed.port if allowed_parsed.port is not None else (443 if allowed_scheme == "https" else 80)

                if (scheme == allowed_scheme or not allowed_parsed.scheme) and origin_host == allowed_host and origin_port == allowed_port:
                    return True
            except Exception:
                continue

        # 2. Legitimate localhost / desktop application origins
        if origin_host in ("127.0.0.1", "localhost", "::1"):
            # Permit standard web ports (80, 443, 8080) and launcher dynamic range [8000..8099]
            if origin_port in (80, 443, 8080) or (8000 <= origin_port < 8100):
                return True
            # Reject arbitrary localhost ports (e.g. 3000, 5000, 9999, etc.)
            return False

        return False
    except Exception:
        return False

async def authenticate_websocket(websocket: WebSocket) -> Optional[User]:
    """
    Authenticates a WebSocket connection via:
      1. Short-lived, single-use connection ticket (?ticket=...)
      2. Server-side session cookie ('soc_session')
      3. Demo mode fallback
    Validates origin header to protect against Cross-Site WebSocket Hijacking (CSWSH).
    Returns User on success, or None on failure (resulting in code 1008 Policy Violation).
    """
    # Validate WebSocket Origin strictly
    origin = websocket.headers.get("origin")
    host_header = websocket.headers.get("host")
    if not is_allowed_origin(origin, host_header):
        return None

    if not settings.AUTH_ENABLED:
        client_host = websocket.client.host if websocket.client else None
        if not is_local_client(client_host):
            return None
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

    # 3. In DEMO_MODE, grant read-only demonstration stream access
    if settings.DEMO_MODE:
        return User(username="demo_viewer", role=Role.VIEWER, auth_type="anonymous")

    return None
