import time
import secrets
import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from app.config import settings

@dataclass
class SessionData:
    session_id_hash: str
    username: str
    role: str
    csrf_token: str
    created_at: float
    expires_at: float

class SessionManager:
    """
    Cryptographically secure, server-side session and single-use WebSocket ticket store.
    Features:
      - Opaque random tokens (never expose API keys in browser cookies or URLs)
      - SHA-256 hashing of session tokens in memory
      - Session expiration and rotation to prevent session fixation
      - Cryptographic CSRF token generation and validation
      - Short-lived, single-use WebSocket connection tickets
      - Thread-safe storage with automatic stale session pruning
    """

    def __init__(self):
        self._sessions: Dict[str, SessionData] = {}
        self._ws_tickets: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

    def create_session(
        self,
        username: str,
        role: str,
        expiry_seconds: Optional[int] = None
    ) -> Tuple[str, str]:
        """
        Creates a new session and returns (raw_session_token, raw_csrf_token).
        Only the hash of the session token is stored on the server.
        """
        if expiry_seconds is None:
            expiry_seconds = getattr(settings, "SESSION_EXPIRY_SECONDS", 43200)

        session_token = f"soc_{secrets.token_urlsafe(32)}"
        csrf_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(session_token)

        now = time.time()
        session_data = SessionData(
            session_id_hash=token_hash,
            username=username,
            role=role,
            csrf_token=csrf_token,
            created_at=now,
            expires_at=now + expiry_seconds
        )

        with self._lock:
            self._prune_expired_locked(now)
            self._sessions[token_hash] = session_data

        return session_token, csrf_token

    def get_session(self, session_token: Optional[str]) -> Optional[SessionData]:
        """
        Retrieves and validates an active session. Returns None if invalid or expired.
        """
        if not session_token or not isinstance(session_token, str):
            return None

        token_hash = self._hash_token(session_token)
        now = time.time()

        with self._lock:
            session = self._sessions.get(token_hash)
            if not session:
                return None
            if now > session.expires_at:
                del self._sessions[token_hash]
                return None
            return session

    def rotate_session(self, old_session_token: str) -> Optional[Tuple[str, str]]:
        """
        Rotates session identifier to prevent session fixation upon privilege elevation.
        """
        session = self.get_session(old_session_token)
        if not session:
            return None

        self.revoke_session(old_session_token)
        return self.create_session(session.username, session.role)

    def revoke_session(self, session_token: Optional[str]) -> bool:
        """
        Revokes an individual session on logout.
        """
        if not session_token:
            return False
        token_hash = self._hash_token(session_token)
        with self._lock:
            return self._sessions.pop(token_hash, None) is not None

    def revoke_all_for_user(self, username: str) -> int:
        """
        Revokes all active sessions for a specific user.
        """
        count = 0
        with self._lock:
            keys_to_delete = [
                h for h, s in self._sessions.items() if s.username == username
            ]
            for h in keys_to_delete:
                del self._sessions[h]
                count += 1
        return count

    def validate_csrf(self, session: SessionData, client_csrf_token: Optional[str]) -> bool:
        """
        Safely validates CSRF token against session token using constant-time comparison.
        """
        if not client_csrf_token or not isinstance(client_csrf_token, str):
            return False
        return hmac.compare_digest(
            session.csrf_token.encode("utf-8"),
            client_csrf_token.strip().encode("utf-8")
        )

    # ------------------------------------------------------------------------
    # Short-Lived Single-Use WebSocket Tickets
    # ------------------------------------------------------------------------
    def create_ws_ticket(
        self,
        username: str,
        role: str,
        expiry_seconds: Optional[int] = None
    ) -> str:
        """
        Issues a cryptographically secure, single-use ticket for WebSocket handshakes.
        Avoids exposing long-lived tokens in query strings.
        """
        if expiry_seconds is None:
            expiry_seconds = getattr(settings, "WS_TICKET_EXPIRY_SECONDS", 60)

        ticket = f"wst_{secrets.token_urlsafe(24)}"
        now = time.time()

        with self._lock:
            self._prune_tickets_locked(now)
            self._ws_tickets[ticket] = {
                "username": username,
                "role": role,
                "expires_at": now + expiry_seconds
            }
        return ticket

    def consume_ws_ticket(self, ticket: Optional[str]) -> Optional[Dict]:
        """
        Validates and atomically consumes a single-use WebSocket ticket.
        Returns ticket payload if valid, None if invalid or expired.
        """
        if not ticket or not isinstance(ticket, str):
            return None

        now = time.time()
        with self._lock:
            record = self._ws_tickets.pop(ticket.strip(), None)
            if not record:
                return None
            if now > record["expires_at"]:
                return None
            return record

    def _prune_expired_locked(self, now: float):
        """Internal helper to clean up expired sessions."""
        expired = [h for h, s in self._sessions.items() if now > s.expires_at]
        for h in expired:
            del self._sessions[h]

    def _prune_tickets_locked(self, now: float):
        """Internal helper to clean up expired WebSocket tickets."""
        expired = [t for t, rec in self._ws_tickets.items() if now > rec["expires_at"]]
        for t in expired:
            del self._ws_tickets[t]

session_manager = SessionManager()
