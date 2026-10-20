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
      - Thread-safe, atomic session rotation to prevent session fixation
      - Constant-time cryptographic CSRF token validation
      - Short-lived, single-use WebSocket connection tickets
      - Thread-safe bounded storage with automatic stale session, ticket, and rate-limit pruning
    """

    MAX_SESSIONS: int = 10000
    MAX_WS_TICKETS: int = 5000

    def __init__(self):
        self._sessions: Dict[str, SessionData] = {}
        self._ws_tickets: Dict[str, Dict] = {}
        self._login_attempts: Dict[str, list] = {}
        self._lockouts: Dict[str, float] = {}
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
            # Enforce capacity bound to prevent memory exhaustion
            if len(self._sessions) >= self.MAX_SESSIONS:
                oldest_hash = min(self._sessions, key=lambda k: self._sessions[k].created_at)
                del self._sessions[oldest_hash]

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
        Atomically rotates session identifier to prevent session fixation upon privilege changes.
        Thread-safe under lock: the old session is consumed and replaced in a single atomic step.
        """
        if not old_session_token or not isinstance(old_session_token, str):
            return None

        old_hash = self._hash_token(old_session_token)
        now = time.time()

        with self._lock:
            old_session = self._sessions.pop(old_hash, None)
            if not old_session or now > old_session.expires_at:
                return None

            new_session_token = f"soc_{secrets.token_urlsafe(32)}"
            new_csrf_token = secrets.token_urlsafe(32)
            new_hash = self._hash_token(new_session_token)

            self._prune_expired_locked(now)
            self._sessions[new_hash] = SessionData(
                session_id_hash=new_hash,
                username=old_session.username,
                role=old_session.role,
                csrf_token=new_csrf_token,
                created_at=now,
                expires_at=old_session.expires_at
            )
            return new_session_token, new_csrf_token

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
            if len(self._ws_tickets) >= self.MAX_WS_TICKETS:
                oldest_ticket = min(self._ws_tickets, key=lambda k: self._ws_tickets[k]["expires_at"])
                del self._ws_tickets[oldest_ticket]

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

    def is_rate_limited(self, client_ip: str) -> Tuple[bool, int]:
        """
        Checks if an IP is currently locked out from authentication.
        Returns (is_locked, remaining_seconds).
        """
        now = time.time()
        with self._lock:
            self._prune_stale_attempts_and_lockouts_locked(now)
            lockout_until = self._lockouts.get(client_ip)
            if lockout_until:
                if now < lockout_until:
                    return True, int(lockout_until - now)
                else:
                    del self._lockouts[client_ip]
            return False, 0

    def record_login_attempt(
        self,
        client_ip: str,
        success: bool,
        max_attempts: int = 5,
        window_seconds: int = 60,
        lockout_seconds: int = 300
    ) -> bool:
        """
        Records an authentication attempt. If failures exceed max_attempts within window,
        temporarily locks out the IP for lockout_seconds. Automatically cleans up stale IP entries.
        """
        now = time.time()
        with self._lock:
            self._prune_stale_attempts_and_lockouts_locked(now, window_seconds)
            if success:
                self._login_attempts.pop(client_ip, None)
                self._lockouts.pop(client_ip, None)
                return True

            attempts = self._login_attempts.get(client_ip, [])
            attempts = [t for t in attempts if now - t <= window_seconds]
            attempts.append(now)
            self._login_attempts[client_ip] = attempts

            if len(attempts) >= max_attempts:
                self._lockouts[client_ip] = now + lockout_seconds
                return False
            return True

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

    def _prune_stale_attempts_and_lockouts_locked(self, now: float, window_seconds: int = 60):
        """Internal helper to clean up expired lockouts and stale login attempts across all IPs."""
        expired_lockouts = [ip for ip, exp in self._lockouts.items() if now >= exp]
        for ip in expired_lockouts:
            del self._lockouts[ip]

        stale_ips = []
        for ip, attempts in self._login_attempts.items():
            valid = [t for t in attempts if now - t <= window_seconds]
            if not valid:
                stale_ips.append(ip)
            else:
                self._login_attempts[ip] = valid
        for ip in stale_ips:
            del self._login_attempts[ip]

session_manager = SessionManager()
