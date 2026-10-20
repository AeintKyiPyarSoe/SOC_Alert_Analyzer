import time
from app.security.session import SessionManager

def test_session_lifecycle_create_get_revoke():
    sm = SessionManager()
    
    # 1. Create session
    token, csrf = sm.create_session(username="test_analyst", role="ANALYST", expiry_seconds=3600)
    assert token.startswith("soc_")
    assert len(csrf) >= 32

    # 2. Get active session
    session = sm.get_session(token)
    assert session is not None
    assert session.username == "test_analyst"
    assert session.role == "ANALYST"
    assert session.csrf_token == csrf

    # 3. Constant-time CSRF token validation
    assert sm.validate_csrf(session, csrf) is True
    assert sm.validate_csrf(session, "wrong_token") is False
    assert sm.validate_csrf(session, None) is False

    # 4. Revoke session
    assert sm.revoke_session(token) is True
    assert sm.get_session(token) is None
    # Subsequent revocation returns False
    assert sm.revoke_session(token) is False

def test_session_expiration():
    sm = SessionManager()
    # Create short-lived session with 1 second expiry
    token, _ = sm.create_session(username="expiring_user", role="VIEWER", expiry_seconds=1)
    assert sm.get_session(token) is not None

    time.sleep(1.1)
    # Session must be expired and pruned
    assert sm.get_session(token) is None

def test_atomic_session_rotation():
    sm = SessionManager()
    old_token, old_csrf = sm.create_session(username="analyst_bob", role="ANALYST", expiry_seconds=3600)
    
    # Rotate session
    rotated = sm.rotate_session(old_token)
    assert rotated is not None
    new_token, new_csrf = rotated
    
    # Old session is revoked
    assert sm.get_session(old_token) is None

    # New session exists with preserved identity and new CSRF
    new_session = sm.get_session(new_token)
    assert new_session is not None
    assert new_session.username == "analyst_bob"
    assert new_session.role == "ANALYST"
    assert new_session.csrf_token == new_csrf
    assert new_token != old_token

    # Attempting to rotate an already revoked token returns None
    assert sm.rotate_session(old_token) is None

def test_revoke_all_for_user():
    sm = SessionManager()
    t1, _ = sm.create_session("multi_user", "ANALYST")
    t2, _ = sm.create_session("multi_user", "ANALYST")
    t3, _ = sm.create_session("other_user", "VIEWER")

    count = sm.revoke_all_for_user("multi_user")
    assert count == 2
    assert sm.get_session(t1) is None
    assert sm.get_session(t2) is None
    assert sm.get_session(t3) is not None

def test_login_rate_limiting_and_pruning():
    sm = SessionManager()
    ip = "192.168.1.150"

    # 4 failed attempts should not trigger lockout (threshold: 5)
    for _ in range(4):
        allowed = sm.record_login_attempt(ip, success=False, max_attempts=5, window_seconds=60, lockout_seconds=2)
        assert allowed is True

    locked, _ = sm.is_rate_limited(ip)
    assert locked is False

    # 5th failed attempt triggers lockout
    allowed = sm.record_login_attempt(ip, success=False, max_attempts=5, window_seconds=60, lockout_seconds=2)
    assert allowed is False

    locked, remaining = sm.is_rate_limited(ip)
    assert locked is True
    assert remaining > 0

    # Wait for lockout to expire
    time.sleep(2.1)
    locked, _ = sm.is_rate_limited(ip)
    assert locked is False

    # Successful login clears attempts and lockouts
    sm.record_login_attempt(ip, success=True)
    assert ip not in sm._login_attempts
    assert ip not in sm._lockouts

def test_websocket_ticket_lifecycle_and_replay_defense():
    sm = SessionManager()
    ticket = sm.create_ws_ticket(username="alice", role="ANALYST", expiry_seconds=2)
    assert ticket.startswith("wst_")

    # First consumption succeeds
    data = sm.consume_ws_ticket(ticket)
    assert data is not None
    assert data["username"] == "alice"
    assert data["role"] == "ANALYST"

    # Replay attack: second consumption of consumed ticket fails
    assert sm.consume_ws_ticket(ticket) is None

    # Expired ticket fails
    expired_ticket = sm.create_ws_ticket(username="bob", role="VIEWER", expiry_seconds=1)
    time.sleep(1.1)
    assert sm.consume_ws_ticket(expired_ticket) is None
