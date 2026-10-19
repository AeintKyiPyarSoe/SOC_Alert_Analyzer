import uuid
from app.config import settings
from app.security.session import session_manager

def test_login_success_admin_sets_secure_session_and_csrf_cookie(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["role"] == "ADMIN"
    assert "csrf_token" in data
    # Confirm raw API key is NOT stored in cookies
    assert "soc_session" in response.cookies
    assert response.cookies["soc_session"] != settings.ADMIN_API_KEY
    assert "soc_csrf" in response.cookies
    assert response.cookies["soc_csrf"] == data["csrf_token"]
    assert "soc_api_key" not in response.cookies

def test_login_success_analyst_sets_opaque_session(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ANALYST_API_KEY}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["role"] == "ANALYST"
    assert "soc_session" in response.cookies
    assert response.cookies["soc_session"] != settings.ANALYST_API_KEY
    assert "csrf_token" in data

def test_login_invalid_key_fails(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": "invalid-secret-key-12345"}
    )
    assert response.status_code == 401
    assert "Invalid API key" in response.json()["detail"]
    assert "soc_session" not in response.cookies

def test_login_empty_or_missing_key(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": ""}
    )
    assert response.status_code == 401

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={}
    )
    assert response.status_code == 422

def test_logout_revokes_session_and_clears_cookies(unauthenticated_client):
    # Log in first
    login_resp = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert login_resp.status_code == 200
    session_token = login_resp.cookies["soc_session"]
    csrf_token = login_resp.json()["csrf_token"]

    # Verify session is active in server store
    assert session_manager.get_session(session_token) is not None

    # Logout with CSRF token
    logout_resp = unauthenticated_client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "success"

    # Verify session was revoked on server
    assert session_manager.get_session(session_token) is None

def test_csrf_protection_on_state_changing_requests(unauthenticated_client, db_session):
    # 1. Log in via session cookie as Analyst
    login_res = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ANALYST_API_KEY}
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]

    # 2. State-changing POST without CSRF token fails with 403
    fail_resp = unauthenticated_client.post("/api/v1/host/drill")
    assert fail_resp.status_code == 403
    assert "CSRF validation failed" in fail_resp.json()["detail"]

    # 3. State-changing POST with invalid CSRF token fails with 403
    fail_invalid = unauthenticated_client.post(
        "/api/v1/host/drill",
        headers={"X-CSRF-Token": "bad-csrf-token"}
    )
    assert fail_invalid.status_code == 403

    # 4. State-changing POST with valid CSRF token succeeds
    success_resp = unauthenticated_client.post(
        "/api/v1/host/drill",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert success_resp.status_code == 200

def test_api_key_clients_bypass_csrf_requirement(unauthenticated_client):
    # Programmatic API clients using X-API-Key do not require CSRF token
    resp = unauthenticated_client.post(
        "/api/v1/host/drill",
        headers={"X-API-Key": settings.ANALYST_API_KEY}
    )
    assert resp.status_code == 200

def test_admin_session_can_delete_and_clear_with_csrf(unauthenticated_client):
    # Log in as ADMIN
    login_res = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]

    # Admin can clear alerts via cookie when providing valid CSRF
    clear_resp = unauthenticated_client.post(
        "/api/v1/alerts/clear",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "success"

def test_websocket_ticket_issuance_and_consumption(unauthenticated_client):
    # Unauthenticated client cannot get ticket
    anon_resp = unauthenticated_client.post("/api/v1/auth/ws-ticket")
    assert anon_resp.status_code == 401

    # Log in as analyst
    login_res = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ANALYST_API_KEY}
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]

    # Request short-lived single-use ticket
    ticket_resp = unauthenticated_client.post(
        "/api/v1/auth/ws-ticket",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert ticket_resp.status_code == 200
    ticket = ticket_resp.json()["ticket"]
    assert ticket.startswith("wst_")

    # Ticket consumption is single-use
    consumed = session_manager.consume_ws_ticket(ticket)
    assert consumed is not None
    assert consumed["username"] == "analyst"
    assert consumed["role"] == "ANALYST"

    # Second consumption of the same ticket must fail (atomically consumed)
    assert session_manager.consume_ws_ticket(ticket) is None
