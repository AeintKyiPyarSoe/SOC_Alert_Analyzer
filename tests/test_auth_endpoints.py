import uuid
from app.config import settings

def test_login_success_admin_sets_cookie(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["role"] == "ADMIN"
    assert "soc_api_key" in response.cookies
    assert response.cookies["soc_api_key"] == settings.ADMIN_API_KEY

def test_login_success_analyst_sets_cookie(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ANALYST_API_KEY}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["role"] == "ANALYST"
    assert "soc_api_key" in response.cookies

def test_login_invalid_key_fails(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": "invalid-secret-key-12345"}
    )
    assert response.status_code == 401
    assert "Invalid API key" in response.json()["detail"]
    assert "soc_api_key" not in response.cookies

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

def test_logout_clears_cookie(unauthenticated_client):
    # Log in first
    login_resp = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert login_resp.status_code == 200

    # Logout
    logout_resp = unauthenticated_client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "success"

def test_cookie_authenticated_requests(unauthenticated_client, db_session):
    # Without cookie, sensitive endpoint fails
    fake_id = uuid.uuid4()
    resp = unauthenticated_client.patch(
        f"/api/v1/alerts/{fake_id}/status",
        json={"status": "INVESTIGATING"}
    )
    assert resp.status_code == 401

    # Log in via cookie as analyst
    login_res = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ANALYST_API_KEY}
    )
    assert login_res.status_code == 200

    # Verify /api/v1/auth/me returns ANALYST using session cookie
    me_resp = unauthenticated_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "ANALYST"
    assert me_resp.json()["authenticated"] is True

    # Analyst can run audit drill via cookie
    audit_resp = unauthenticated_client.post("/api/v1/host/drill")
    assert audit_resp.status_code == 200

    # Analyst cannot delete alert (requires ADMIN)
    del_resp = unauthenticated_client.delete(f"/api/v1/alerts/{fake_id}")
    assert del_resp.status_code == 403

def test_admin_cookie_can_delete_and_clear(unauthenticated_client):
    # Log in as ADMIN
    login_res = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"api_key": settings.ADMIN_API_KEY}
    )
    assert login_res.status_code == 200

    # Admin can clear alerts via cookie
    clear_resp = unauthenticated_client.post("/api/v1/alerts/clear")
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "success"
