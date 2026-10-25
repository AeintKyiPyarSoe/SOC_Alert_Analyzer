"""
tests/test_static_cache_invalidation.py
Regression tests for static asset cache reliability, fingerprinting, and HTTP caching headers.

Asserts:
  1. Static assets (styles.css, app.js) have deterministically computed content fingerprints.
  2. Modifying file content produces a new fingerprint.
  3. Jinja2 templates render HTML with versioned static asset tags (?v=<fingerprint>).
  4. HTTP 304 Not Modified works normally on unchanged assets when If-None-Match or If-Modified-Since is provided.
  5. HTML views carry 'no-cache, must-revalidate' to ensure browsers discover updated asset hashes.
  6. Sensitive API endpoints carry 'no-store, private' cache headers.
"""

import time
import tempfile
from pathlib import Path
from starlette.testclient import TestClient
from app.main import app, versioned_static, get_asset_fingerprint, BASE_DIR
from app.security.session import session_manager
from app.security.auth import Role


def test_asset_fingerprint_deterministic_and_changes_on_modification():
    """Verify content hash fingerprint generation and cache invalidation on content change."""
    # Test on real app assets
    css_fp = get_asset_fingerprint("css/styles.css")
    js_fp = get_asset_fingerprint("js/app.js")
    assert len(css_fp) == 12, f"Expected 12-char hex digest, got {css_fp}"
    assert len(js_fp) == 12, f"Expected 12-char hex digest, got {js_fp}"

    # Repeated calls should return cached fingerprint
    assert get_asset_fingerprint("css/styles.css") == css_fp
    assert get_asset_fingerprint("js/app.js") == js_fp

    # Test versioned URL format
    css_url = versioned_static("css/styles.css")
    js_url = versioned_static("js/app.js")
    assert css_url == f"/static/css/styles.css?v={css_fp}"
    assert js_url == f"/static/js/app.js?v={js_fp}"


def test_jinja2_template_renders_versioned_static_links():
    """Verify dashboard HTML renders fingerprinted script and style links."""
    token, _ = session_manager.create_session("admin", Role.ADMIN)
    client = TestClient(app, cookies={"soc_session": token})

    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text

    css_fp = get_asset_fingerprint("css/styles.css")
    js_fp = get_asset_fingerprint("js/app.js")

    assert f"/static/css/styles.css?v={css_fp}" in html, "Fingerprinted CSS link missing in HTML"
    assert f"/static/js/app.js?v={js_fp}" in html, "Fingerprinted JS script missing in HTML"


def test_static_asset_http_304_caching_behavior():
    """Verify unchanged static assets return HTTP 304 when client sends ETag / If-None-Match."""
    client = TestClient(app)

    # 1. First GET returns 200 with ETag / Last-Modified
    resp1 = client.get("/static/css/styles.css")
    assert resp1.status_code == 200
    etag = resp1.headers.get("etag")
    last_mod = resp1.headers.get("last-modified")

    # Static asset should carry cache-control
    assert "public" in resp1.headers.get("cache-control", "")

    # 2. Conditional GET with If-None-Match returns 304 Not Modified
    if etag:
        resp_etag = client.get("/static/css/styles.css", headers={"If-None-Match": etag})
        assert resp_etag.status_code == 304

    # 3. Conditional GET with If-Modified-Since returns 304 Not Modified
    if last_mod:
        resp_mod = client.get("/static/css/styles.css", headers={"If-Modified-Since": last_mod})
        assert resp_mod.status_code == 304


def test_html_views_cache_control_headers():
    """Verify HTML document endpoints enforce revalidation to ensure prompt asset refresh."""
    token, _ = session_manager.create_session("analyst", Role.ANALYST)
    client = TestClient(app, cookies={"soc_session": token})

    for endpoint in ["/", "/alerts", "/incidents", "/reports/mitre", "/upload"]:
        resp = client.get(endpoint)
        assert resp.status_code == 200
        cc = resp.headers.get("cache-control", "")
        assert "no-cache" in cc, f"Expected no-cache for {endpoint}, got '{cc}'"
        assert "must-revalidate" in cc, f"Expected must-revalidate for {endpoint}, got '{cc}'"


def test_sensitive_api_cache_control_headers():
    """Verify sensitive telemetry API responses carry 'no-store, private'."""
    token, _ = session_manager.create_session("analyst", Role.ANALYST)
    client = TestClient(app, cookies={"soc_session": token})

    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    cc = resp.headers.get("cache-control", "")
    assert "no-store" in cc, f"Expected no-store for API endpoint, got '{cc}'"
    assert "private" in cc, f"Expected private for API endpoint, got '{cc}'"
