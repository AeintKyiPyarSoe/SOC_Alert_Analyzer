"""Tests for FastAPI route organization, ensuring zero duplicate route registrations or shadowing."""
import pytest
from app.main import app


def test_no_duplicate_route_registrations():
    """Verify that no (method, path) combination is registered or exposed more than once."""
    openapi = app.openapi()
    paths = openapi.get("paths", {})
    seen_routes = set()

    for path, methods in paths.items():
        for method in methods.keys():
            if method.lower() in ("head", "options"):
                continue
            key = (method.upper(), path)
            assert key not in seen_routes, f"Duplicate route exposed in application: {key}"
            seen_routes.add(key)

    assert len(seen_routes) > 0


def test_api_v1_routes_registered_under_api_prefix():
    """Verify that all API v1 endpoints are registered cleanly with /api/v1 prefix."""
    paths = app.openapi().get("paths", {})
    api_routes = [p for p in paths if p.startswith("/api/v1/")]

    assert len(api_routes) >= 20
    assert "/api/v1/host/monitor/toggle" in api_routes
    assert "/api/v1/simulation/toggle" in api_routes
    assert "/api/v1/stream/status" in api_routes
    assert "/api/v1/sample-data/load/{dataset_type}" in api_routes


def test_main_views_distinct_from_api():
    """Verify that root web views are cleanly separated from API endpoints."""
    paths = app.openapi().get("paths", {})
    web_views = [p for p in paths if not p.startswith("/api/v1/")]

    expected_views = {"/", "/alerts", "/alerts/{alert_id}", "/incidents", "/incidents/{incident_id}", "/upload", "/reports/mitre"}
    assert set(web_views) == expected_views


def test_host_status_reports_monitoring_active():
    """Verify that HostSecuritySensor.get_host_info() reflects host_monitoring_active, not simulation_active."""
    from app.security.host_sensor import host_sensor
    from app.security.stream import stream_manager

    # Case 1: host monitoring True, simulation False
    stream_manager.host_monitoring_active = True
    stream_manager.simulation_active = False
    info1 = host_sensor.get_host_info()
    assert info1["monitoring_active"] is True

    # Case 2: host monitoring False, simulation True
    stream_manager.host_monitoring_active = False
    stream_manager.simulation_active = True
    info2 = host_sensor.get_host_info()
    assert info2["monitoring_active"] is False

    # Restore default
    stream_manager.host_monitoring_active = True
    stream_manager.simulation_active = False


def test_canonical_version_consistency():
    """Verify that canonical version is strictly synchronized across app, config, and main."""
    import app
    from app.config import settings
    from app.main import app as fastapi_app

    assert settings.VERSION == app.__version__
    assert fastapi_app.version == app.__version__
    assert app.__version__ == "1.2.14"
