"""
tests/test_browser_monitoring_ui.py
Playwright Real Browser Automation Test Suite for SOC Alert Analyzer Monitoring UI.

Executes genuine user interactions across Scenarios 1 through 10 in real headless Chromium:
  Scenario 1: Initial CHECKING state (delayed backend response displays neutral CHECKING, no false ACTIVE)
  Scenario 2: Synchronized ACTIVE monitoring state across pill, button, notice, and EDR labels
  Scenario 3: Synchronized PAUSED monitoring state via real button click and pulse animation cessation
  Scenario 4: Backend ERROR handling (500 response displays UNKNOWN/ERROR without false ACTIVE)
  Scenario 5: Stale response race prevention (older delayed response cannot overwrite newer user pause)
  Scenario 6: Decoupled WebSocket connection while Host Monitoring is PAUSED
  Scenario 7: Connection loss handling (transport disruption distinct from monitoring state)
  Scenario 8: Preference-save failure explicit warning toast display
  Scenario 9: Clear History modal confirmation text differentiation (PAUSED vs ACTIVE)
  Scenario 10: Accessibility attributes, button state locks, and keyboard navigation
"""

import time
import socket
import threading
import pytest
from app.main import app
from app.security.session import session_manager
from app.security.auth import Role
from app.security.stream import stream_manager
import uvicorn

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def browser_server():
    """Spins up a lightweight Uvicorn test server on a free port for Playwright tests."""
    port = find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    start = time.time()
    while time.time() - start < 15:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except (OSError, ConnectionRefusedError):
            time.sleep(0.1)

    # Ensure backend starts active for tests
    stream_manager.start_host_monitoring_sync(persist=False)

    yield base_url

    server.should_exit = True
    thread.join(timeout=3)


@pytest.fixture(scope="module")
def browser_instance():
    """Initializes Playwright headless Chromium instance. Fails if Playwright or Chromium is missing."""
    assert PLAYWRIGHT_AVAILABLE, "Playwright is required for browser UI testing but is not installed."
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def auth_page(browser_instance, browser_server):
    """Provides a fresh browser context pre-authenticated as ADMIN."""
    token, _ = session_manager.create_session("admin", Role.ADMIN)
    context = browser_instance.new_context()
    context.add_cookies([
        {
            "name": "soc_session",
            "value": token,
            "domain": "127.0.0.1",
            "path": "/"
        }
    ])
    page = context.new_page()
    yield page, browser_server
    page.close()
    context.close()


def test_scenario_1_initial_checking_neutral_state(auth_page):
    """Scenario 1: Dashboard displays neutral CHECKING state before backend status resolves."""
    page, base_url = auth_page

    pending_routes = []

    def delayed_status(route):
        pending_routes.append(route)

    page.route("**/api/v1/stream/status", delayed_status)
    page.goto(base_url, wait_until="commit")

    # During delay, state must NOT claim ACTIVE; should show neutral checking
    live_text = page.locator("#live-sensor-text")
    live_text.wait_for(state="attached", timeout=5000)
    current_text = live_text.text_content().strip()
    assert "CHECKING" in current_text or "STATUS UNKNOWN" in current_text
    assert current_text != "HOST SENSOR: ACTIVE"

    pill = page.locator("#live-sensor-pill")
    pill_classes = pill.get_attribute("class") or ""
    assert "active" not in pill_classes.split()

    # Now fulfill the held route from the test thread to verify transition to ACTIVE
    assert len(pending_routes) > 0, "Expected /api/v1/stream/status to be intercepted"
    pending_routes[0].fulfill(
        status=200,
        content_type="application/json",
        body='{"host_monitoring_active": true, "monitoring_state": "ACTIVE"}'
    )

    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: ACTIVE"
    page.unroute("**/api/v1/stream/status")


def test_scenario_2_synchronized_active_state(auth_page):
    """Scenario 2: Synchronized ACTIVE monitoring state across all UI indicators."""
    page, base_url = auth_page

    stream_manager.start_host_monitoring_sync(persist=False)
    page.goto(base_url)
    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)

    # 1. Header live sensor text
    live_text = page.locator("#live-sensor-text")
    assert live_text.text_content().strip() == "HOST SENSOR: ACTIVE"

    # 2. Toolbar toggle button
    btn = page.locator("#btn-toggle-host-monitor")
    assert "ACTIVE" in btn.text_content()
    assert not btn.is_disabled()

    # 3. Data notice banner
    notice = page.locator("#data-notice-text")
    assert "Monitoring local machine processes" in notice.text_content()

    # 4. Host EDR sidebar / mode label
    mode_label = page.locator("#host-edr-mode-label")
    assert "Active" in mode_label.text_content()


def test_scenario_3_synchronized_paused_state(auth_page):
    """Scenario 3: Genuine click on Host Sensor button transitions to PAUSED."""
    page, base_url = auth_page

    stream_manager.start_host_monitoring_sync(persist=False)
    page.goto(base_url)
    page.wait_for_selector("#btn-toggle-host-monitor")

    # Genuine user click to pause
    btn = page.locator("#btn-toggle-host-monitor")
    with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
        btn.click()

    # Wait for synchronized PAUSED indicators
    page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)

    live_text = page.locator("#live-sensor-text")
    assert live_text.text_content().strip() == "HOST SENSOR: PAUSED"

    assert "PAUSED" in btn.text_content()
    assert not btn.is_disabled()

    notice = page.locator("#data-notice-text")
    assert "paused" in notice.text_content().lower()

    mode_label = page.locator("#host-edr-mode-label")
    assert "Paused" in mode_label.text_content()

    # Backend verification
    assert stream_manager.get_status()["host_monitoring_active"] is False


def test_scenario_4_backend_error_handling(auth_page):
    """Scenario 4: Backend 500 ERROR displays ERROR/UNKNOWN without false ACTIVE indicator."""
    page, base_url = auth_page

    page.route("**/api/v1/stream/status", lambda route: route.fulfill(status=500, body="Server Error"))
    page.goto(base_url)

    # Wait for the error / unknown state to reflect
    page.wait_for_selector("#live-sensor-pill.unknown, #live-sensor-pill.error", timeout=5000)

    live_text = page.locator("#live-sensor-text")
    text = live_text.text_content().strip()
    assert "UNKNOWN" in text or "ERROR" in text
    assert text != "HOST SENSOR: ACTIVE"

    pill = page.locator("#live-sensor-pill")
    pill_classes = pill.get_attribute("class") or ""
    assert "active" not in pill_classes.split()

    page.unroute("**/api/v1/stream/status")


def test_scenario_5_stale_response_race_prevention(auth_page):
    """Scenario 5: Stale delayed HTTP responses cannot restore ACTIVE after pause."""
    page, base_url = auth_page

    stream_manager.start_host_monitoring_sync(persist=False)
    page.goto(base_url)
    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)

    # Intercept next /stream/status poll and hold it
    held_status_routes = []
    def hold_status(route):
        held_status_routes.append(route)

    page.route("**/api/v1/stream/status", hold_status)

    res = page.evaluate("(() => { try { initStreamStatus(); return 'ok'; } catch(e) { return e.toString(); } })()")
    page.wait_for_timeout(500)
    assert len(held_status_routes) > 0, f"Expected a status check route to be held (res={res})"

    # Now click the button to pause monitoring
    btn = page.locator("#btn-toggle-host-monitor")
    with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
        btn.click()

    page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: PAUSED"

    # Fulfill the older held status route with a stale ACTIVE payload
    stale_route = held_status_routes.pop(0)
    stale_route.fulfill(
        status=200,
        content_type="application/json",
        body='{"host_monitoring_active": true, "monitoring_state": "ACTIVE"}'
    )

    # Allow time for potential UI handling; the stale response must be ignored
    time.sleep(0.5)
    page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: PAUSED"

    page.unroute("**/api/v1/stream/status")


def test_scenario_6_websocket_decoupled_while_paused(auth_page):
    """Scenario 6: Real WebSocket connectivity decoupled from Host Sensor monitoring state."""
    page, base_url = auth_page

    stream_manager.start_host_monitoring_sync(persist=False)
    page.goto(base_url)
    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)

    # Pause host sensor
    btn = page.locator("#btn-toggle-host-monitor")
    with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
        btn.click()

    page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: PAUSED"

    # WebSocket is connected in background; wait a moment and verify monitoring does NOT flip back to ACTIVE
    time.sleep(1.0)
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: PAUSED"


def test_scenario_7_connection_loss_distinction(auth_page):
    """Scenario 7: WebSocket disconnect updates connection pill title without breaking monitoring state."""
    page, base_url = auth_page

    page.goto(base_url)
    page.wait_for_selector("#live-sensor-text")

    # Ensure state is PAUSED so we can test that disconnect leaves monitoring intact
    live_text = page.locator("#live-sensor-text")
    if "ACTIVE" in live_text.text_content():
        btn = page.locator("#btn-toggle-host-monitor")
        with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
            btn.click()
        page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)

    assert "PAUSED" in live_text.text_content()

    # Disconnect websocket client-side
    page.evaluate("""
        if (threatSocket && threatSocket.readyState === WebSocket.OPEN) {
            threatSocket.close(1000);
        }
    """)

    # Verify connection disruption updates pill title without changing monitoring state
    pill = page.locator("#live-sensor-pill")
    page.wait_for_function("() => document.getElementById('live-sensor-pill')?.title?.includes('Telemetry Stream: Reconnecting')", timeout=5000)

    # Verify monitoring text remains strictly PAUSED
    assert page.locator("#live-sensor-text").text_content().strip() == "HOST SENSOR: PAUSED"
    pill_classes = pill.get_attribute("class") or ""
    assert "paused" in pill_classes.split()
    assert "active" not in pill_classes.split()


def test_scenario_8_preference_save_failure_toast(auth_page):
    """Scenario 8: Preference save failure displays explicit warning toast."""
    page, base_url = auth_page

    page.goto(base_url)
    page.wait_for_selector("#btn-toggle-host-monitor")

    # Intercept toggle route to simulate persistence failure in returned JSON
    page.route("**/api/v1/host/monitor/toggle*", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"status": "success", "host_monitoring_active": false, "monitoring_state": "PAUSED", "persisted": false, "persistence_error": "Disk full"}'
    ))

    btn = page.locator("#btn-toggle-host-monitor")
    btn.click()

    # Toast warning must be displayed
    toast = page.locator(".toast, .toast-message, #toast-container")
    page.wait_for_selector(".toast, .toast-message, #toast-container", timeout=5000)
    assert toast.first.is_visible()
    assert "preference save failed" in toast.first.text_content().lower()

    page.unroute("**/api/v1/host/monitor/toggle*")


def test_scenario_9_clear_history_confirmation_text(auth_page):
    """Scenario 9: Clear History confirmation modal text differentiates PAUSED vs ACTIVE state."""
    page, base_url = auth_page

    page.goto(base_url)
    page.wait_for_selector("#btn-clear-alerts")
    btn_toggle = page.locator("#btn-toggle-host-monitor")

    # 1. Transition to PAUSED via genuine user click if active
    live_text = page.locator("#live-sensor-text")
    if "ACTIVE" in live_text.text_content():
        with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
            btn_toggle.click()
        page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)

    # Click Clear History while PAUSED and verify confirmation dialog message
    captured_dialogs = []
    def on_dialog_paused(dialog):
        captured_dialogs.append(dialog.message)
        dialog.dismiss()

    page.once("dialog", on_dialog_paused)
    page.locator("#btn-clear-alerts").click()

    assert len(captured_dialogs) == 1
    assert "Host monitoring is paused, so no automatic rescan will run" in captured_dialogs[0]

    # 2. Transition back to ACTIVE via genuine user click
    with page.expect_response(lambda r: "/api/v1/host/monitor/toggle" in r.url and r.status == 200):
        btn_toggle.click()
    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)

    # Click Clear History while ACTIVE and verify confirmation dialog message
    captured_active = []
    def on_dialog_active(dialog):
        captured_active.append(dialog.message)
        dialog.dismiss()

    page.once("dialog", on_dialog_active)
    page.locator("#btn-clear-alerts").click()

    assert len(captured_active) == 1
    assert "perform a new host audit" in captured_active[0]


def test_scenario_10_accessibility_and_button_locks(auth_page):
    """Scenario 10: Toggle button has ARIA attributes and is locked during in-flight transitions."""
    page, base_url = auth_page

    stream_manager.start_host_monitoring_sync(persist=False)
    page.goto(base_url)
    page.wait_for_selector("#live-sensor-pill.active", timeout=5000)
    page.wait_for_selector("#btn-toggle-host-monitor")

    btn = page.locator("#btn-toggle-host-monitor")

    # 1. Verify ARIA attributes on button
    assert btn.get_attribute("aria-label") is not None
    assert btn.get_attribute("aria-busy") == "false"

    # 2. Keyboard focus navigation
    btn.focus()
    active_id = page.evaluate("document.activeElement.id")
    assert active_id == "btn-toggle-host-monitor"

    # 3. Intercept toggle route and hold response to verify in-flight button lock and ARIA busy state
    held_toggle = []
    def hold_toggle(route):
        held_toggle.append(route)

    page.route("**/api/v1/host/monitor/toggle*", hold_toggle)

    # Trigger genuine keyboard activation (Enter key on focused button)
    btn.press("Enter")
    page.wait_for_timeout(300)
    assert len(held_toggle) > 0, "Expected toggle route to be intercepted"

    # Verify button is locked and ARIA busy while transition is in-flight
    assert btn.is_disabled()
    assert btn.get_attribute("aria-busy") == "true"
    btn_text = btn.text_content()
    assert "PAUSING" in btn_text or "RESUMING" in btn_text

    # Now fulfill the held route
    held_route = held_toggle.pop(0)
    held_route.fulfill(
        status=200,
        content_type="application/json",
        body='{"status": "success", "host_monitoring_active": false, "monitoring_state": "PAUSED", "persisted": true}'
    )

    # Verify button unlocks and returns aria-busy to false
    page.wait_for_selector("#live-sensor-pill.paused", timeout=5000)
    assert not btn.is_disabled()
    assert btn.get_attribute("aria-busy") == "false"

    page.unroute("**/api/v1/host/monitor/toggle*")
