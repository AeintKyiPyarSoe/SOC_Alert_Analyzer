import io
import json

def test_html_views(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Defensive Security Operations Center" in r.text
    assert "Host EDR" in r.text or "HOST SENSOR" in r.text

    r = client.get("/alerts")
    assert r.status_code == 200
    assert "Security Alert Explorer" in r.text

    r = client.get("/incidents")
    assert r.status_code == 200
    assert "Correlated Security Incidents" in r.text

    r = client.get("/upload")
    assert r.status_code == 200
    assert "Import Security Telemetry" in r.text

def test_upload_api_wazuh(client):
    wazuh_sample = [
        {
            "timestamp": "2026-09-10T10:00:00.000+0000",
            "rule": {
                "level": 10,
                "description": "sshd: Failed authentication attempt",
                "id": "5710",
                "groups": ["authentication_failed"]
            },
            "data": {
                "srcip": "192.168.1.50",
                "dstuser": "root"
            }
        }
    ]
    file_bytes = json.dumps(wazuh_sample).encode("utf-8")
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("wazuh.json", io.BytesIO(file_bytes), "application/json")},
        data={"source_type": "wazuh"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["alerts_count"] == 1

def test_upload_api_xml_windows(client):
    xml_sample = """<Events>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4625</EventID>
                <TimeCreated SystemTime="2026-09-10T10:00:00.000Z"/>
            </System>
            <EventData>
                <Data Name="TargetUserName">admin</Data>
                <Data Name="IpAddress">192.168.1.199</Data>
            </EventData>
        </Event>
    </Events>"""
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("security_event.xml", io.BytesIO(xml_sample.encode("utf-8")), "application/xml")},
        data={"source_type": "windows"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["alerts_count"] == 1

def test_upload_api_csv_generic(client):
    csv_sample = """timestamp,event_type,description,source_ip,severity
2026-09-10T10:00:00Z,malware_probe,Inbound port probe from external scanner,45.33.32.156,HIGH
"""
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("alerts.csv", io.BytesIO(csv_sample.encode("utf-8")), "text/csv")},
        data={"source_type": "generic"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["alerts_count"] == 1

def test_upload_invalid_extension(client):
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("malicious.exe", io.BytesIO(b"binary"), "application/octet-stream")}
    )
    assert response.status_code == 422

def test_dashboard_stats_api(client):
    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "total_alerts" in stats
    assert "critical_count" in stats
    assert "total_incidents" in stats

def test_alert_status_patch(client):
    # Ingest 1 alert first
    wazuh_sample = [{
        "timestamp": "2026-09-10T10:00:00.000+0000",
        "rule": {"level": 8, "description": "Alert test", "id": "100", "groups": ["test"]},
        "data": {"srcip": "10.0.0.1"}
    }]
    client.post(
        "/api/v1/alerts/upload",
        files={"file": ("test.json", io.BytesIO(json.dumps(wazuh_sample).encode()), "application/json")}
    )

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) > 0
    alert_id = alerts[0]["id"]

    # Patch status
    res = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"

def test_host_sensor_status_api(client):
    response = client.get("/api/v1/host/status")
    assert response.status_code == 200
    data = response.json()
    assert "os" in data
    assert "hostname" in data
    assert "process_count" in data
    assert data["process_count"] > 0

def test_host_sensor_drill_api(client):
    response = client.post("/api/v1/host/drill")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "[TEST DRILL]" in data["alert"]["description"]
