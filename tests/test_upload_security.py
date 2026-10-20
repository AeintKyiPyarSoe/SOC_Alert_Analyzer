import io
from app.config import settings

def test_upload_binary_executable_rejected(client):
    # Windows PE executable magic header: MZ
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + (b"\x00" * 100)
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("malware.log", io.BytesIO(pe_bytes), "text/plain")}
    )
    assert response.status_code == 415
    assert "Binary executable or archive file detected" in response.json()["detail"]

def test_upload_elf_binary_rejected(client):
    # Linux ELF magic header: \x7fELF
    elf_bytes = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 100)
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("backdoor.txt", io.BytesIO(elf_bytes), "text/plain")}
    )
    assert response.status_code == 415

def test_upload_null_bytes_rejected(client):
    corrupted_bytes = b"Some normal text\x00with null byte injection"
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("corrupt.log", io.BytesIO(corrupted_bytes), "text/plain")}
    )
    assert response.status_code == 415

def test_upload_oversized_payload_rejected(client, monkeypatch):
    # Temporarily set max upload to 1 KB for test verification
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_BYTES", 1024)
    oversized_data = b"A" * 2048  # 2 KB

    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("big_log.log", io.BytesIO(oversized_data), "text/plain")}
    )
    assert response.status_code == 413
    assert "exceeds maximum allowed upload size" in response.json()["detail"]

def test_upload_empty_file_rejected(client):
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("empty.log", io.BytesIO(b""), "text/plain")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()

def test_upload_path_traversal_filename_sanitized(client):
    # Path traversal attack filename: ../../../../../etc/passwd.json
    traversal_json = b'[{"timestamp": "2026-09-10T10:00:00Z", "description": "test", "event_type": "security_anomaly"}]'
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("../../../../../etc/passwd.json", io.BytesIO(traversal_json), "application/json")}
    )
    assert response.status_code == 201
    # File was processed safely under sanitized name passwd.json without directory escape
    assert "passwd.json" in response.json()["message"]

def test_upload_malformed_json_returns_422(client):
    malformed_json = b'{"timestamp": "2026-09-10T10:00:00Z", "unclosed_string": '
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("malformed.json", io.BytesIO(malformed_json), "application/json")},
        data={"source_type": "generic"}
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "Error parsing log file" in detail or "No valid security alerts" in detail

def test_upload_malformed_xml_returns_422(client):
    malformed_xml = b'<Events><Event><System><EventID>4625</EventID></System>'  # Missing closing tags
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("malformed.xml", io.BytesIO(malformed_xml), "application/xml")},
        data={"source_type": "windows"}
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "Error parsing log file" in detail or "No valid security alerts" in detail

def test_upload_exceeds_max_events_per_upload(client, monkeypatch):
    import json
    monkeypatch.setattr(settings, "MAX_EVENTS_PER_UPLOAD", 5)
    events = [
        {"timestamp": f"2026-09-10T10:0{i}:00Z", "description": f"Test alert {i}", "event_type": "security_anomaly"}
        for i in range(10)
    ]
    raw_json = json.dumps(events).encode("utf-8")
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("too_many_events.json", io.BytesIO(raw_json), "application/json")},
        data={"source_type": "generic"}
    )
    assert response.status_code == 413
    assert "exceeds the limit of 5 events" in response.json()["detail"]

def test_upload_batch_processing_large_event_set(client, monkeypatch):
    import json
    # Use small batch size to exercise batch chunking loop
    monkeypatch.setattr(settings, "DB_BATCH_SIZE", 50)
    events = [
        {"timestamp": f"2026-09-10T10:00:{i:02d}Z", "description": f"Batch alert {i}", "event_type": "security_anomaly"}
        for i in range(60)
    ]
    raw_json = json.dumps(events).encode("utf-8")
    response = client.post(
        "/api/v1/alerts/upload",
        files={"file": ("batch_events.json", io.BytesIO(raw_json), "application/json")},
        data={"source_type": "generic"}
    )
    assert response.status_code == 201
    assert response.json()["alerts_count"] == 60

