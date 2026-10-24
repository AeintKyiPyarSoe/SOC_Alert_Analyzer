"""
Unit and regression tests for Docker security configuration and credential persistence.
Verifies container loopback port publishing, non-root user setup, volume persistence,
and stable instance-unique credential generation.
"""

from pathlib import Path
from app.config import _load_or_generate_local_credentials


def test_docker_compose_loopback_binding():
    """Verify docker-compose.yml publishes web port strictly to 127.0.0.1 by default."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"

    content = compose_path.read_text(encoding="utf-8")
    assert "127.0.0.1:8000:8000" in content, "Web service must bind to 127.0.0.1:8000:8000 to prevent LAN exposure"
    # Ensure raw "8000:8000" is not present as active port mapping
    lines = [line.strip() for line in content.splitlines()]
    assert '- "8000:8000"' not in lines, 'Bare "8000:8000" mapping must not be present'


def test_docker_compose_database_isolated():
    """Verify postgres database service is not exposed to host network by default."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    # In active lines under db:, "5432:5432" must not be active
    lines = [line.strip() for line in content.splitlines() if not line.strip().startswith("#")]
    assert '- "5432:5432"' not in lines
    assert '- "0.0.0.0:5432:5432"' not in lines


def test_docker_compose_persistent_volume_and_datadir():
    """Verify docker-compose.yml mounts soc_data volume to /app/data and sets DATA_DIR."""
    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    content = compose_path.read_text(encoding="utf-8")

    assert "soc_data:/app/data" in content, "soc_data volume must be mounted to /app/data"
    assert "DATA_DIR: ${DATA_DIR:-/app/data}" in content or "DATA_DIR:" in content


def test_dockerfile_non_root_user_and_permissions():
    """Verify Dockerfile establishes dedicated non-root user and creates /app/data."""
    dockerfile_path = Path(__file__).resolve().parent.parent / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist"

    content = dockerfile_path.read_text(encoding="utf-8")
    assert "USER socuser" in content, "Container must switch to unprivileged non-root user socuser"
    assert "mkdir -p /app/uploads /app/data" in content or "/app/data" in content


def test_local_dev_credentials_persist_across_restarts(tmp_path):
    """Verify credentials generated on first run persist and are reused on subsequent container starts."""
    # First container startup
    creds_first_run = _load_or_generate_local_credentials(tmp_path)
    assert creds_first_run.get("is_first_run") is True
    admin_key_1 = creds_first_run["admin_key"]
    secret_key_1 = creds_first_run["secret_key"]

    # Verify .auth_credentials file was created
    creds_file = tmp_path / ".auth_credentials"
    assert creds_file.exists()

    # Second container startup (simulating container restart with same volume)
    creds_second_run = _load_or_generate_local_credentials(tmp_path)
    assert creds_second_run["admin_key"] == admin_key_1
    assert creds_second_run["secret_key"] == secret_key_1


def test_local_dev_credentials_unique_per_instance(tmp_path):
    """Verify two separate installations receive distinct, non-shared cryptographic keys."""
    dir_a = tmp_path / "instance_a"
    dir_b = tmp_path / "instance_b"

    creds_a = _load_or_generate_local_credentials(dir_a)
    creds_b = _load_or_generate_local_credentials(dir_b)

    assert creds_a["admin_key"] != creds_b["admin_key"]
    assert creds_a["secret_key"] != creds_b["secret_key"]
    assert creds_a["analyst_key"] != creds_b["analyst_key"]
