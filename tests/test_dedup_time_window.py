import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest

from app.security.host_sensor import HostSecuritySensor
from app.models.alert import Alert
from app.config import settings

def test_dedup_sliding_window_suppresses_within_window(db_session):
    sensor = HostSecuritySensor()
    # Signature seen just now
    sig = "powershell_encoded_command_1001_1600000000.0"
    sensor.seen_signatures[sig] = datetime.now(timezone.utc)

    # Should report as recently seen within 300 seconds
    assert sensor._is_signature_seen_recent(sig, max_age_seconds=300) is True

def test_dedup_sliding_window_allows_recurring_after_expiry():
    sensor = HostSecuritySensor()
    sig = "powershell_encoded_command_1001_1600000000.0"
    # Signature seen 400 seconds ago (outside 300s window)
    sensor.seen_signatures[sig] = datetime.now(timezone.utc) - timedelta(seconds=400)

    # Should NOT be seen recent, and should be refreshed
    assert sensor._is_signature_seen_recent(sig, max_age_seconds=300) is False
    # After query, it updates to current time
    assert sensor._is_signature_seen_recent(sig, max_age_seconds=300) is True

def test_dedup_pid_reuse_differentiated_by_create_time():
    sensor = HostSecuritySensor()
    pid = 4420
    t1 = 1700000000.0
    t2 = 1700005000.0

    sig_proc1 = f"procdump_lsass_{pid}_{t1}"
    sig_proc2 = f"procdump_lsass_{pid}_{t2}"

    # Record first process
    sensor.seen_signatures[sig_proc1] = datetime.now(timezone.utc)

    # Second process with SAME PID but different create_time must NOT be suppressed
    assert sensor._is_signature_seen_recent(sig_proc1, max_age_seconds=300) is True
    assert sensor._is_signature_seen_recent(sig_proc2, max_age_seconds=300) is False

def test_dedup_signature_cache_pruning():
    sensor = HostSecuritySensor()
    now = datetime.now(timezone.utc)

    # Populate 3200 signatures (above the 3000 cap), with half expired
    for i in range(1600):
        sensor.seen_signatures[f"old_sig_{i}"] = now - timedelta(seconds=500)
    for i in range(1600):
        sensor.seen_signatures[f"new_sig_{i}"] = now - timedelta(seconds=10)

    assert len(sensor.seen_signatures) == 3200

    # Checking any signature triggers automatic pruning
    sensor._is_signature_seen_recent("trigger_prune_sig", max_age_seconds=300)

    # All expired entries must be pruned, leaving significantly fewer than 3000
    assert len(sensor.seen_signatures) <= 1650
