"""
Unit and integration tests for network exposure analysis:
Distinguishing listening sockets from confirmed network reachability.
"""

from unittest.mock import patch, MagicMock
from collections import namedtuple
import socket
from app.security.host_sensor import HostSecuritySensor

snicaddr = namedtuple('snicaddr', ['family', 'address', 'netmask', 'broadcast', 'ptp'])
snicstats = namedtuple('snicstats', ['isup', 'duplex', 'speed', 'mtu', 'flags'])


def test_assess_socket_reachability_loopback():
    """Sockets bound strictly to loopback (127.0.0.1, ::1) must be classified as LOOPBACK_ONLY."""
    sensor = HostSecuritySensor()
    res = sensor.assess_socket_reachability("127.0.0.1", 8080)

    assert res["binding_type"] == "LOOPBACK"
    assert res["reachability"] == "LOOPBACK_ONLY"
    assert res["exposure_tier"] == "LOW"
    assert res["has_public_reachability"] is False
    assert "loopback" in res["summary"].lower()


def test_assess_socket_reachability_wildcard_lan():
    """Wildcard socket on host with only private LAN interfaces must be classified as LAN_ACCESSIBLE."""
    sensor = HostSecuritySensor()

    mock_addrs = {
        "eth0": [snicaddr(family=socket.AF_INET, address="192.168.1.100", netmask="255.255.255.0", broadcast=None, ptp=None)],
        "lo": [snicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0", broadcast=None, ptp=None)]
    }
    mock_stats = {
        "eth0": snicstats(isup=True, duplex=1, speed=1000, mtu=1500, flags=""),
        "lo": snicstats(isup=True, duplex=1, speed=0, mtu=65536, flags="")
    }

    with patch("psutil.net_if_addrs", return_value=mock_addrs), \
         patch("psutil.net_if_stats", return_value=mock_stats), \
         patch.object(sensor, "is_firewall_enabled", return_value=True):
        res = sensor.assess_socket_reachability("0.0.0.0", 4444)

        assert res["binding_type"] == "WILDCARD"
        assert res["reachability"] == "LAN_ACCESSIBLE"
        assert res["firewall_mitigation"] == "FILTERED"
        assert res["has_public_reachability"] is False
        assert "192.168.1.100" in res["active_interfaces"]


def test_assess_socket_reachability_wildcard_public_reachability():
    """Wildcard socket on host with public routable interface must be classified as INTERNET_EXPOSED."""
    sensor = HostSecuritySensor()

    mock_addrs = {
        "wan0": [snicaddr(family=socket.AF_INET, address="93.184.216.34", netmask="255.255.255.0", broadcast=None, ptp=None)],
        "lo": [snicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0", broadcast=None, ptp=None)]
    }
    mock_stats = {
        "wan0": snicstats(isup=True, duplex=1, speed=1000, mtu=1500, flags=""),
        "lo": snicstats(isup=True, duplex=1, speed=0, mtu=65536, flags="")
    }

    with patch("psutil.net_if_addrs", return_value=mock_addrs), \
         patch("psutil.net_if_stats", return_value=mock_stats), \
         patch.object(sensor, "is_firewall_enabled", return_value=False):
        res = sensor.assess_socket_reachability("0.0.0.0", 23)

        assert res["binding_type"] == "WILDCARD"
        assert res["reachability"] == "INTERNET_EXPOSED"
        assert res["exposure_tier"] == "CRITICAL"
        assert res["firewall_mitigation"] == "UNFILTERED_EXPOSED"
        assert res["has_public_reachability"] is True


def test_assess_socket_reachability_specific_public_ip():
    """Socket bound directly to an external public IP must be confirmed as INTERNET_EXPOSED."""
    sensor = HostSecuritySensor()

    with patch.object(sensor, "is_firewall_enabled", return_value=True):
        res = sensor.assess_socket_reachability("8.8.8.8", 3389)

        assert res["binding_type"] == "SPECIFIC_INTERFACE"
        assert res["reachability"] == "INTERNET_EXPOSED"
        assert res["firewall_mitigation"] == "FILTERED"
        assert res["exposure_tier"] == "HIGH"
        assert res["has_public_reachability"] is True


def test_audit_network_sockets_enriches_reachability_metadata():
    """Audit network sockets must populate reachability and firewall mitigation fields in event dictionaries."""
    sensor = HostSecuritySensor()

    MockAddr = namedtuple('MockAddr', ['ip', 'port'])
    MockConn = namedtuple('MockConn', ['status', 'laddr', 'raddr', 'pid'])

    fake_conn = MockConn(status="LISTEN", laddr=MockAddr(ip="0.0.0.0", port=4444), raddr=None, pid=1234)

    with patch("psutil.net_connections", return_value=[fake_conn]), \
         patch("psutil.Process") as mock_proc, \
         patch.object(sensor, "assess_socket_reachability") as mock_assess:

        mock_proc.return_value.name.return_value = "handler.exe"
        mock_assess.return_value = {
            "binding": "0.0.0.0",
            "port": 4444,
            "binding_type": "WILDCARD",
            "reachability": "LAN_ACCESSIBLE",
            "exposure_tier": "HIGH",
            "firewall_mitigation": "FILTERED",
            "active_interfaces": ["192.168.1.50"],
            "has_public_reachability": False,
            "summary": "Mock summary assessment"
        }

        events = sensor.audit_network_sockets()
        assert len(events) == 1
        ev = events[0]

        assert ev["event_type"] == "insecure_listening_port"
        assert ev["reachability"] == "LAN_ACCESSIBLE"
        assert ev["exposure_tier"] == "HIGH"
        assert ev["firewall_mitigation"] == "FILTERED"
        assert "LAN_ACCESSIBLE" in ev["description"]
        assert "FW: FILTERED" in ev["description"]
