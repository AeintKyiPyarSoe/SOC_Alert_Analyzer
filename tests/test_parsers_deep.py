import json
import pytest
from datetime import datetime, timezone

from app.parsers.firewall import FirewallParser
from app.parsers.wazuh import WazuhParser
from app.parsers.web_access import WebAccessParser
from app.parsers.windows_event import WindowsEventParser
from app.parsers.suricata import SuricataParser

# ---------------------------------------------------------------------------
# Firewall Parser Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_firewall_parser_empty_and_comments():
    parser = FirewallParser()
    assert parser.parse("") == []
    assert parser.parse("   \n\n  ") == []
    assert parser.parse("# This is a comment\n# Another comment") == []

def test_firewall_parser_windows_drop_and_ignore_open():
    parser = FirewallParser()
    log_content = (
        "2026-10-20 14:00:00 DROP TCP 198.51.100.22 192.168.1.100 54321 445 0 - - - - - - - RECEIVE\n"
        "2026-10-20 14:00:01 OPEN TCP 192.168.1.100 198.51.100.22 54322 80 0 - - - - - - - SEND\n"
        "2026-10-20 14:00:02 CLOSE TCP 192.168.1.100 198.51.100.22 54322 80 0 - - - - - - - -"
    )
    events = parser.parse(log_content)
    assert len(events) == 1
    assert events[0]["event_type"] == "firewall_blocked_traffic"
    assert events[0]["source_ip"] == "198.51.100.22"
    assert events[0]["destination_port"] == 445

def test_firewall_parser_iptables_syslog_and_iso():
    parser = FirewallParser()
    log_content = (
        "Oct 20 14:05:00 soc-gateway kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 "
        "SRC=203.0.113.88 DST=192.168.1.50 PROTO=TCP SPT=44556 DPT=22\n"
        "2026-10-20T14:05:01+00:00 soc-gateway kernel: [IPTABLES DROP] IN=eth0 OUT= "
        "SRC=203.0.113.89 DST=192.168.1.50 PROTO=UDP SPT=53 DPT=161\n"
        "Oct 20 14:05:02 soc-gateway kernel: [UFW BLOCK] IN=eth0 OUT= "
        "SRC=203.0.113.90 DST=192.168.1.50 PROTO=ICMP"
    )
    events = parser.parse(log_content)
    assert len(events) == 3
    assert events[0]["source_port"] == 44556
    assert events[0]["destination_port"] == 22
    assert events[1]["source_ip"] == "203.0.113.89"
    assert events[1]["destination_port"] == 161
    assert events[2]["source_port"] is None
    assert events[2]["destination_port"] is None

def test_firewall_parser_timestamp_fallbacks():
    parser = FirewallParser()
    assert parser._parse_iso("invalid-time") is not None
    assert parser._parse_syslog_ts("completely malformed timestamp") is not None

# ---------------------------------------------------------------------------
# Wazuh Parser Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_wazuh_parser_empty_and_formats():
    parser = WazuhParser()
    assert parser.parse("") == []
    assert parser.parse("   ") == []

    # Single dict
    single_json = json.dumps({
        "timestamp": "2026-10-20T10:00:00.000+0000",
        "rule": {"id": "1002", "level": 7, "description": "Unknown rule alert", "groups": []},
        "data": {"srcip": "1.2.3.4", "dstip": "5.6.7.8"}
    })
    events = parser.parse(single_json)
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"

def test_wazuh_parser_ndjson_and_group_classifications():
    parser = WazuhParser()
    ndjson_content = "\n".join([
        json.dumps({"rule": {"id": "5710", "groups": ["authentication_failed"]}, "data": {"srcip": "10.0.0.1", "dstuser": "root"}}),
        json.dumps({"rule": {"id": "5715", "groups": ["sshd", "ssh"]}, "data": {"srcip": "10.0.0.2"}}),
        json.dumps({"rule": {"id": "7001", "groups": ["rootcheck"]}, "data": {}}),
        json.dumps({"rule": {"id": "550", "groups": ["syscheck"]}, "data": {}}),
        json.dumps({"rule": {"id": "31101", "groups": ["web", "scan_detection"]}, "data": {}}),
        json.dumps({"rule": {"id": "90001", "groups": ["command"], "description": "PowerShell execution"}, "data": {}}),
        "this is a malformed non-json line that should be skipped cleanly",
        json.dumps({"rule": {"id": "90002", "groups": ["other"], "description": "Execution of powershell.exe -enc"}, "data": {}})
    ])
    events = parser.parse(ndjson_content)
    assert len(events) == 7
    event_types = [e["event_type"] for e in events]
    assert "ssh_authentication_failure" in event_types
    assert "ssh_activity" in event_types
    assert "rootcheck_anomaly" in event_types
    assert "file_integrity_change" in event_types
    assert "network_scan" in event_types
    assert "suspicious_command" in event_types

# ---------------------------------------------------------------------------
# Web Access Parser Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_web_access_parser_empty_and_skip():
    parser = WebAccessParser()
    assert parser.parse("") == []
    assert parser.parse("   # comment\n") == []
    # Benign non-attack line should be skipped
    benign = '192.168.1.10 - - [20/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    assert parser.parse(benign) == []

def test_web_access_parser_attacks_and_scanners():
    parser = WebAccessParser()
    lines = [
        # Scanner User Agent
        '198.51.100.5 - - [20/Oct/2026:10:01:00 +0000] "GET /api/v1 HTTP/1.1" 200 500 "-" "sqlmap/1.5#stable"',
        # Directory Traversal
        '198.51.100.6 - - [20/Oct/2026:10:02:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 400 "-" "curl/7.68"',
        # Shell probe
        '198.51.100.7 - - [20/Oct/2026:10:03:00 +0000] "GET /shell.php?cmd=whoami HTTP/1.1" 404 150 "-" "curl/7.68"',
        # 403 Access Denied to sensitive resource (.env)
        '198.51.100.8 - - [20/Oct/2026:10:04:00 +0000] "GET /.env HTTP/1.1" 403 200 "-" "Mozilla/5.0"',
        # 401 Access Denied to .git/config
        '198.51.100.9 - - [20/Oct/2026:10:05:00 +0000] "GET /.git/config HTTP/1.1" 401 200 "-" "Mozilla/5.0"'
    ]
    events = parser.parse("\n".join(lines))
    assert len(events) == 5
    types = [e["event_type"] for e in events]
    assert "web_scanner_activity" in types
    assert "web_path_traversal" in types
    assert "web_shell_probe" in types
    assert "web_reconnaissance" in types

def test_web_access_parser_timestamps():
    parser = WebAccessParser()
    # Timestamp without offset
    t1 = parser._parse_timestamp("20/Oct/2026:10:00:00")
    assert t1 is not None
    # Completely invalid timestamp falls back to now
    t2 = parser._parse_timestamp("unparseable")
    assert t2 is not None

# ---------------------------------------------------------------------------
# Windows Event Parser Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_windows_event_parser_empty_and_json_edges():
    parser = WindowsEventParser()
    assert parser.parse("") == []
    # Non-dict json
    assert parser.parse("[1, 2, 3]") == []
    # JSON missing Id/EventID
    assert parser.parse(json.dumps([{"SomeField": "value"}])) == []
    # JSON invalid Id
    assert parser.parse(json.dumps([{"Id": "not-an-integer"}])) == []

def test_windows_event_parser_xml_multi_and_case_variants():
    parser = WindowsEventParser()
    xml_data = """
    <Events>
        <Event>
            <System>
                <EventID>4625</EventID>
                <TimeCreated SystemTime="2026-10-20T12:00:00.000Z"/>
            </System>
            <EventData>
                <Data Name="TargetUserName">compromised_user</Data>
                <Data Name="IpAddress">10.0.0.50</Data>
                <Data Name="IpPort">51234</Data>
            </EventData>
        </Event>
        <event>
            <system>
                <eventid>7045</eventid>
                <timecreated SystemTime="2026-10-20T12:05:00.000Z"/>
            </system>
            <eventdata>
                <Data Name="ServiceName">PwnService</Data>
            </eventdata>
        </event>
    </Events>
    """
    events = parser.parse(xml_data)
    assert len(events) == 2
    assert events[0]["event_id"] == 4625
    assert events[0]["username"] == "compromised_user"
    assert events[0]["source_ip"] == "10.0.0.50"
    assert events[0]["source_port"] == 51234
    assert events[1]["event_id"] == 7045

def test_windows_event_parser_text_dump():
    parser = WindowsEventParser()
    text_data = (
        "Event ID: 4625\n"
        "Date: 2026-10-20 12:30:00\n"
        "Account Name: Administrator\n"
        "Source Network Address: 198.51.100.99\n"
        "Source Port: 4444\n\n"
        "Event ID: 1102\n"
        "Date: 2026-10-20 12:35:00\n"
        "Account Name: SYSTEM\n"
    )
    events = parser.parse(text_data)
    assert len(events) == 2
    assert events[0]["event_id"] == 4625
    assert events[0]["username"] == "Administrator"
    assert events[0]["source_ip"] == "198.51.100.99"
    assert events[0]["source_port"] == 4444
    assert events[1]["event_id"] == 1102
    assert events[1]["username"] is None  # SYSTEM filtered to None

def test_windows_event_parser_timestamp_formats():
    parser = WindowsEventParser()
    assert parser._parse_timestamp(None) is not None
    assert parser._parse_timestamp("2026-10-20 12:00:00") is not None
    assert parser._parse_timestamp("10/20/2026 12:00:00 PM") is not None
    assert parser._parse_timestamp("2026/10/20 12:00:00") is not None
    assert parser._parse_timestamp("completely_invalid_timestamp") is not None

# ---------------------------------------------------------------------------
# Suricata Parser Deep Coverage Tests
# ---------------------------------------------------------------------------

def test_suricata_parser_empty_and_skip_non_alert():
    parser = SuricataParser()
    assert parser.parse("") == []

    # Non-alert event_type should be skipped
    dns_event = json.dumps({"event_type": "dns", "dns": {"query": [{"type": "A", "rrname": "example.com"}]}})
    assert parser.parse(dns_event) == []

def test_suricata_parser_signatures_and_json_array():
    parser = SuricataParser()
    records = [
        {"event_type": "alert", "alert": {"signature": "ET EXPLOIT Apache Struts RCE CVE-2017-5638", "severity": 1}, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"},
        {"event_type": "alert", "alert": {"signature": "ET ATTACK_RESPONSE PowerShell Empire Agent Activity", "severity": 1}, "src_ip": "1.1.1.2", "dest_ip": "2.2.2.2"},
        {"event_type": "alert", "alert": {"signature": "ET SCAN Nmap Scripting Engine Probe", "severity": 2}, "src_ip": "1.1.1.3", "dest_ip": "2.2.2.2"},
        {"event_type": "alert", "alert": {"signature": "ET DOS Possible Inbound SYN Flood", "severity": 1}, "src_ip": "1.1.1.4", "dest_ip": "2.2.2.2"},
        {"event_type": "alert", "alert": {"signature": "ET POLICY SSH Brute Force Login Attempt", "severity": 2}, "src_ip": "1.1.1.5", "dest_ip": "2.2.2.2"},
        {"event_type": "alert", "alert": {"signature": "ET INFO Generic Network Anomaly Traffic", "severity": 3}, "src_ip": "1.1.1.6", "dest_ip": "2.2.2.2"}
    ]
    # Test JSON array
    events = parser.parse(json.dumps(records))
    assert len(events) == 6
    types = [e["event_type"] for e in events]
    assert "exploit_attempt" in types
    assert "suspicious_command" in types
    assert "network_scan" in types
    assert "denial_of_service" in types
    assert "ssh_authentication_failure" in types
    assert "network_anomaly" in types
