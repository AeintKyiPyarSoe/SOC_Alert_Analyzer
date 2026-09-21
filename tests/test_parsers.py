from app.parsers.wazuh import WazuhParser
from app.parsers.suricata import SuricataParser
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.windows_event import WindowsEventParser
from app.parsers.web_access import WebAccessParser
from app.parsers.firewall import FirewallParser
from app.parsers.generic_log import GenericLogParser
from app.parsers import detect_source_type, get_parser

def test_wazuh_parser_json():
    content = """
    {
      "timestamp": "2026-09-10T10:01:05.120+0000",
      "rule": {
        "level": 10,
        "description": "sshd: Multiple failed SSH login attempts",
        "id": "5710",
        "groups": ["syslog", "sshd", "authentication_failed"]
      },
      "data": {
        "srcip": "192.168.1.45",
        "dstuser": "root",
        "srcport": "54321"
      }
    }
    """
    parser = WazuhParser()
    events = parser.parse(content)
    assert len(events) == 1
    ev = events[0]
    assert ev["source_type"] == "Wazuh"
    assert ev["event_type"] == "ssh_authentication_failure"
    assert ev["source_ip"] == "192.168.1.45"
    assert ev["username"] == "root"
    assert ev["source_port"] == 54321
    assert ev["rule_level"] == 10

def test_suricata_parser_eve():
    line = '{"timestamp":"2026-09-10T10:10:00.123+0000","event_type":"alert","src_ip":"198.51.100.22","src_port":44123,"dest_ip":"192.168.1.10","dest_port":80,"alert":{"signature":"ET SCAN Nmap Scripting Engine","severity":2,"signature_id":2000001}}'
    parser = SuricataParser()
    events = parser.parse(line)
    assert len(events) == 1
    ev = events[0]
    assert ev["source_type"] == "Suricata"
    assert ev["event_type"] == "network_scan"
    assert ev["source_ip"] == "198.51.100.22"
    assert ev["source_port"] == 44123
    assert ev["destination_ip"] == "192.168.1.10"
    assert ev["destination_port"] == 80

def test_linux_auth_parser():
    logs = """
    Sep 10 10:14:01 server1 sshd[14101]: Failed password for invalid user admin from 192.168.1.45 port 49152 ssh2
    Sep 10 10:15:30 server1 sshd[14150]: Accepted password for ubuntu from 192.168.1.100 port 49160 ssh2
    Sep 10 10:16:02 server1 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
    """
    parser = LinuxAuthParser()
    events = parser.parse(logs)
    assert len(events) == 3
    
    # 1. Failed
    assert events[0]["event_type"] == "ssh_authentication_failure"
    assert events[0]["username"] == "admin"
    assert events[0]["source_ip"] == "192.168.1.45"
    assert events[0]["source_port"] == 49152

    # 2. Accepted
    assert events[1]["event_type"] == "ssh_login_successful"
    assert events[1]["username"] == "ubuntu"
    assert events[1]["source_ip"] == "192.168.1.100"

    # 3. Sudo
    assert events[2]["event_type"] == "sudo_command_execution"
    assert events[2]["username"] == "ubuntu"

def test_windows_event_parser_json():
    json_log = """
    [
        {
            "Id": 4625,
            "TimeCreated": "2026-09-10T11:20:00Z",
            "Message": "An account failed to log on.\\nAccount Name: Administrator\\nSource Network Address: 192.168.1.200\\nSource Port: 51200"
        },
        {
            "Id": 7045,
            "TimeCreated": "2026-09-10T11:22:00Z",
            "Message": "A service was installed in the system.\\nService Name: BackdoorSvc"
        }
    ]
    """
    parser = WindowsEventParser()
    events = parser.parse(json_log)
    assert len(events) == 2
    assert events[0]["event_type"] == "windows_failed_logon"
    assert events[0]["source_ip"] == "192.168.1.200"
    assert events[0]["username"] == "Administrator"
    assert events[1]["event_type"] == "windows_service_installed"

def test_windows_event_parser_xml():
    xml_log = """
    <Events>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4688</EventID>
                <TimeCreated SystemTime="2026-09-10T11:30:00.000Z"/>
            </System>
            <EventData>
                <Data Name="TargetUserName">analyst</Data>
                <Data Name="CommandLine">powershell.exe -enc SQBFAFgA</Data>
            </EventData>
        </Event>
    </Events>
    """
    parser = WindowsEventParser()
    events = parser.parse(xml_log)
    assert len(events) == 1
    assert events[0]["event_type"] == "windows_suspicious_process"
    assert events[0]["username"] == "analyst"

def test_web_access_parser_attacks():
    web_log = """
    192.168.1.50 - - [10/Sep/2026:12:00:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 4500 "-" "Mozilla/5.0"
    10.0.0.99 - - [10/Sep/2026:12:01:00 +0000] "GET /comment?msg=<script>alert('XSS')</script> HTTP/1.1" 200 1200 "-" "Mozilla/5.0"
    185.220.101.5 - - [10/Sep/2026:12:02:00 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 150 "-" "Mozilla/5.0"
    45.155.205.2 - - [10/Sep/2026:12:03:00 +0000] "POST /shell.php HTTP/1.1" 404 150 "-" "sqlmap/1.5.2#stable"
    """
    parser = WebAccessParser()
    events = parser.parse(web_log)
    assert len(events) == 4
    assert events[0]["event_type"] == "web_sql_injection"
    assert events[0]["source_ip"] == "192.168.1.50"
    assert events[1]["event_type"] == "web_xss_attempt"
    assert events[2]["event_type"] == "web_path_traversal"
    assert events[3]["event_type"] == "web_shell_probe"

def test_firewall_parser():
    win_fw = "2026-09-10 12:30:00 DROP TCP 192.168.1.88 192.168.1.10 54100 445 48 S 12345 0 65535 - - - RECEIVE"
    parser = FirewallParser()
    events = parser.parse(win_fw)
    assert len(events) == 1
    assert events[0]["event_type"] == "firewall_blocked_traffic"
    assert events[0]["source_ip"] == "192.168.1.88"
    assert events[0]["destination_port"] == 445

def test_generic_csv_parser():
    csv_content = """timestamp,event_type,description,source_ip,destination_ip,severity
2026-09-10T13:00:00Z,malware_alert,Trojan.Generic quarantined,192.168.1.15,10.0.0.1,HIGH
"""
    parser = GenericLogParser()
    events = parser.parse(csv_content)
    assert len(events) == 1
    assert events[0]["event_type"] == "malware_alert"
    assert events[0]["source_ip"] == "192.168.1.15"

def test_detect_source_type():
    assert detect_source_type('{"rule": {"id": 5710}}') == "wazuh"
    assert detect_source_type('{"event_type": "alert", "src_ip": "10.0.0.1"}') == "suricata"
    assert detect_source_type('Sep 10 10:14:01 server1 sshd[14101]: Failed password for root') == "linux_auth"
    assert detect_source_type('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">') == "windows"
    assert detect_source_type('192.168.1.1 - - [10/Sep/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 500') == "web"
    assert detect_source_type('2026-09-10 12:00:00 DROP TCP 1.2.3.4 5.6.7.8 80 80') == "firewall"
