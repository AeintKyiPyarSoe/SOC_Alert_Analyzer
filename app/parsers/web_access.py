import re
import urllib.parse
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class WebAccessParser(BaseParser):
    """
    Parser for Web Server Access Logs (Apache, Nginx, IIS).
    Supports NCSA Common Log Format (CLF) and Combined Log Format:
      IP - - [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/1.1" STATUS BYTES "REFERER" "USER_AGENT"
    
    Detects real-world web application attack patterns:
      - SQL Injection (UNION SELECT, OR 1=1, benchmark, sleep)
      - Cross-Site Scripting (XSS) (<script>, javascript:, onerror=)
      - Directory Traversal / LFI (../../, /etc/passwd, win.ini, ..%2f)
      - Web Shell probing (cmd.php, c99.php, eval-stdin, /actuator)
      - Automated Security Scanners (sqlmap, nikto, dirbuster, masscan)
    """

    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # Attack Detection Signatures
    SQLI_PATTERN = re.compile(
        r"(?:union\s+(?:all\s+)?select|select\s+.*from|or\s+['\"0-9]+=['\"0-9]+|'\s*or\s+'|waitfor\s+delay|information_schema|benchmark\s*\(|sleep\s*\(|--|/\*|char\(|concat\()",
        re.IGNORECASE
    )

    XSS_PATTERN = re.compile(
        r"(?:<script|script>|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|<img\s+src=|<svg\s+onload=)",
        re.IGNORECASE
    )

    TRAVERSAL_PATTERN = re.compile(
        r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c|/etc/passwd|/etc/shadow|/windows/win\.ini|/boot\.ini|/proc/self/)",
        re.IGNORECASE
    )

    SHELL_PATTERN = re.compile(
        r"(?:shell\.php|c99\.php|r57\.php|cmd\.(?:php|jsp|asp)|eval-stdin\.php|\.env|actuator/gateway|boaform|solr/admin)",
        re.IGNORECASE
    )

    SCANNER_AGENTS = [
        "sqlmap", "nikto", "acunetix", "nessus", "nmap", "dirbuster", "gobuster",
        "wpscan", "masscan", "zgrab", "nuclei", "metasploit", "hydra"
    ]

    def parse(self, content: str) -> List[Dict[str, Any]]:
        events = []
        if not content:
            return events

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m = self.LOG_PATTERN.search(line)
            if not m:
                # Check if JSON line (e.g. JSON-formatted Nginx/Caddy logs)
                continue

            ip = m.group("ip")
            ts_str = m.group("ts")
            method = m.group("method")
            raw_uri = m.group("uri")
            status_code = int(m.group("status"))
            user_agent = m.group("user_agent") or ""
            username = m.group("user")
            if username == "-":
                username = None

            # URL decode the URI
            try:
                decoded_uri = urllib.parse.unquote(raw_uri)
            except Exception:
                decoded_uri = raw_uri

            full_req = f"{method} {decoded_uri}"
            timestamp = self._parse_timestamp(ts_str)

            # Analyze for attacks
            attack_detected = None
            description = None

            if self.SQLI_PATTERN.search(decoded_uri):
                attack_detected = "web_sql_injection"
                description = f"SQL Injection probe detected in HTTP {method} request: '{decoded_uri[:80]}'"
            elif self.XSS_PATTERN.search(decoded_uri):
                attack_detected = "web_xss_attempt"
                description = f"Cross-Site Scripting (XSS) payload in HTTP {method} request: '{decoded_uri[:80]}'"
            elif self.TRAVERSAL_PATTERN.search(decoded_uri):
                attack_detected = "web_path_traversal"
                description = f"Directory Traversal / LFI probe detected in path: '{decoded_uri[:80]}'"
            elif self.SHELL_PATTERN.search(decoded_uri):
                attack_detected = "web_shell_probe"
                description = f"Web Shell / Vulnerable Endpoint probe for: '{decoded_uri[:80]}'"
            elif any(scanner in user_agent.lower() for scanner in self.SCANNER_AGENTS):
                scanner_name = next(s for s in self.SCANNER_AGENTS if s in user_agent.lower())
                attack_detected = "web_scanner_activity"
                description = f"Automated vulnerability scanner '{scanner_name}' detected targeting '{decoded_uri[:60]}'"
            elif status_code in (401, 403):
                # Unauthorized probe
                if any(kw in decoded_uri.lower() for kw in [".git", "admin", "backup", "config", "phpmyadmin", ".env"]):
                    attack_detected = "web_reconnaissance"
                    description = f"HTTP {status_code} Access Denied to sensitive resource: '{decoded_uri[:70]}'"

            # If an attack or high-interest event was detected, create an alert
            if attack_detected:
                events.append({
                    "source_type": "Web_Access",
                    "timestamp": timestamp,
                    "event_type": attack_detected,
                    "description": description,
                    "source_ip": ip,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": 80 if status_code != 443 else 443,
                    "username": username,
                    "raw_log": line
                })

        return events

    def _parse_timestamp(self, ts_str: str) -> str:
        """Parses web server timestamp like '10/Oct/2026:13:55:36 +0000'."""
        try:
            # e.g. 10/Oct/2026:13:55:36 +0000
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

        try:
            clean_ts = ts_str.split(" ")[0]
            dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            pass

        return datetime.now(timezone.utc).isoformat()
