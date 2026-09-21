import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from app.parsers.base import BaseParser

logger = logging.getLogger(__name__)

class LinuxAuthParser(BaseParser):
    """
    Parser for Linux authentication logs (/var/log/auth.log or /var/log/secure).
    Extracts SSH failed/accepted logins, invalid users, and sudo execution.
    """

    # Regex patterns for SSH authentication events
    SSH_FAILED_PATTERN = re.compile(
        r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )

    SSH_INVALID_USER_PATTERN = re.compile(
        r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Invalid\s+user\s+(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )

    SSH_ACCEPTED_PATTERN = re.compile(
        r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<auth_type>\S+)\s+for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )

    SUDO_CMD_PATTERN = re.compile(
        r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
        r"(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)"
    )

    def parse(self, content: str) -> List[Dict[str, Any]]:
        events = []
        if not content:
            return events

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            # Check SSH failed
            m = self.SSH_FAILED_PATTERN.search(line)
            if m:
                events.append({
                    "source_type": "Linux_Auth",
                    "timestamp": self._parse_timestamp(m.group("ts")),
                    "event_type": "ssh_authentication_failure",
                    "description": f"Failed SSH password for user '{m.group('user')}' from {m.group('ip')}",
                    "source_ip": m.group("ip"),
                    "destination_ip": None,
                    "source_port": int(m.group("port")),
                    "username": m.group("user"),
                    "raw_log": line
                })
                continue

            # Check SSH invalid user
            m = self.SSH_INVALID_USER_PATTERN.search(line)
            if m:
                events.append({
                    "source_type": "Linux_Auth",
                    "timestamp": self._parse_timestamp(m.group("ts")),
                    "event_type": "ssh_invalid_user",
                    "description": f"Failed SSH login attempt with invalid username '{m.group('user')}' from {m.group('ip')}",
                    "source_ip": m.group("ip"),
                    "destination_ip": None,
                    "source_port": int(m.group("port")),
                    "username": m.group("user"),
                    "raw_log": line
                })
                continue

            # Check SSH accepted
            m = self.SSH_ACCEPTED_PATTERN.search(line)
            if m:
                events.append({
                    "source_type": "Linux_Auth",
                    "timestamp": self._parse_timestamp(m.group("ts")),
                    "event_type": "ssh_login_successful",
                    "description": f"Accepted SSH login ({m.group('auth_type')}) for user '{m.group('user')}' from {m.group('ip')}",
                    "source_ip": m.group("ip"),
                    "destination_ip": None,
                    "source_port": int(m.group("port")),
                    "username": m.group("user"),
                    "raw_log": line
                })
                continue

            # Check sudo execution
            m = self.SUDO_CMD_PATTERN.search(line)
            if m:
                events.append({
                    "source_type": "Linux_Auth",
                    "timestamp": self._parse_timestamp(m.group("ts")),
                    "event_type": "sudo_command_execution",
                    "description": f"User '{m.group('user')}' executed privileged command: {m.group('cmd')}",
                    "source_ip": None,
                    "destination_ip": None,
                    "username": m.group("user"),
                    "raw_log": line
                })

        return events

    def _parse_timestamp(self, ts_str: str) -> str:
        """Standardize syslog or ISO timestamp to ISO 8601 string."""
        ts_str = ts_str.strip()
        # Try ISO 8601 first
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

        # Parse syslog format e.g. "Sep 10 10:14:22"
        current_year = datetime.now(timezone.utc).year
        for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                dt = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}")
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue

        return datetime.now(timezone.utc).isoformat()
