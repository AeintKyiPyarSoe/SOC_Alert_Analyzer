import ipaddress
from typing import Optional, Tuple, Union

class IPClassifier:
    """
    Robust IP address classifier distinguishing public, private, loopback,
    link-local, multicast, and reserved addresses for IPv4 and IPv6.
    
    Treats RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    RFC 6598 CGNAT (100.64.0.0/10), and IPv6 Unique Local (fc00::/7)
    as internal private network ranges.
    """

    RFC1918_NETWORKS = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
    IPV6_ULA = ipaddress.ip_network("fc00::/7")

    @classmethod
    def parse_ip(cls, ip_str: Optional[str]) -> Tuple[Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]], str]:
        if not ip_str or not isinstance(ip_str, str):
            return None, "NONE"
        cleaned = ip_str.strip()
        if not cleaned:
            return None, "NONE"
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            category = cls._categorize(ip_obj)
            return ip_obj, category
        except ValueError:
            return None, "INVALID"

    @classmethod
    def _categorize(cls, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
        if ip_obj.is_loopback:
            return "LOOPBACK"
        if ip_obj.is_multicast:
            return "MULTICAST"
        if ip_obj.is_link_local:
            return "LINK_LOCAL"
        if ip_obj.is_unspecified:
            return "UNSPECIFIED"
        
        # Check RFC 1918 & CGNAT
        if ip_obj.version == 4:
            if any(ip_obj in net for net in cls.RFC1918_NETWORKS):
                return "PRIVATE"
            if ip_obj in cls.CGNAT_NET:
                return "PRIVATE"
            if ip_obj.is_reserved:
                return "RESERVED"
            return "PUBLIC"
        else:
            if ip_obj in cls.IPV6_ULA:
                return "PRIVATE"
            if ip_obj.is_reserved:
                return "RESERVED"
            return "PUBLIC"

    @classmethod
    def classify_ip(cls, ip_str: Optional[str]) -> str:
        _, category = cls.parse_ip(ip_str)
        return category

    @classmethod
    def is_public_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if the address is a public internet IP (not private, loopback, or link-local)."""
        _, category = cls.parse_ip(ip_str)
        return category == "PUBLIC"

    @classmethod
    def is_private_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if the address is within RFC 1918 or RFC 6598 private ranges."""
        _, category = cls.parse_ip(ip_str)
        return category == "PRIVATE"

    @classmethod
    def is_internal_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if the address is an internal/non-public address (private, loopback, link-local, unspecified)."""
        _, category = cls.parse_ip(ip_str)
        return category in ("PRIVATE", "LOOPBACK", "LINK_LOCAL", "UNSPECIFIED")

    @classmethod
    def sanitize_ip(cls, ip_str: Optional[str]) -> Optional[str]:
        """Returns standardized IP string if valid, else None."""
        ip_obj, category = cls.parse_ip(ip_str)
        if ip_obj and category != "INVALID":
            return str(ip_obj)
        return None
