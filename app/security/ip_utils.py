import ipaddress
from typing import Optional, Tuple, Union

class IPClassifier:
    """
    Robust IP address classifier distinguishing public, private, loopback,
    link-local, multicast, documentation, and special-purpose reserved addresses
    for both IPv4 and IPv6.
    
    Standards conformance:
      - RFC 1918: Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - RFC 4193: Unique Local IPv6 Unicast (fc00::/7)
      - RFC 6598: Carrier-Grade NAT (100.64.0.0/10)
      - RFC 5737: IPv4 Documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
      - RFC 3849: IPv6 Documentation (2001:db8::/32)
      - RFC 2544 / RFC 6815: Benchmarking (198.18.0.0/15)
      - RFC 6890: IETF Protocol Assignments (192.0.0.0/24)
      - RFC 7526: 6to4 Relay Anycast (192.88.99.0/24)
      - RFC 1112: Reserved for future use (240.0.0.0/4)
      - RFC 1122: "This host" network (0.0.0.0/8)
    """

    RFC1918_NETWORKS = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
    IPV6_ULA = ipaddress.ip_network("fc00::/7")

    DOCUMENTATION_NETWORKS = (
        ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
        ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
        ipaddress.ip_network("2001:db8::/32"),     # IPv6 Documentation
    )

    SPECIAL_PURPOSE_NETWORKS = (
        ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
        ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
        ipaddress.ip_network("192.88.99.0/24"),    # 6to4 Relay Anycast
        ipaddress.ip_network("0.0.0.0/8"),         # This network
        ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use
        ipaddress.ip_network("255.255.255.255/32") # Limited Broadcast
    )

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
        if ip_obj.is_unspecified:
            return "UNSPECIFIED"
        if ip_obj.is_loopback:
            return "LOOPBACK"
        if ip_obj.is_link_local:
            return "LINK_LOCAL"
        if ip_obj.is_multicast:
            return "MULTICAST"

        # Check documentation networks first
        if any(ip_obj in net for net in cls.DOCUMENTATION_NETWORKS):
            return "DOCUMENTATION"

        # Check special-purpose / benchmarking / reserved
        if any(ip_obj in net for net in cls.SPECIAL_PURPOSE_NETWORKS):
            return "SPECIAL_PURPOSE"

        if ip_obj.version == 4:
            if any(ip_obj in net for net in cls.RFC1918_NETWORKS):
                return "PRIVATE"
            if ip_obj in cls.CGNAT_NET:
                return "CGNAT"
            if ip_obj.is_reserved:
                return "RESERVED"
            if ip_obj.is_global:
                return "PUBLIC"
            return "RESERVED"
        else:
            if ip_obj in cls.IPV6_ULA:
                return "PRIVATE"
            if ip_obj.is_reserved:
                return "RESERVED"
            if ip_obj.is_global:
                return "PUBLIC"
            return "RESERVED"

    @classmethod
    def classify_ip(cls, ip_str: Optional[str]) -> str:
        _, category = cls.parse_ip(ip_str)
        return category

    @classmethod
    def is_public_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if the address is a genuine routable public internet IP."""
        _, category = cls.parse_ip(ip_str)
        return category == "PUBLIC"

    @classmethod
    def is_private_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if the address is within RFC 1918, RFC 4193, or RFC 6598 CGNAT."""
        _, category = cls.parse_ip(ip_str)
        return category in ("PRIVATE", "CGNAT")

    @classmethod
    def is_internal_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True for any non-public internal, loopback, private, or reserved address."""
        _, category = cls.parse_ip(ip_str)
        return category in ("PRIVATE", "CGNAT", "LOOPBACK", "LINK_LOCAL", "UNSPECIFIED", "DOCUMENTATION", "SPECIAL_PURPOSE", "RESERVED")

    @classmethod
    def is_documentation_ip(cls, ip_str: Optional[str]) -> bool:
        """Returns True if address is reserved for documentation/testing (RFC 5737 / RFC 3849)."""
        _, category = cls.parse_ip(ip_str)
        return category == "DOCUMENTATION"

    @classmethod
    def sanitize_ip(cls, ip_str: Optional[str]) -> Optional[str]:
        """Returns standardized IP string if valid, else None."""
        ip_obj, category = cls.parse_ip(ip_str)
        if ip_obj and category != "INVALID":
            return str(ip_obj)
        return None

