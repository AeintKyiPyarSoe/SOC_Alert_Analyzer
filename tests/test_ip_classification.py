from app.security.ip_utils import IPClassifier

def test_ip_classifier_private_ips():
    # RFC 1918
    assert IPClassifier.classify_ip("10.0.0.1") == "PRIVATE"
    assert IPClassifier.is_private_ip("10.254.254.1")
    assert IPClassifier.is_internal_ip("10.0.0.1")
    assert not IPClassifier.is_public_ip("10.0.0.1")

    assert IPClassifier.classify_ip("172.16.5.20") == "PRIVATE"
    assert IPClassifier.classify_ip("172.31.255.255") == "PRIVATE"

    assert IPClassifier.classify_ip("192.168.1.100") == "PRIVATE"
    assert IPClassifier.is_private_ip("192.168.0.1")

    # CGNAT RFC 6598
    assert IPClassifier.classify_ip("100.64.0.1") == "PRIVATE"

def test_ip_classifier_loopback():
    assert IPClassifier.classify_ip("127.0.0.1") == "LOOPBACK"
    assert IPClassifier.classify_ip("::1") == "LOOPBACK"
    assert IPClassifier.is_internal_ip("127.0.0.1")
    assert not IPClassifier.is_public_ip("127.0.0.1")

def test_ip_classifier_link_local():
    assert IPClassifier.classify_ip("169.254.169.254") == "LINK_LOCAL"
    assert IPClassifier.classify_ip("fe80::1") == "LINK_LOCAL"
    assert IPClassifier.is_internal_ip("169.254.1.1")
    assert not IPClassifier.is_public_ip("169.254.1.1")

def test_ip_classifier_public_ips():
    # Public routable IPs
    assert IPClassifier.classify_ip("8.8.8.8") == "PUBLIC"
    assert IPClassifier.is_public_ip("8.8.8.8")
    assert not IPClassifier.is_internal_ip("8.8.8.8")

    assert IPClassifier.classify_ip("1.1.1.1") == "PUBLIC"
    assert IPClassifier.classify_ip("198.51.100.45") == "PUBLIC"
    assert IPClassifier.classify_ip("45.33.32.156") == "PUBLIC"
    assert IPClassifier.classify_ip("2607:f8b0:4005:805::200e") == "PUBLIC"

def test_ip_classifier_multicast_and_unspecified():
    assert IPClassifier.classify_ip("224.0.0.1") == "MULTICAST"
    assert IPClassifier.classify_ip("0.0.0.0") == "UNSPECIFIED"
    assert not IPClassifier.is_public_ip("0.0.0.0")

def test_ip_classifier_invalid_and_empty():
    assert IPClassifier.classify_ip("invalid-ip") == "INVALID"
    assert IPClassifier.classify_ip("") == "NONE"
    assert IPClassifier.classify_ip(None) == "NONE"
    assert not IPClassifier.is_public_ip("invalid-ip")
    assert IPClassifier.sanitize_ip("  192.168.1.1  ") == "192.168.1.1"
    assert IPClassifier.sanitize_ip("not-an-ip") is None
