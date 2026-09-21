from app.security.mitre_mapper import MitreMapper

def test_mitre_mappings():
    assert MitreMapper.map_event("ssh_authentication_failure") == "T1110"
    assert MitreMapper.map_event("network_scan") == "T1046"
    assert MitreMapper.map_event("suspicious_command", "powershell -enc ...") == "T1059.001"
    assert MitreMapper.map_event("ssh_login_successful") == "T1021.004"
    assert MitreMapper.map_event("sudo_command_execution") == "T1548"
    assert MitreMapper.map_event("file_integrity_change") == "T1565"

def test_mitre_details_and_urls():
    details = MitreMapper.get_details("T1110")
    assert details is not None
    assert details["name"] == "Brute Force"
    assert details["tactic"] == "Credential Access"
    assert "https://attack.mitre.org/techniques/T1110/" in MitreMapper.get_url("T1110")
