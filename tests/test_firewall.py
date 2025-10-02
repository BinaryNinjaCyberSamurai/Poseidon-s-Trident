from src import firewall

def test_firewall_rule_parsing():
    rules = ["ALLOW tcp 80", "DENY udp 53"]
    fw = firewall.Firewall(rules)
    assert fw.is_allowed("tcp", 80) is True
    assert fw.is_allowed("udp", 53) is False