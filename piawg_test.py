from piawg import build_wg_config

def test_build_wg_config():
    conf_entries = {}
    conf_entries["Interface"] = {
        "Address": "172.0.0.1",
        "PrivateKey": "somekey",
        "PostUp": ["echo up", "true"]
    }
    conf_entries["Peer"] = {
        "PersistentKeepalive": "25",
        "PublicKey": "otherkey",
        "AllowedIPs": "0.0.0.0/0",
        "Endpoint": "10.0.0.1:9090"
    }
    out = (build_wg_config(conf_entries))
    expected = """[Interface]
Address = 172.0.0.1
PrivateKey = somekey
PostUp = echo up
PostUp = true
[Peer]
PersistentKeepalive = 25
PublicKey = otherkey
AllowedIPs = 0.0.0.0/0
Endpoint = 10.0.0.1:9090
"""
    assert out == expected
