from hades_surveillance_advanced import parse_discovered_hosts


def test_discovery_incluye_host_con_nombre_dns_inverso():
    output = (
        "Nmap scan report for 192.168.1.1\nHost is up.\n"
        "Nmap scan report for host.docker.internal (192.168.1.89)\nHost is up.\n"
    )
    assert parse_discovered_hosts(output) == ["192.168.1.1", "192.168.1.89"]
