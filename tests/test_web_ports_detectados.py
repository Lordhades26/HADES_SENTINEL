from hades_win_master_advanced import HadesMCP


def test_nuclei_recibe_servicios_http_en_puertos_no_estandar():
    nmap = (
        "80/tcp open http micro_httpd\n"
        "443/tcp open ssl/http micro_httpd\n"
        "8000/tcp open ssl/http micro_httpd\n"
        "5357/tcp open http Microsoft HTTPAPI\n"
        "16992/tcp open http Intel AMT\n"
        "2179/tcp open vmrdp?\n"
    )
    assert HadesMCP()._detect_web_ports(nmap, "192.0.2.10") == [
        "http://192.0.2.10",
        "https://192.0.2.10",
        "https://192.0.2.10:8000",
        "http://192.0.2.10:5357",
        "http://192.0.2.10:16992",
    ]
