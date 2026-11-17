from hades_report_docx import _build_recommendations, _parse_host_block


def test_info_nuclei_duplicado_no_cuenta_como_vulnerabilidad_cve():
    block = (
        "[NMAP]\nHost is up.\n80/tcp open http micro_httpd\n"
        "[NUCLEI]\n  [INFO] HTTP Missing Security Headers → http://192.0.2.10\n"
        "  [INFO] HTTP Missing Security Headers → http://192.0.2.10\n"
        "[ANÁLISIS IA HADES]\nComentario consultivo."
    )
    host = _parse_host_block("192.0.2.10", block)
    assert len(host["nuclei"]) == 1
    assert host["cves_confirmados"] == []
    assert host["risk"] == "BAJO"
    recommendations = _build_recommendations({"hosts": [host]})
    assert not any("CVE" in item["rec"] for item in recommendations)
