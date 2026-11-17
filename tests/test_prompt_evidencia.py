"""Regresiones del informe por host: la IA debe recibir cada fuente técnica."""

import io
import urllib.error
from unittest import mock

from hades_report_docx import _parse_host_block
from hades_win_master_advanced import HadesMCP


def test_prompt_conserva_nuclei_y_tls_tras_nmap_largo():
    mcp = HadesMCP()
    nmap = (
        "Nmap scan report for 192.0.2.10\n"
        "Host is up.\n"
        "443/tcp open https nginx 1.25\n"
        + ("| script output: dato adicional\n" * 140)
        + "|_ssl-enum-ciphers: TLSv1.0 enabled\n"
    )
    nuclei = "[NUCLEI] 1 hallazgo(s) en https://192.0.2.10:\n  [HIGH] Exposición [CVE-2025-12345] → https://192.0.2.10"
    tls = "subject=CN=ejemplo.local\nVerify return code: 10 (certificate has expired)"
    prompts = []

    def capture(prompt):
        prompts.append(prompt)
        return "Puerto 443; CVE-2025-12345; certificado expirado."

    with (
        mock.patch.object(mcp, "nmap_scan", return_value=nmap),
        mock.patch.object(mcp, "asset_profile", return_value=""),
        mock.patch.object(mcp, "nuclei_scan", return_value=nuclei),
        mock.patch.object(mcp, "ssl_audit", return_value=tls),
        mock.patch.object(mcp, "ai_analysis", side_effect=capture),
    ):
        report = mcp.full_audit("192.0.2.10", web_ports=["https://192.0.2.10"])

    assert "CVE-2025-12345" in prompts[0]
    assert "certificate has expired" in prompts[0]
    assert "TLSv1.0 enabled" in prompts[0]
    assert "TLSv1.0 enabled" in report
    assert "CVE-2025-12345" in report
    assert "CVE que no aparecen" not in report
    parsed = _parse_host_block("192.0.2.10", report)
    assert parsed["cves_confirmados"] == ["CVE-2025-12345"]
    assert "CVE-2025-12345" in parsed["texto_ia"]
    assert any("TLSv1.0" in line for line in parsed["tls"])
    assert any("certificate has expired" in line for line in parsed["tls"])
    assert "CONTROL DE COBERTURA" not in parsed["texto_ia"]
    assert "TLSv1.0" in parsed["control_ia"]


def test_control_cve_acepta_hallazgo_estructurado_nuclei():
    mcp = HadesMCP()
    facts = mcp.hechos_desde_nmap("80/tcp open http nginx 1.25")
    nuclei = ["[NUCLEI] 1 hallazgo(s):\n  [HIGH] Exposición [CVE-2025-12345] → http://192.0.2.10"]
    warnings = mcp.auditar_respuesta_ia(
        "Puerto 80. Nuclei detectó CVE-2025-12345.", facts, nuclei_results=nuclei
    )
    assert not any("CVE que no aparecen" in warning for warning in warnings)


def test_ia_reintenta_una_vez_si_runner_devuelve_500():
    mcp = HadesMCP()
    failure = urllib.error.HTTPError("http://127.0.0.1:11434/api/generate", 500, "runner stopped", {}, None)
    success = io.BytesIO(b'{"response":"analisis recuperado","eval_count":1}')
    with (
        mock.patch("hades_win_master_advanced.urllib.request.urlopen", side_effect=[failure, success]) as call,
        mock.patch.object(mcp, "_record_ollama_metrics"),
        mock.patch("hades_win_master_advanced.time.sleep"),
    ):
        result = mcp.ai_analysis("evidencia", retries=0)
    assert result == "analisis recuperado"
    assert call.call_count == 2
    assert not mcp.ai_unavailable


def test_control_avisa_si_ia_omite_tls_obsoleto_detectado_por_nmap():
    mcp = HadesMCP()
    nmap = "443/tcp open https nginx 1.25\n|_ssl-enum-ciphers: TLSv1.0 enabled"
    facts = mcp.hechos_desde_nmap(nmap)
    warnings = mcp.auditar_respuesta_ia(
        "Puerto 443; certificado expirado.", facts, nmap_output=nmap
    )
    assert any("TLSv1.0" in warning for warning in warnings)


def test_control_avisa_si_ia_atribuye_cve_a_producto_sin_evidencia():
    mcp = HadesMCP()
    facts = mcp.hechos_desde_nmap("443/tcp open https nginx 1.25")
    nuclei = ["[NUCLEI] 1 hallazgo(s):\n  [HIGH] Synthetic finding [CVE-2025-12345]"]
    warnings = mcp.auditar_respuesta_ia(
        "Puerto 443. Actualizar nginx para resolver CVE-2025-12345.",
        facts,
        nuclei_results=nuclei,
        nmap_output="443/tcp open https nginx 1.25",
    )
    assert any("nginx" in warning and "CVE-2025-12345" in warning for warning in warnings)
