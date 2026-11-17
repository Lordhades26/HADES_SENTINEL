"""Tests de aprobación (golden master) de las salidas deterministas de SENTINEL.

Fijan el comportamiento observable de punta a punta con datos sintéticos
(rangos de documentación 192.0.2.0/24 y 198.51.100.0/24, sin tocar la red):
parsers de herramientas, bloques que van al prompt de la IA, el control
anti-alucinación y la cadena del informe maestro → datos del DOCX.

Si un golden cambia, el test falla con el diff y deja un `.received.txt` en
tests/approved/. Ver tests/approval.py para aprobar un cambio intencional.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from approval import verify  # noqa: E402
import hades_win_master_advanced as motor  # noqa: E402
import hades_report_docx as informe  # noqa: E402

IP = "192.0.2.10"

NMAP_SALIDA = """\
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for 192.0.2.10
Host is up (0.0031s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE    SERVICE       VERSION
22/tcp   open     ssh           OpenSSH 7.4 (protocol 2.0)
80/tcp   open     http          Apache httpd 2.4.6 ((CentOS))
| http-vuln-cve2017-5638:
|   VULNERABLE: CVE-2017-5638 Apache Struts
443/tcp  open     ssl/http      Apache httpd 2.4.6
| ssl-enum-ciphers:
|   TLSv1.0:
|_  least strength: C
445/tcp  filtered microsoft-ds
3306/tcp open     mysql         MySQL 5.5.62
MAC Address: 00:11:22:33:44:55 (Hewlett Packard)
OS details: Linux 2.6.32 - 3.10
TRACEROUTE
HOP RTT     ADDRESS
1   3.10 ms 192.0.2.10

Nmap done: 1 IP address (1 host up) scanned in 22.10 seconds
"""

NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 Path Traversal",'
    '"severity":"critical","classification":{"cve-id":["CVE-2021-41773"]}},'
    '"matched-at":"http://192.0.2.10/cgi-bin/.%2e/etc/passwd"}\n'
    '{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers",'
    '"severity":"info"},"matched-at":"http://192.0.2.10"}\n'
)

PERFIL_SNMP = """\
PORT    STATE         SERVICE
137/udp open          netbios-ns
161/udp open          snmp
| snmp-sysdescr: HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153
|_  System uptime: 12 days
| snmp-info:
|   enterprise: Hewlett Packard
|_  sysName: IMPRESORA-PISO2
Host script results:
| nbstat: NetBIOS name: IMPRESORA-PISO2, NetBIOS user: <unknown>, NetBIOS MAC: 00:11:22:33:44:55 (Hewlett Packard)
"""


def _mcp():
    return motor.HadesMCP()


class TestAprobacionParserNuclei(unittest.TestCase):
    """_parse_nuclei: cada estado de la herramienta debe quedar distinguible."""

    CASOS = {
        "vacio": "",
        "hallazgos_jsonl": NUCLEI_JSONL,
        "solo_error": "[ERROR]: [WinError 2] El sistema no puede encontrar el archivo especificado",
        "timeout_sin_hallazgos": "\n[TIMEOUT] Comando excedió 300s; resultados PARCIALES: nuclei -u http://192.0.2.10",
        "timeout_con_hallazgos": NUCLEI_JSONL + "\n[TIMEOUT] Comando excedió 300s; resultados PARCIALES: nuclei",
        "solo_stderr": "\n[STDERR]: [FTL] Could not run nuclei: no templates provided for scan",
        "jsonl_malformado": '{"template-id":"x","info":{"name":"roto"\n',
        # Antes: la advertencia contaba como «1 hallazgo» por contener «low».
        "advertencia_texto": "[WRN] Found 2 templates with runtime error (low)\n",
        "json_ajeno": '{"x": 1}\n',
        "stderr_multilinea_fatal": "\n[STDERR]: [INF] Current nuclei version: v3.8.0\n[FTL] Could not create runner: no templates\n",
        "stderr_solo_avisos": "\n[STDERR]: [INF] Current nuclei version: v3.8.0\n[WRN] Found 1 template with syntax warning\n",
        "codigo_salida_no_cero": "\n[EXIT rc=1] nuclei terminó con error\n",
    }

    def test_estados_de_nuclei(self):
        mcp = _mcp()
        salida = {nombre: mcp._parse_nuclei(raw, "http://192.0.2.10")
                  for nombre, raw in self.CASOS.items()}
        verify(self, "nuclei_parse_estados", salida)


class TestAprobacionHechosYPrompt(unittest.TestCase):
    """Lo que la IA recibe como hechos verificados y el perfil del activo."""

    def test_hechos_desde_nmap_y_bloque(self):
        mcp = _mcp()
        hechos = mcp.hechos_desde_nmap(NMAP_SALIDA)
        verify(self, "nmap_hechos", hechos)
        verify(self, "nmap_bloque_hechos", mcp.bloque_hechos(hechos))

    def test_perfil_snmp_netbios(self):
        mcp = _mcp()
        perfil = mcp.hechos_desde_perfil(PERFIL_SNMP)
        verify(self, "perfil_hechos", perfil)
        verify(self, "perfil_bloque", mcp.bloque_perfil(perfil))

    def test_perfil_sin_respuesta_udp(self):
        mcp = _mcp()
        perfil = mcp.hechos_desde_perfil("161/udp open|filtered snmp\n137/udp open|filtered netbios-ns\n")
        verify(self, "perfil_sin_respuesta", {"hechos": perfil, "bloque": mcp.bloque_perfil(perfil)})


class TestAprobacionControlIA(unittest.TestCase):
    """auditar_respuesta_ia: avisos deterministas sobre la salida del modelo."""

    def test_avisos_sobre_respuesta_con_alucinaciones(self):
        mcp = _mcp()
        hechos = mcp.hechos_desde_nmap(NMAP_SALIDA)
        nuclei = [mcp._parse_nuclei(NUCLEI_JSONL, "http://192.0.2.10")]
        respuesta = (
            "El servidor expone SSH (22) y HTTP (80) con Apache, que está actualizado.\n"
            "OpenSSH es vulnerable a CVE-2099-0001.\n"
            "Apache presenta CVE-2021-41773 y CVE-2017-5638."
        )
        avisos = mcp.auditar_respuesta_ia(respuesta, hechos, nuclei_results=nuclei,
                                          nmap_output=NMAP_SALIDA)
        verify(self, "control_ia_avisos", avisos)

    def test_puerto_no_se_da_por_cubierto_por_subcadena(self):
        mcp = _mcp()
        hechos = {"puertos": [{"puerto": "80", "proto": "tcp", "estado": "open",
                               "servicio": "http", "version": ""}], "os": ""}
        casos = {
            "solo_8080_y_2018": "El proxy en 8080 se instaló en 2018.",
            "menciona_80": "HTTP en el puerto 80/tcp sin cifrar.",
        }
        verify(self, "control_ia_puerto_subcadena",
               {k: mcp.auditar_respuesta_ia(v, hechos) for k, v in casos.items()})

    def test_limpieza_de_andamiaje_del_modelo(self):
        casos = {
            "cerrado": "<think>razono</think>Respuesta final.",
            "huerfano": "Texto útil.\n<haedes_cortex>sin cerrar...",
            "limpio": "Sin andamiaje.",
        }
        verify(self, "ia_strip_scaffolding",
               {k: motor.strip_model_scaffolding(v) for k, v in casos.items()})


class TestAprobacionEvidenciaResumida(unittest.TestCase):

    def test_resumen_tls_y_extracto(self):
        import re
        tls_raw = (
            "CONNECTED(00000003)\n-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
            "subject=CN = intranet.example\nissuer=CN = intranet.example\n"
            "notBefore=Jan  1 00:00:00 2019 GMT\nnotAfter=Jan  1 00:00:00 2020 GMT\n"
            "New, TLSv1.0, Cipher is ECDHE-RSA-AES128-SHA\nVerify return code: 10 (certificate has expired)\n"
        )
        extracto = motor.HadesMCP._extracto_evidencia(
            NMAP_SALIDA, 300, re.compile(r"open|CVE-", re.I))
        verify(self, "evidencia_resumida", {
            "tls": motor.HadesMCP._resumen_tls(tls_raw),
            "extracto_nmap_300": extracto,
        })


class TestAprobacionInforme(unittest.TestCase):
    """INFORME_MAESTRO.md sintético → datos que alimentan el DOCX."""

    MAESTRO = f"""\
# INFORME MAESTRO HADES

| Campo | Valor |
|---|---|
| Red objetivo | `192.0.2.0/24` |
| Fecha | 2026-11-17 10:00 |
| Dispositivos activos | 2 |
| IPs | 192.0.2.10, 198.51.100.7 |

| Herramienta | Estado |
|---|---|
| Nmap | ✅ Disponible |
| Nuclei | ✅ Disponible |
| OpenSSL | ✅ Disponible |
| Tshark | ❌ No encontrado |
| Ollama | ❌ No encontrado |

## Fase 2 — Tráfico
```
TCP 70 %, UDP 30 %
```

========================================
OBJETIVO: {IP}
[NMAP]
{NMAP_SALIDA}
[NUCLEI]
{_mcp().__class__._parse_nuclei(None, NUCLEI_JSONL, "http://192.0.2.10")}
[SSL/TLS]
Objetivo: {IP}:443
Verify return code: 10 (certificate has expired)
[ANÁLISIS IA HADES]
Apache desactualizado; revisar TLSv1.0.
[CONTROL DE COBERTURA DEL ANÁLISIS IA]
- El análisis IA no menciona el/los puerto(s) 3306.
---
========================================
OBJETIVO: 198.51.100.7
[NMAP]
Nmap scan report for 198.51.100.7
Host is up (0.0100s latency).
All 1000 scanned ports on 198.51.100.7 are filtered
[NUCLEI]
[ERROR]: [WinError 2] El sistema no puede encontrar el archivo especificado
---
========================================
OBJETIVO: 198.51.100.8
[NMAP]

[TIMEOUT] Comando excedió 390s; resultados PARCIALES: nmap -sV 198.51.100.8
[SSL/TLS]
Objetivo: 198.51.100.8:443
connect:errno=10060
[EXIT rc=1] La herramienta terminó con error: openssl s_client
---
"""

    def test_docx_real_muestra_no_evaluado(self):
        """Genera el DOCX completo y comprueba que el fallo de herramienta se ve."""
        import tempfile
        try:
            import docx  # python-docx
        except ImportError:
            self.skipTest("python-docx no instalado")
        data = informe.parse_master_report(self.MAESTRO)
        with tempfile.TemporaryDirectory() as tmp:
            ruta = os.path.join(tmp, "informe.docx")
            informe.build_iso27001_docx(data, ruta)
            documento = docx.Document(ruta)
            texto = "\n".join(p.text for p in documento.paragraphs)
            for tabla in documento.tables:
                for fila in tabla.rows:
                    texto += "\n" + " | ".join(c.text for c in fila.cells)
        self.assertIn("No evaluada", texto)
        self.assertIn("Pruebas NO concluyentes", texto)
        self.assertIn("certificado y protocolo NO verificados", texto)
        self.assertNotIn("Bajo: sin servicios expuestos a la red.\n198.51.100.8", texto)

    def test_cadena_maestro_a_docx(self):
        data = informe.parse_master_report(self.MAESTRO)
        verify(self, "informe_datos", data)
        verify(self, "informe_iso", informe.map_iso_controls(data))
        verify(self, "informe_recomendaciones", informe._build_recommendations(data))


class TestAprobacionContratoExecute(unittest.TestCase):
    """execute(): éxito, fallo con código de salida y timeout quedan distinguibles."""

    def test_estados_de_ejecucion(self):
        py = f'"{sys.executable}"'
        casos = {
            "ok": (f'{py} -c "print(1)"', 20),
            "rc_no_cero_con_stderr": (
                f'{py} -c "import sys; sys.stderr.write(\'fallo\\n\'); sys.exit(3)"', 20),
            "timeout_con_parcial": (
                f'{py} -u -c "import sys,time; print(\'parcial\'); '
                f'sys.stderr.write(\'aviso\\n\'); sys.stderr.flush(); time.sleep(30)"', 2),
        }
        salida = {}
        for nombre, (cmd, tope) in casos.items():
            texto = motor.execute(cmd, timeout=tope).replace(sys.executable, "<python>")
            salida[nombre] = texto.replace("\r\n", "\n")
        verify(self, "execute_contrato", salida)


class TestAprobacionAuditoriaConFallos(unittest.TestCase):
    """full_audit con herramientas que fallan, usando dobles (sin red)."""

    def _auditar(self, nmap_out, ssl_out=None):
        import re
        mcp = _mcp()
        mcp.ai_skip = True
        mcp.nmap_scan = lambda ip, **kw: nmap_out
        mcp.asset_profile = lambda ip: ""
        mcp.nuclei_scan = lambda url, **kw: mcp._parse_nuclei("", url)
        mcp.ssl_audit = lambda h, p=443: ssl_out or ""
        salida = mcp.full_audit(IP)
        return re.sub(r"TIMESTAMP: .*", "TIMESTAMP: <fecha>", salida)

    def test_nmap_con_timeout_deja_constancia(self):
        verify(self, "full_audit_nmap_timeout",
               self._auditar("\n[TIMEOUT] Comando excedió 390s; resultados PARCIALES: nmap -sV 192.0.2.10"))

    def test_el_informe_clasifica_los_fallos(self):
        nmap_ok = ("Nmap scan report for 192.0.2.10\nHost is up (0.01s latency).\n"
                   "443/tcp open ssl/http nginx\n")
        bloques = {
            "nmap_timeout": self._auditar("\n[TIMEOUT] Comando excedió 390s; resultados PARCIALES: nmap"),
            "tls_errno": self._auditar(nmap_ok, ssl_out="connect:errno=10060\n[EXIT rc=1] openssl"),
        }
        salida = {}
        for nombre, txt in bloques.items():
            host = informe._parse_host_block(IP, txt.split("OBJETIVO:", 1)[1])
            salida[nombre] = {k: host[k] for k in ("status", "risk", "no_concluyente")}
            salida[nombre]["impacto"] = informe._business_impact(host)
        verify(self, "full_audit_a_informe", salida)

    def test_tls_sin_respuesta_conserva_el_error(self):
        nmap = ("Nmap scan report for 192.0.2.10\nHost is up (0.01s latency).\n"
                "443/tcp open ssl/http nginx\n")
        verify(self, "full_audit_tls_errno", self._auditar(
            nmap, ssl_out="connect:errno=10060\n[EXIT rc=1] La herramienta terminó con error: openssl"))


class TestAprobacionTrafico(unittest.TestCase):
    """parse_tshark_output: captura válida, fallo, corte e IPs no globales."""

    CAPTURA = (
        "192.0.2.10\t93.184.216.34\t443\t\tTLSv1.2\n"
        "192.0.2.10\t224.0.0.251\t\t5353\tMDNS\n"
        "169.254.10.2\t192.0.2.10\t\t137\tNBNS\n"
        "192.0.2.10\t255.255.255.255\t\t67\tDHCP\n"
        "10.0.0.5\t8.8.8.8\t\t53\tDNS\n"
    )
    CASOS = {
        "captura_valida": CAPTURA,
        "error_sin_datos": "\n[ERROR]: [WinError 2] El sistema no puede encontrar el archivo especificado",
        "interfaz_invalida": ("\n[STDERR]: Capturing on 'Wi-Fi'\ntshark: The capture session could not be "
                              "initiated on interface 'Wi-Fi'\n\n[EXIT rc=2] La herramienta terminó con error: tshark"),
        "timeout_con_datos": CAPTURA + "\n[TIMEOUT] Comando excedió 45s; resultados PARCIALES: tshark",
        "sin_trafico_ok": "\n[STDERR]: Capturing on 'Ethernet'\n0 packets captured\n",
    }

    def test_estados_de_captura(self):
        import hades_surveillance_advanced as vig
        verify(self, "tshark_estados",
               {k: vig.parse_tshark_output(v, ["192.0.2.10"]) for k, v in self.CASOS.items()})


class TestAprobacionDescubrimientoYHostFallido(unittest.TestCase):

    def test_descubrimiento_fallido_vs_sin_hosts(self):
        import hades_surveillance_advanced as vig
        casos = {
            "sin_hosts_completo": "Starting Nmap 7.95\nNmap done: 256 IP addresses (0 hosts up) scanned in 9.1 seconds\n",
            "timeout": "Starting Nmap 7.95\n\n[TIMEOUT] Comando excedió 600s; resultados PARCIALES: nmap -sn",
            "binario_ausente": "[NMAP] Binario no encontrado en C:\\Program Files (x86)\\Nmap\\nmap.exe",
            "rc_no_cero": "Starting Nmap 7.95\n\n[EXIT rc=1] La herramienta terminó con error: nmap",
            "vacio": "",
        }
        verify(self, "descubrimiento_fallido", {k: vig.descubrimiento_fallido(v) for k, v in casos.items()})

    def test_host_con_excepcion_no_desaparece_del_informe(self):
        import hades_surveillance_advanced as vig
        maestro = ("| Red objetivo | `192.0.2.0/24` |\n" +
                   vig.bloque_host_fallido(IP, RuntimeError("fallo sintético")) +
                   vig.bloque_host_fallido("192.0.2.11", RuntimeError("IA caída"),
                                           f"\n{'=' * 60}\nOBJETIVO: 192.0.2.11\n{'=' * 60}\n[NMAP]\n"
                                           "Nmap scan report for 192.0.2.11\nHost is up.\n22/tcp open ssh OpenSSH 9.6\n"))
        data = informe.parse_master_report(maestro)
        verify(self, "host_con_excepcion", [
            {k: h[k] for k in ("ip", "status", "risk", "no_concluyente", "ports")} for h in data["hosts"]])


class TestAprobacionSeguridadDashboard(unittest.TestCase):
    """El PTR de una IP remota es dato de un tercero: sólo hostnames válidos."""

    def test_ptr_saneado(self):
        import hades_server
        casos = ["router.example.", "intranet-01.local", '<img src=x onerror=alert(1)>',
                 'a"onmouseover="x', "con espacios.example", "", None]
        verify(self, "dashboard_ptr_saneado",
               {str(c): hades_server._sanitize_ptr(c) for c in casos})


class TestAprobacionDescubrimiento(unittest.TestCase):

    def test_escalado_por_tamano(self):
        salida = {t: motor._scaled_routed_discovery(t)
                  for t in ("198.51.100.0/24", "198.51.100.0/22", "10.99.0.0/16", "192.0.2.5")}
        verify(self, "descubrimiento_escalado", salida)


if __name__ == "__main__":
    unittest.main()
