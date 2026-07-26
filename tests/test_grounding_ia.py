# -*- coding: utf-8 -*-
"""
Grounding y control anti-alucinación del análisis IA.

Revisión del 25-07-2026 sobre HADES-DOLPHIN con evidencia de un escaneo real: el
modelo NO inventó datos (0 CVE y 0 IP falsos), pero omitió parte de la evidencia
(el puerto filtrado, un puerto alto, el sistema operativo y el fabricante) y
concluyó que un servicio SSH de 2019 "está actualizado", asignando severidad Baja.
El fallo no es de invención sino de cobertura y criterio.

El fixture de abajo es SINTÉTICO y reproduce la forma de la salida de Nmap. No se
usan los datos del equipo auditado: el reconocimiento real de red no se publica
(ver .gitignore).

La defensa es determinista, coherente con el principio del proyecto (la heurística
manda, la IA es consultiva):
  1. Los hechos se extraen del escaneo y se inyectan ya estructurados.
  2. La respuesta del modelo se audita contra esos hechos y las omisiones o
     invenciones se anotan en el propio informe.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hades_win_master_advanced as hwm

NMAP_REAL = """
Starting Nmap 7.80 ( https://nmap.org ) at 2026-01-01 00:00
Nmap scan report for 192.168.56.10
Host is up (0.0019s latency).
Not shown: 995 closed ports
PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       Dropbear sshd 2018.76 (protocol 2.0)
23/tcp   filtered telnet
80/tcp   open     http?
443/tcp  open     https?
8000/tcp open     http-alt?
MAC Address: 00:1A:2B:3C:4D:5E (Example Networks)
Running: Linux 2.6.X
OS details: Linux 2.6.32 - 2.6.35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""


class TestExtraccionDeHechos(unittest.TestCase):

    def setUp(self):
        self.mcp = hwm.HadesMCP()

    def test_extrae_todos_los_puertos_reales(self):
        hechos = self.mcp.hechos_desde_nmap(NMAP_REAL)
        puertos = {p["puerto"] for p in hechos["puertos"]}
        self.assertEqual(puertos, {"22", "23", "80", "443", "8000"},
                         "deben extraerse los cinco puertos observados")

    def test_conserva_estado_servicio_y_version(self):
        hechos = self.mcp.hechos_desde_nmap(NMAP_REAL)
        ssh = next(p for p in hechos["puertos"] if p["puerto"] == "22")
        self.assertEqual(ssh["estado"], "open")
        self.assertIn("Dropbear", ssh["version"])
        self.assertIn("2018.76", ssh["version"])
        telnet = next(p for p in hechos["puertos"] if p["puerto"] == "23")
        self.assertEqual(telnet["estado"], "filtered")

    def test_extrae_sistema_operativo_y_fabricante(self):
        hechos = self.mcp.hechos_desde_nmap(NMAP_REAL)
        self.assertIn("2.6", hechos["os"])
        self.assertIn("Example", hechos["vendor"])

    def test_bloque_de_hechos_es_legible_para_el_modelo(self):
        bloque = self.mcp.bloque_hechos(self.mcp.hechos_desde_nmap(NMAP_REAL))
        for esperado in ("22", "23", "8000", "Dropbear", "filtered", "2.6"):
            self.assertIn(esperado, bloque,
                          f"el bloque de hechos debe declarar '{esperado}'")


class TestAuditoriaDeLaRespuesta(unittest.TestCase):

    def setUp(self):
        self.mcp = hwm.HadesMCP()
        self.hechos = self.mcp.hechos_desde_nmap(NMAP_REAL)

    def test_detecta_puertos_abiertos_omitidos(self):
        # Respuesta real observada: solo cubrió 22, 80 y 443.
        respuesta = ("1) HALLAZGO: ssh Dropbear 2018.76 en el puerto 22, "
                     "http en 80 y https en 443.")
        avisos = self.mcp.auditar_respuesta_ia(respuesta, self.hechos)
        texto = " ".join(avisos)
        self.assertIn("8000", texto, "debe avisar que 8000/tcp no fue analizado")
        self.assertIn("23", texto, "debe avisar que 23/tcp no fue analizado")

    def test_detecta_cve_inventado(self):
        respuesta = "Se identifica CVE-2024-99999 en el servicio ssh."
        avisos = self.mcp.auditar_respuesta_ia(respuesta, self.hechos)
        self.assertTrue(any("CVE-2024-99999" in a for a in avisos),
                        "un CVE ausente de la evidencia debe señalarse")

    def test_no_avisa_cuando_la_cobertura_es_completa(self):
        respuesta = ("Puertos 22 (Dropbear 2018.76), 23 filtrado, 80, 443 y 8000. "
                     "Sistema Linux 2.6.32, fabricante Example.")
        avisos = self.mcp.auditar_respuesta_ia(respuesta, self.hechos)
        self.assertEqual(avisos, [],
                         f"sin omisiones no debe haber avisos; llegaron: {avisos}")

    def test_señala_contradiccion_de_version_antigua_declarada_actual(self):
        """El fallo concreto observado: llamar 'actualizado' a un SSH de 2018."""
        respuesta = ("Puertos 22, 23, 80, 443, 8000. Linux 2.6.32, Example. "
                     "El servicio ssh Dropbear 2018.76 está actualizado, severidad Baja.")
        avisos = self.mcp.auditar_respuesta_ia(respuesta, self.hechos)
        texto = " ".join(avisos).lower()
        self.assertIn("actualizad", texto,
                      "debe señalar la afirmación de vigencia sobre software antiguo")


if __name__ == "__main__":
    unittest.main(verbosity=2)
