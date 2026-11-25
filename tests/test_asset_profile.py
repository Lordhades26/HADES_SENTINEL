#!/usr/bin/env python3
"""Perfilado de activos por SNMP + NetBIOS (paridad con LookLAN Network Monitor).

El reversing de LookLAN mostró que su valor no está en el
ping sweep sino en enriquecer cada host vivo: SNMP (sysDescr/sysName) para
identificar electrónica de red gestionable, y NetBIOS para nombre de equipo y
grupo de trabajo. Estos casos fijan el contrato de los parsers y del comando,
con mocks y sin tocar la red.
"""
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hades_win_master_advanced as win

SALIDA_SWITCH = """Nmap scan report for 10.77.128.1
PORT    STATE SERVICE
137/udp open  netbios-ns
161/udp open  snmp
| snmp-info:
|   enterprise: cisco
|   sysName: SW-CORE-01
|_  sysDescr: Cisco IOS Software, C2960 Version 15.0(2)SE11
| nbstat: NetBIOS name: SW-CORE-01, NetBIOS user: <unknown>, NetBIOS MAC: 00:1a:2b:3c:4d:5e (Cisco Systems)
"""

# Nmap pega a veces el nombre del script a la clave: "|_snmp-sysdescr: ..."
SALIDA_IMPRESORA = """Nmap scan report for 10.77.128.80
PORT    STATE SERVICE
161/udp open  snmp
|_snmp-sysdescr: HP LaserJet MFP M428fdw, Firmware 20230815
"""

SALIDA_WINDOWS = """Nmap scan report for 10.77.128.13
PORT    STATE SERVICE
137/udp open  netbios-ns
| nbstat: NetBIOS name: PC-CONTA-07, NetBIOS user: LABORAL, NetBIOS MAC: a0:29:19:7b:a2:7f (Intel Corporate)
"""

SALIDA_SNMP_DESNUDO = "161/udp open  snmp\n"
SALIDA_SIN_NADA = "161/udp closed snmp\n"


class TestParsersDePerfil(unittest.TestCase):
    def setUp(self):
        self.mcp = win.HadesMCP()

    def test_switch_gestionable(self):
        p = self.mcp.hechos_desde_perfil(SALIDA_SWITCH)
        self.assertEqual(p["snmp_sysname"], "SW-CORE-01")
        self.assertIn("Cisco IOS", p["snmp_sysdescr"])
        self.assertEqual(p["netbios_nombre"], "SW-CORE-01")
        self.assertEqual(p["netbios_mac"], "00:1a:2b:3c:4d:5e")
        self.assertEqual(p["netbios_vendor"], "Cisco Systems")
        self.assertTrue(p["snmp_activo"])

    def test_impresora_con_prefijo_de_script_pegado(self):
        # Regresión: "|_snmp-sysdescr:" no se parseaba y el activo salía sin datos.
        p = self.mcp.hechos_desde_perfil(SALIDA_IMPRESORA)
        self.assertIn("HP LaserJet", p["snmp_sysdescr"])

    def test_host_windows_solo_netbios(self):
        p = self.mcp.hechos_desde_perfil(SALIDA_WINDOWS)
        self.assertEqual(p["netbios_nombre"], "PC-CONTA-07")
        self.assertEqual(p["netbios_usuario"], "LABORAL")
        self.assertEqual(p["netbios_vendor"], "Intel Corporate")
        self.assertEqual(p["snmp_sysdescr"], "")

    def test_snmp_abierto_sin_datos_se_reporta_como_exposicion(self):
        p = self.mcp.hechos_desde_perfil(SALIDA_SNMP_DESNUDO)
        self.assertTrue(p["snmp_activo"])
        self.assertIn("UDP/161", self.mcp.bloque_perfil(p))

    def test_udp_open_filtered_no_es_exposicion_snmp(self):
        # Regresión (medido contra un router real): en UDP, "open|filtered"
        # significa SIN respuesta. Reportarlo como SNMP expuesto es falso positivo.
        p = self.mcp.hechos_desde_perfil(
            "137/udp open|filtered netbios-ns\n161/udp open|filtered snmp\n")
        self.assertFalse(p["snmp_activo"])
        self.assertEqual(self.mcp.bloque_perfil(p), "")

    def test_sin_datos_devuelve_bloque_vacio(self):
        p = self.mcp.hechos_desde_perfil(SALIDA_SIN_NADA)
        self.assertEqual(self.mcp.bloque_perfil(p), "")

    def test_entrada_vacia_o_none_no_lanza(self):
        for v in ("", None):
            self.assertEqual(self.mcp.bloque_perfil(self.mcp.hechos_desde_perfil(v)), "")


class TestComandoDePerfil(unittest.TestCase):
    def _capturar(self, ip="10.77.128.1"):
        capt = {}

        def fake_execute(cmd, timeout=None):
            capt["cmd"] = cmd
            capt["timeout"] = timeout
            return SALIDA_SWITCH

        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "execute", side_effect=fake_execute):
            out = win.HadesMCP().asset_profile(ip)
        capt["out"] = out
        return capt

    def test_sondea_snmp_y_netbios_por_udp(self):
        capt = self._capturar()
        self.assertIn("-sU", capt["cmd"])
        self.assertIn("161", capt["cmd"])
        self.assertIn("137", capt["cmd"])
        self.assertIn("nbstat", capt["cmd"])
        self.assertIn("snmp-info", capt["cmd"])
        self.assertIn("--host-timeout", capt["cmd"])  # acotado: no cuelga la Fase 4
        self.assertEqual(capt["timeout"], win.HadesMCP.ASSET_PROFILE_TIMEOUT)

    def test_objetivo_invalido_no_ejecuta_nmap(self):
        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "execute", side_effect=AssertionError("no debe ejecutarse")):
            out = win.HadesMCP().asset_profile("no;valido")
        self.assertIn("inválido", out.lower())

    def test_cidr_rechazado_es_perfilado_por_host(self):
        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "execute", side_effect=AssertionError("no debe ejecutarse")):
            out = win.HadesMCP().asset_profile("10.77.0.0/16")
        self.assertIn("inválido", out.lower())

    def test_comunidad_snmp_saneada(self):
        # Evita inyección de argumentos vía HADES_SNMP_COMMUNITIES.
        with mock.patch.object(win.HadesMCP, "SNMP_COMMUNITIES", "public; rm -rf /"), \
             mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "execute", side_effect=lambda cmd, timeout=None: cmd):
            out = win.HadesMCP().asset_profile("10.77.128.1")
        self.assertNotIn("rm -rf", out)
        self.assertIn("snmpcommunity=public", out)


class TestIntegracionEnFullAudit(unittest.TestCase):
    def test_full_audit_incluye_identidad_del_activo(self):
        mcp = win.HadesMCP()
        with mock.patch.object(mcp, "nmap_scan", return_value="22/tcp open ssh OpenSSH 7.4"), \
             mock.patch.object(mcp, "asset_profile", return_value=SALIDA_SWITCH), \
             mock.patch.object(mcp, "_detect_web_ports", return_value=[]), \
             mock.patch.object(mcp, "ai_analysis", return_value="1) HALLAZGO: puerto 22"):
            rep = mcp.full_audit("10.77.128.1")
        self.assertIn("IDENTIDAD DEL ACTIVO", rep)
        self.assertIn("SW-CORE-01", rep)

    def test_fallo_del_perfilado_no_aborta_la_auditoria(self):
        mcp = win.HadesMCP()
        with mock.patch.object(mcp, "nmap_scan", return_value="22/tcp open ssh"), \
             mock.patch.object(mcp, "asset_profile", side_effect=RuntimeError("boom")), \
             mock.patch.object(mcp, "_detect_web_ports", return_value=[]), \
             mock.patch.object(mcp, "ai_analysis", return_value="ok"):
            rep = mcp.full_audit("10.77.128.1")
        self.assertIn("[NMAP]", rep)          # la auditoría técnica se conserva
        self.assertNotIn("IDENTIDAD DEL ACTIVO", rep)


if __name__ == "__main__":
    unittest.main(verbosity=2)
