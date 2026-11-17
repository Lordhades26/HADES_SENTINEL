#!/usr/bin/env python3
"""Regresión del descubrimiento adaptativo de la Fase 1 (on-link ARP / L3 enrutado).

Motivo: el descubrimiento antiguo usaba siempre `-sn -PR -PE -PS...`. El `-PR` (ARP)
no cruza un router, y sin timing acotado Nmap se arrastraba contra un /24 enrutado
hasta agotar el techo del subproceso (300 s) y devolvía una lista de hosts vacía.
Ahora `nmap_discovery` elige el perfil según dónde caiga el objetivo. Estos casos
fijan ese contrato con mocks, sin tocar la red.
"""
import os
import sys
import unittest
from unittest import mock
import ipaddress

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hades_win_master_advanced as win


def _nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


class TestClasificacionOnlink(unittest.TestCase):
    def test_onlink_true_en_la_propia_subred(self):
        with mock.patch.object(win, "_local_ipv4_networks",
                               return_value=_nets("10.77.140.0/24", "192.168.1.0/24")):
            self.assertTrue(win._target_is_onlink("10.77.140.0/24"))
            self.assertTrue(win._target_is_onlink("10.77.140.55"))
            self.assertTrue(win._target_is_onlink("192.168.1.0/24"))

    def test_onlink_false_para_red_enrutada(self):
        # El caso real: escanear 10.77.0.0/24 desde 10.77.140.0/24 cruza el router.
        with mock.patch.object(win, "_local_ipv4_networks",
                               return_value=_nets("10.77.140.0/24")):
            self.assertFalse(win._target_is_onlink("10.77.0.0/24"))
            self.assertFalse(win._target_is_onlink("8.8.8.8"))

    def test_objetivo_que_engloba_la_subred_local_es_enrutado(self):
        # Un /16 que CONTIENE la /24 local es mayormente enrutado: debe ir por L3,
        # no por ARP (que solo vería la porción local y perdería el resto del /16).
        with mock.patch.object(win, "_local_ipv4_networks",
                               return_value=_nets("10.77.140.0/24")):
            self.assertFalse(win._target_is_onlink("10.77.0.0/16"))   # engloba la local
            self.assertFalse(win._target_is_onlink("10.77.140.0/23")) # excede la local
            self.assertTrue(win._target_is_onlink("10.77.140.0/24"))  # igual a la local
            self.assertTrue(win._target_is_onlink("10.77.140.128/25"))# contenida en la local

    def test_hostname_o_rango_no_cidr_se_trata_como_enrutado(self):
        with mock.patch.object(win, "_local_ipv4_networks",
                               return_value=_nets("10.77.140.0/24")):
            self.assertFalse(win._target_is_onlink("scanme.nmap.org"))
            self.assertFalse(win._target_is_onlink("10.77.0.1-50"))

    def test_sin_subredes_locales_todo_es_enrutado(self):
        # Fallback conservador si psutil no está o no devuelve nada.
        with mock.patch.object(win, "_local_ipv4_networks", return_value=[]):
            self.assertFalse(win._target_is_onlink("10.77.140.0/24"))


class TestPerfilDeDescubrimiento(unittest.TestCase):
    def _capturar_cmd(self, target, onlink):
        capt = {}

        def fake_execute(cmd, timeout=None):
            capt["cmd"] = cmd
            capt["timeout"] = timeout
            return "Nmap done: 0 hosts up"

        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "_target_is_onlink", return_value=onlink), \
             mock.patch.object(win, "execute", side_effect=fake_execute):
            win.HadesMCP().nmap_discovery(target)
        return capt

    def test_onlink_usa_arp(self):
        capt = self._capturar_cmd("10.77.140.0/24", onlink=True)
        self.assertIn("-PR", capt["cmd"])
        self.assertNotIn("--min-rate", capt["cmd"])  # el perfil L2 no necesita timing agresivo

    def test_enrutado_usa_l3_acotado_sin_arp(self):
        capt = self._capturar_cmd("10.77.0.0/24", onlink=False)
        cmd = capt["cmd"]
        self.assertIn("--host-timeout", cmd)          # timing acotado: no se cuelga
        self.assertIn("--max-retries", cmd)
        self.assertIn("-PU53,137,161", cmd)           # sondas L3 diversas (UDP)
        self.assertIn("-PA80,443,3389", cmd)          # TCP ACK
        self.assertNotIn(" -PR ", " " + cmd + " ")    # ARP no aplica en enrutado
        self.assertEqual(capt["timeout"], win.DISCOVERY_SUBPROC_TIMEOUT)

    def test_objetivo_invalido_no_lanza_nmap(self):
        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "execute", side_effect=AssertionError("no debe ejecutarse")):
            out = win.HadesMCP().nmap_discovery("no es;un objetivo")
        self.assertIn("inválido", out.lower())


class TestEscaladoDelRango(unittest.TestCase):
    """El timing del barrido L3 debe escalar con el tamaño: un /24 usa el perfil
    base; un /16 sube rate y techo o Nmap no termina (bug 'el /16 no hace nada')."""

    def test_rango_pequeno_usa_perfil_base(self):
        flags, timeout = win._scaled_routed_discovery("10.77.140.0/24")
        self.assertEqual(flags, win.DISCOVERY_ROUTED_FLAGS)
        self.assertEqual(timeout, win.DISCOVERY_SUBPROC_TIMEOUT)

    def test_rango_grande_sube_rate_y_techo(self):
        import re
        flags, timeout = win._scaled_routed_discovery("10.77.0.0/16")
        mr = int(re.search(r"--min-rate\s+(\d+)", flags).group(1))
        self.assertGreater(mr, 200)                                # rate > base
        self.assertGreater(timeout, win.DISCOVERY_SUBPROC_TIMEOUT)  # techo > 600
        self.assertLessEqual(timeout, 3600)                        # acotado a 1 h

    def test_conteo_de_hosts(self):
        self.assertEqual(win._target_host_count("10.77.0.0/16"), 65536)
        self.assertEqual(win._target_host_count("10.77.140.0/24"), 256)
        self.assertEqual(win._target_host_count("10.77.100.5"), 1)
        self.assertEqual(win._target_host_count("no-es-cidr"), 1)

    def test_discovery_enrutado_grande_pasa_timeout_escalado(self):
        import re
        capt = {}
        def fake_execute(cmd, timeout=None):
            capt["cmd"] = cmd; capt["timeout"] = timeout; return "Nmap done"
        with mock.patch.object(win.os.path, "exists", return_value=True), \
             mock.patch.object(win, "_target_is_onlink", return_value=False), \
             mock.patch.object(win, "execute", side_effect=fake_execute):
            win.HadesMCP().nmap_discovery("10.77.0.0/16")
        self.assertGreater(capt["timeout"], win.DISCOVERY_SUBPROC_TIMEOUT)
        self.assertIn("--min-rate", capt["cmd"])
        mr = int(re.search(r"--min-rate\s+(\d+)", capt["cmd"]).group(1))
        self.assertGreater(mr, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
