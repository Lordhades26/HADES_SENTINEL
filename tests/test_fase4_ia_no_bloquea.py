# -*- coding: utf-8 -*-
"""
Regresión de la Fase 4: el análisis IA es CONSULTIVO y no debe bloquear ni
ocultar la evidencia determinista del host.

Reproduce el fallo observado el 25-07-2026: Ollama quedó escuchando en el puerto
pero sin responder HTTP. Como la conexión TCP sí se establecía, urllib esperaba
el timeout completo en cada intento (360 s x 3 = 18 min por host), y como el
informe solo se persistía DESPUÉS de completar el host, la auditoría profunda
no dejaba ningún rastro en disco.

Los tres casos cubren:
  1. La IA degrada en tiempo acotado frente a un servicio colgado.
  2. La evidencia técnica se entrega ANTES de invocar a la IA.
  3. Un servicio caído se detecta UNA vez por corrida, no una vez por host.
"""
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hades_win_master_advanced as hwm


class ServidorColgado:
    """Acepta conexiones TCP y nunca responde: reproduce el estado real de
    Ollama observado (puerto en LISTEN, HTTP mudo)."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._vivas = []
        self._parar = threading.Event()
        self._hilo = threading.Thread(target=self._servir, daemon=True)
        self._hilo.start()

    def _servir(self):
        self._sock.settimeout(0.5)
        while not self._parar.is_set():
            try:
                conn, _ = self._sock.accept()
                self._vivas.append(conn)  # se acepta y se deja muda
            except socket.timeout:
                continue
            except OSError:
                break

    def cerrar(self):
        self._parar.set()
        for c in self._vivas:
            try:
                c.close()
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass

    @property
    def url_generate(self):
        return f"http://127.0.0.1:{self.port}/api/generate"


class TestFase4IANoBloquea(unittest.TestCase):

    def setUp(self):
        self.servidor = ServidorColgado()
        self._url_original = hwm.WIN_PATHS["ollama"]
        hwm.WIN_PATHS["ollama"] = self.servidor.url_generate
        self.mcp = hwm.HadesMCP()

    def tearDown(self):
        hwm.WIN_PATHS["ollama"] = self._url_original
        self.servidor.cerrar()

    def test_ia_degrada_en_tiempo_acotado(self):
        """Con el servicio colgado, ai_analysis debe rendirse dentro del
        presupuesto declarado, no consumir (retries+1) x timeout."""
        inicio = time.time()
        salida = self.mcp.ai_analysis("prueba", timeout=2, retries=1)
        transcurrido = time.time() - inicio

        self.assertIn("[IA]", salida,
                      "debe devolver una nota de degradación, no propagar la excepción")
        # Presupuesto: timeout x (retries+1) + margen. Sin presupuesto global el
        # tiempo real se disparaba muy por encima de esta cota.
        self.assertLess(transcurrido, 12,
                        f"la IA tardó {transcurrido:.1f}s en degradar; debe ser acotado")

    def test_evidencia_tecnica_se_entrega_antes_de_la_ia(self):
        """full_audit debe publicar la parte determinista (nmap/nuclei/TLS)
        ANTES de llamar al modelo, para que un fallo de IA no la oculte."""
        # Se registra la SECUENCIA de eventos, no marcas de tiempo: en Windows la
        # resolución de time.time() (~15 ms) puede igualar dos instantes seguidos.
        eventos = []
        capturado = {}

        def al_tener_tecnica(texto_parcial):
            eventos.append("tecnica")
            capturado["texto"] = texto_parcial

        # Aislamos las herramientas externas: aquí se prueba el orden, no el escaneo.
        self.mcp.nmap_scan = lambda ip, **kw: "80/tcp open http"
        self.mcp.nuclei_scan = lambda url, **kw: "[NUCLEI] 0 hallazgos"
        self.mcp.ssl_audit = lambda h, p=443: "[SSL/TLS] sin datos"

        def ia_simulada(prompt, **kw):
            eventos.append("ia")
            return "[IA] simulada"

        self.mcp.ai_analysis = ia_simulada

        salida = self.mcp.full_audit("192.168.56.10", on_technical_ready=al_tener_tecnica)

        self.assertEqual(eventos, ["tecnica", "ia"],
                         "la evidencia técnica debe publicarse ANTES del análisis IA")
        self.assertIn("NMAP", capturado["texto"],
                      "el parcial entregado debe contener la evidencia de Nmap")
        self.assertNotIn("[ANÁLISIS IA HADES]", capturado["texto"],
                         "el parcial no debe contener aún la sección de IA")
        self.assertIn("[ANÁLISIS IA HADES]", salida,
                      "el informe final del host sí debe incluir la IA")

    def test_servicio_caido_se_detecta_una_vez_por_corrida(self):
        """Si el servicio no responde, la corrida debe marcarlo y dejar de
        reintentar en cada host (antes: 18 min de espera por cada uno)."""
        self.mcp.ai_budget_seconds = 4  # presupuesto total de IA para la corrida

        t0 = time.time()
        primera = self.mcp.ai_analysis("host 1", timeout=2, retries=0)
        t1 = time.time()
        segunda = self.mcp.ai_analysis("host 2", timeout=2, retries=0)
        t2 = time.time()

        self.assertIn("[IA]", primera)
        self.assertIn("[IA]", segunda)
        # La segunda llamada debe cortocircuitar: el servicio ya se declaró caído.
        self.assertLess(t2 - t1, 0.5,
                        "tras detectar el servicio caído, las llamadas siguientes "
                        "deben omitirse de inmediato")
        self.assertLess(t2 - t0, 10, "el conjunto debe respetar el presupuesto")


if __name__ == "__main__":
    unittest.main(verbosity=2)
