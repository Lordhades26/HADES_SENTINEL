"""Regresión 24-11-2026: IA lenta en CPU no es IA caída, y Ollama se recupera."""
import http.server
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hades_ollama_runtime as runtime
import hades_server
import hades_win_master_advanced as hwm


class _Ollama(http.server.BaseHTTPRequestHandler):
    """Ollama simulado: responde /api/version y genera muy despacio."""
    inicial = 0.0
    intervalo = 0.0
    tokens = 3

    def log_message(self, *_):
        pass

    def do_GET(self):
        cuerpo = b'{"version":"test"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_POST(self):
        datos = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).ultimo = datos
        try:
            time.sleep(self.inicial)
            self.send_response(200)
            self.end_headers()
            for i in range(self.tokens):
                self.wfile.write(json.dumps({"response": f"t{i} ", "done": False}).encode() + b"\n")
                self.wfile.flush()
                time.sleep(self.intervalo)
            self.wfile.write(b'{"response":"","done":true,"done_reason":"stop","eval_count":3}\n')
        except OSError:
            pass  # el cliente cortó


class IALentaTests(unittest.TestCase):
    def setUp(self):
        self.handler = type("H", (_Ollama,), {})
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{self.srv.server_port}/api/generate"
        p = mock.patch.dict(hwm.WIN_PATHS, {"ollama": url})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.mcp = hwm.HadesMCP()
        self.mcp._record_ollama_metrics = lambda *_: None

    def test_streaming_completo(self):
        self.assertEqual(self.mcp.ai_analysis("x", timeout=5, retries=0), "t0 t1 t2")
        self.assertTrue(self.handler.ultimo["stream"])

    def test_corte_por_tiempo_conserva_texto_parcial(self):
        self.handler.intervalo, self.handler.tokens = 0.4, 50
        t0 = time.time()
        salida = self.mcp.ai_analysis("x", timeout=2, retries=0)
        self.assertLess(time.time() - t0, 5)
        self.assertIn("t0", salida)
        self.assertIn("Respuesta parcial", salida)
        self.assertFalse(self.mcp.ai_unavailable)

    def test_lento_pero_vivo_no_anula_los_hosts_siguientes(self):
        self.handler.inicial = 4
        salida = self.mcp.ai_analysis("x", timeout=1, retries=0)
        self.assertIn("[IA]", salida)
        self.assertFalse(self.mcp.ai_unavailable)
        self.handler.inicial = 0
        self.assertIn("t0", self.mcp.ai_analysis("y", timeout=5, retries=0))

    def test_error_dentro_del_stream_no_se_da_por_respuesta(self):
        def post(h):
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b'{"error":"runner stopped"}\n')
        self.handler.do_POST = post
        salida = self.mcp.ai_analysis("x", timeout=3, retries=0)
        self.assertIn("runner stopped", salida)


class PresupuestoPromptTests(unittest.TestCase):
    def test_prompt_maximo_cabe_en_el_tiempo_de_cpu(self):
        mcp = hwm.HadesMCP()
        nmap = "\n".join(f"{8000+i}/tcp open http Servicio-{i} v{i}.2" for i in range(900))
        nuclei = "\n".join(f"[HIGH] hallazgo {i} CVE-2025-{10000+i}" for i in range(900))
        prompts = []
        with mock.patch.object(mcp, "nmap_scan", return_value=nmap), \
             mock.patch.object(mcp, "asset_profile", return_value=""), \
             mock.patch.object(mcp, "nuclei_scan", return_value=nuclei), \
             mock.patch.object(mcp, "ssl_audit", return_value="subject=CN=x " * 900), \
             mock.patch.object(mcp, "ai_analysis", side_effect=lambda p: prompts.append(p) or "ok"):
            mcp.full_audit("192.0.2.10", web_ports=["https://192.0.2.10"])
        # 4.815 tokens tardaron 237 s hasta el primer token en este equipo.
        self.assertLessEqual(len(prompts[0]), 9000)


class ResumenTraficoTests(unittest.TestCase):
    def test_recorta_por_linea_y_avisa(self):
        import hades_surveillance_advanced as hsa
        self.assertEqual(hsa.resumen_trafico_ia("corto"), "corto")
        salida = hsa.resumen_trafico_ia("linea completa\n" * 500)
        self.assertLess(len(salida), 3100)
        self.assertIn("Captura resumida", salida)
        self.assertEqual(salida.splitlines()[-2], "linea completa")


class _Proc:
    pid = 77

    def __init__(self, rc=None):
        self.rc, self.cerrado = rc, False

    def poll(self):
        return self.rc

    def terminate(self):
        self.cerrado, self.rc = True, 0

    kill = terminate

    def wait(self, timeout=None):
        return self.rc


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, runtime, "_owned_process", None)

    def _ensure(self, probe, proc, **kw):
        reloj = [0.0]
        return runtime.ensure_ollama_available(
            source_env={}, probe=probe, port_busy=lambda *_: False,
            resolve_binary=lambda: Path(r"C:\safe\ollama.exe"), spawn=lambda *a, **k: proc,
            monotonic=lambda: reloj[0],
            wait=lambda s: reloj.__setitem__(0, reloj[0] + max(s, .01)), **kw)

    def test_arranque_de_20_segundos_se_acepta(self):
        n = [0]

        def probe(_):
            n[0] += 1
            if n[0] < 80:  # 80 sondeos x 0,25 s = 20 s
                raise ConnectionError()
            return {"version": "x"}
        self.assertEqual(self._ensure(probe, _Proc()).state, "started")

    def test_arranque_fallido_no_deja_huerfano(self):
        proc = _Proc()
        with mock.patch.object(runtime, "terminate_process_tree",
                               side_effect=lambda p, timeout=5: p.terminate()):
            st = self._ensure(lambda _: (_ for _ in ()).throw(ConnectionError()), proc, timeout_seconds=2)
        self.assertEqual(st.state, "startup_failed")
        self.assertTrue(proc.cerrado)

    def test_si_otro_ollama_gano_el_puerto_queda_healthy(self):
        n = [0]

        def probe(_):
            n[0] += 1
            if n[0] == 1:
                raise ConnectionError()
            return {"version": "x"}
        self.assertEqual(self._ensure(probe, _Proc(rc=1)).state, "healthy")

    def test_cierre_solo_termina_el_proceso_propio(self):
        with mock.patch.object(runtime, "terminate_process_tree") as fin:
            runtime._owned_process = None
            runtime.shutdown_owned_ollama()
            fin.assert_not_called()
            runtime._owned_process = p = _Proc()
            runtime.shutdown_owned_ollama()
            fin.assert_called_once()
            self.assertIs(fin.call_args[0][0], p)


class RecuperacionDashboardTests(unittest.TestCase):
    def test_recupera_ollama_caido_y_respeta_enfriamiento(self):
        llamadas = []

        def ensure():
            llamadas.append(1)
            return runtime.OllamaRuntimeStatus("started", "ok")
        r = hades_server.OllamaRecovery(ensure, cooldown=60)
        self.assertIsNone(r.tick(False, 0))       # una sola falla no basta
        self.assertEqual(r.tick(False, 3).state, "started")
        r.tick(False, 6)
        r.tick(False, 9)
        self.assertEqual(len(llamadas), 1)        # dentro del enfriamiento
        r.tick(False, 70)
        self.assertEqual(len(llamadas), 2)

    def test_conectado_reinicia_el_contador(self):
        r = hades_server.OllamaRecovery(lambda: self.fail("no debe arrancar"), cooldown=60)
        r.tick(False, 0)
        r.tick(True, 3)
        self.assertIsNone(r.tick(False, 6))


if __name__ == "__main__":
    unittest.main()
