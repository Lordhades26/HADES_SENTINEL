# -*- coding: utf-8 -*-
"""Regresiones de producción para los cierres P0/P1 de AUDITORIA_CODEX.

Todos los datos de red son sintéticos. Los cinco arreglos se ejecutan como
``subTest`` de un único caso para conservar el contrato histórico de 24 casos
del runner, sin perder diagnóstico individual por hallazgo.
"""
import io
import inspect
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hades_local
import hades_mcp
import hades_report_docx
import hades_server
import hades_win_master_advanced as hwm


ALLOWED_HOST = f"127.0.0.1:{hades_server.PORT}"


class _MemorySocket:
    """Transporte HTTP en memoria; el handler y su parser son los reales."""

    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = io.BytesIO()

    def makefile(self, mode, buffering=None):
        return self.input if "r" in mode else self.output

    def sendall(self, data):
        self.output.write(data)

    def settimeout(self, timeout):
        pass


class _HandlerServer:
    server_name = "localhost"
    server_port = hades_server.PORT


def _request(method, path, body=None, headers=None, add_content_length=True):
    request_headers = {"Host": ALLOWED_HOST}
    if method == "POST":
        # Desde 2026-11-17 los POST exigen el token de sesión; el dashboard lo
        # envía siempre. Los tests de rechazo lo quitan o lo alteran a propósito.
        request_headers[hades_server.TOKEN_HEADER] = hades_server.SESSION_TOKEN
    request_headers.update(headers or {})
    request_headers = {k: v for k, v in request_headers.items() if v is not None}
    payload = b"" if body is None else body
    if add_content_length and body is not None:
        request_headers.setdefault("Content-Length", str(len(payload)))
    request_headers.setdefault("Connection", "close")
    lines = [f"{method} {path} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in request_headers.items())
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload
    transport = _MemorySocket(raw)
    hades_server.SecureHadesHandler(
        transport, ("127.0.0.1", 45000), _HandlerServer()
    )
    response = transport.output.getvalue()
    head, _, response_body = response.partition(b"\r\n\r\n")
    header_lines = head.split(b"\r\n")
    status = int(header_lines[0].split()[1])
    parsed_headers = {}
    for line in header_lines[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            parsed_headers[name.decode("ascii")] = value.strip().decode("latin-1")
    return status, response_body, parsed_headers


class _ImmediateProcess:
    def __init__(self, pid=41001):
        self.pid = pid
        self.returncode = 0
        self.stdout = io.StringIO("")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


class _BlockingStream:
    def __init__(self, release):
        self.release = release

    def readline(self):
        self.release.wait(timeout=5)
        return ""

    def close(self):
        self.release.set()


class _BlockingProcess:
    def __init__(self, release, pid=41002):
        self.pid = pid
        self.returncode = None
        self.stdout = _BlockingStream(release)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            if not self.stdout.release.wait(timeout=timeout):
                raise subprocess.TimeoutExpired("synthetic", timeout)
            self.returncode = 0
        return self.returncode

    def terminate(self):
        self.returncode = 0
        self.stdout.release.set()

    def kill(self):
        self.terminate()


class _EscalationProcess:
    """Proceso sintético: terminate no basta y kill sí lo finaliza."""

    def __init__(self):
        self.pid = 41003
        self.returncode = None
        self.stdout = io.StringIO("")
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return self.returncode


class TestProduccionP0P1(unittest.TestCase):

    def test_cierres_p0_p1(self):
        with self.subTest(arreglo="P0-1 S-01 GET_HEAD_allowlist"):
            status, _, _ = _request(
                "GET", "/README.md",
                headers={"Host": f"rebinding.invalid:{hades_server.PORT}"},
            )
            self.assertEqual(status, 403)

            status, body, _ = _request(
                "HEAD", "/",
                headers={"Host": f"rebinding.invalid:{hades_server.PORT}"},
            )
            self.assertEqual((status, body), (403, b""))

            for blocked in (
                "/README.md", "/hades_server.py", "/server_out.log",
                "/informes/", "/.git/config", "/",
            ):
                method = "HEAD" if blocked == "/" else "GET"
                status, body, _ = _request(method, blocked)
                if blocked == "/":
                    self.assertEqual((status, body), (200, b""))
                else:
                    self.assertEqual(status, 404, blocked)

            for asset in (
                "/agente%20HADES.html",
                "/assets/logo_hades_sentinel_doc.png",
                "/network_map_3d.js",
                "/vendor/hades-graph-bundle.js",
            ):
                status, _, _ = _request("GET", asset)
                self.assertEqual(status, 200, asset)

            logo_path = os.path.join(
                hades_server._HERE, "assets", "logo_hades_sentinel_doc.png"
            )
            real_islink = hades_server.os.path.islink
            with mock.patch.object(
                hades_server.os.path,
                "islink",
                side_effect=lambda path: (
                    os.path.normcase(path) == os.path.normcase(logo_path)
                    or real_islink(path)
                ),
            ):
                self.assertIsNone(
                    hades_server._resolve_static_asset(
                        "/assets/logo_hades_sentinel_doc.png"
                    )
                )

        with self.subTest(arreglo="P0-2 S-02_procedencia_CVE"):
            block = """
10.20.30.40
[NMAP]
Host is up (0.002s latency).
80/tcp open http Synthetic banner CVE-2026-90001
| vulners: CVE-2025-10001
[NUCLEI]
[HIGH] synthetic-template CVE-2025-20002
[SSL/TLS]
sin datos
[ANÁLISIS IA HADES]
El modelo propone CVE-2026-99999.
---
"""
            host = hades_report_docx._parse_host_block("10.20.30.40", block)
            self.assertEqual(
                host["cves_confirmados"],
                ["CVE-2025-10001", "CVE-2025-20002"],
            )
            self.assertIn("CVE-2026-99999", host["texto_ia"])
            self.assertNotIn("cves", host)
            self.assertNotIn("ai", host)

            only_ai = hades_report_docx._parse_host_block(
                "10.20.30.41",
                """
10.20.30.41
[NMAP]
Host is up.
[ANÁLISIS IA HADES]
CVE-2026-99999
---
""",
            )
            self.assertEqual(only_ai["cves_confirmados"], [])
            self.assertEqual(only_ai["risk"], "INFORMATIVO")

            hechos = {"puertos": [], "os": "", "vendor": "", "mac": ""}
            avisos = hwm.HadesMCP().auditar_respuesta_ia(
                "Se identifica CVE-2024-99999.", hechos
            )
            self.assertTrue(any("CVE-2024-99999" in aviso for aviso in avisos))

        with self.subTest(arreglo="P1-1 S-03_validadores_reales"):
            import hades_validation

            invalid = (
                "--help", "-oNloot", "999.999.999.999", "10.0.0.0/99",
                "host..example", "-host.example", "host-.example",
            )
            validators = (
                hades_validation.validate_target,
                hades_local._safe_target,
                hades_mcp._safe_target,
                hwm._valid_target,
            )
            for validator in validators:
                for value in invalid:
                    self.assertIsNone(
                        validator(value), f"{validator.__module__}: {value}"
                    )

            for valid in (
                "127.0.0.1", "192.0.2.17/24", "router.example",
                "2001:db8::1", "2001:db8::/64",
            ):
                self.assertEqual(hades_validation.validate_target(valid), valid)
            self.assertEqual(
                hwm._valid_url("https://scanner.example/path"),
                "https://scanner.example/path",
            )
            self.assertIsNone(hwm._valid_url("https://user@scanner.example/"))

        with self.subTest(arreglo="P1-2 S-05_contrato_POST"):
            popen = mock.Mock(return_value=_ImmediateProcess())
            with mock.patch.object(hades_server, "_launch_scan_process", popen):
                status, _, _ = _request(
                    "POST", "/api/scan",
                    headers={"Content-Type": "application/json"},
                    add_content_length=False,
                )
                self.assertEqual(status, 411)

                status, _, _ = _request(
                    "POST", "/api/scan", body=b"{}",
                    headers={"Content-Type": "text/plain"},
                )
                self.assertEqual(status, 415)

                oversized = b"x" * (8 * 1024 + 1)
                status, _, _ = _request(
                    "POST", "/api/scan", body=oversized,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(status, 413)

                invalid_bodies = (
                    b"{",
                    json.dumps({"target": "auto"}).encode(),
                    json.dumps({"target": 7, "duration": 30}).encode(),
                    json.dumps({"target": "auto", "duration": True}).encode(),
                    json.dumps({"target": "auto", "duration": 4}).encode(),
                    json.dumps({"target": "auto", "duration": 301}).encode(),
                    json.dumps(
                        {"target": "auto", "duration": 30, "extra": 1}
                    ).encode(),
                )
                for body in invalid_bodies:
                    status, _, _ = _request(
                        "POST", "/api/scan", body=body,
                        headers={"Content-Type": "application/json"},
                    )
                    self.assertEqual(status, 400, body)

                status, _, _ = _request(
                    "POST", "/api/desconocida", body=b"{}",
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(status, 404)
                status, _, _ = _request(
                    "POST", "/api/stop", body=b"{}",
                    headers={"Content-Type": "text/plain"},
                )
                self.assertEqual(status, 415)
                status, _, _ = _request(
                    "POST", "/api/stop", body=b'{"unexpected": true}',
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(status, 400)

            self.assertEqual(
                popen.call_count, 0,
                "ninguna entrada HTTP inválida debe lanzar un escaneo",
            )

        with self.subTest(arreglo="P1-3 R-01_R-02_lifecycle"):
            release = threading.Event()
            created = []

            def fake_popen(*args, **kwargs):
                process = _BlockingProcess(release, pid=42000 + len(created))
                created.append(process)
                return process

            body = json.dumps({"target": "auto", "duration": 30}).encode()
            with mock.patch.object(
                hades_server, "_launch_scan_process", fake_popen
            ):
                barrier = threading.Barrier(3)
                responses = []

                def launch():
                    barrier.wait()
                    responses.append(
                        _request(
                            "POST", "/api/scan", body=body,
                            headers={"Content-Type": "application/json"},
                        )[0]
                    )

                threads = [threading.Thread(target=launch) for _ in range(2)]
                for thread in threads:
                    thread.start()
                barrier.wait()
                for thread in threads:
                    thread.join(timeout=5)

                self.assertEqual(len(created), 1)
                self.assertEqual(sorted(responses), [200, 400])
                release.set()
                deadline = time.time() + 3
                while hades_server.active_process is not None and time.time() < deadline:
                    time.sleep(0.01)

            import hades_processes

            process = _EscalationProcess()
            taskkill_failed = mock.Mock(
                return_value=subprocess.CompletedProcess([], 1)
            )
            self.assertTrue(
                hades_processes.terminate_process_tree(
                    process,
                    taskkill_runner=taskkill_failed,
                    platform_name="nt",
                )
            )
            self.assertEqual(process.terminate_calls, 1)
            self.assertEqual(process.kill_calls, 1)
            self.assertGreaterEqual(process.wait_calls, 2)
            taskkill_failed.assert_called_once()
            self.assertFalse(taskkill_failed.call_args.kwargs.get("shell", False))

            exited = _EscalationProcess()
            exited.returncode = 0
            with (
                mock.patch.object(
                    hades_processes, "_snapshot_descendants", return_value=[]
                ) as snapshot,
                mock.patch.object(
                    hades_processes, "_stop_descendants", return_value=True
                ) as stop_descendants,
            ):
                self.assertTrue(hades_processes.terminate_process_tree(exited))
            snapshot.assert_called_once_with(exited.pid)
            stop_descendants.assert_called_once()

            server_source = inspect.getsource(hades_server)
            master_source = inspect.getsource(hwm)
            self.assertNotIn("def _kill_child_tools", server_source)
            self.assertNotIn("WINDOWTITLE eq hades*", server_source)
            self.assertNotIn('subprocess.run("taskkill', master_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
