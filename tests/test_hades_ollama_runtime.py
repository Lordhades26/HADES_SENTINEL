import unittest
from pathlib import Path

from hades_ollama_runtime import (
    OllamaRuntimeStatus,
    ensure_ollama_available,
)


class _FakeProcess:
    def __init__(self, pid=4321, returncode=None):
        self.pid = pid
        self._returncode = returncode

    def poll(self):
        return self._returncode


class OllamaRuntimeTests(unittest.TestCase):
    def test_healthy_service_is_never_restarted(self):
        spawn_calls = []

        status = ensure_ollama_available(
            probe=lambda _: {"version": "0.32.5"},
            port_busy=lambda *_: True,
            spawn=lambda *args, **kwargs: spawn_calls.append((args, kwargs)),
        )

        self.assertEqual(
            status,
            OllamaRuntimeStatus(
                state="healthy",
                detail="Ollama local disponible.",
                version="0.32.5",
            ),
        )
        self.assertEqual(spawn_calls, [])

    def test_disabled_runtime_does_not_probe_or_spawn(self):
        calls = []

        status = ensure_ollama_available(
            source_env={"HADES_SKIP_AI": "1"},
            probe=lambda _: calls.append("probe"),
            spawn=lambda *args, **kwargs: calls.append("spawn"),
        )

        self.assertEqual(status.state, "disabled")
        self.assertEqual(calls, [])

    def test_remote_or_ambiguous_endpoint_is_rejected(self):
        for endpoint in (
            "http://0.0.0.0:11434",
            "http://192.168.1.20:11434",
            "http://user:secret@127.0.0.1:11434",
            "https://127.0.0.1:11434",
            "http://127.0.0.1:9999",
        ):
            with self.subTest(endpoint=endpoint):
                status = ensure_ollama_available(endpoint=endpoint)
                self.assertEqual(status.state, "unsupported_endpoint")
                self.assertNotIn("secret", status.detail)

    def test_busy_port_with_failed_api_is_not_terminated_or_restarted(self):
        spawn_calls = []

        def failing_probe(_):
            raise TimeoutError("listener sin respuesta")

        status = ensure_ollama_available(
            probe=failing_probe,
            port_busy=lambda *_: True,
            spawn=lambda *args, **kwargs: spawn_calls.append((args, kwargs)),
        )

        self.assertEqual(status.state, "blocked_stale_listener")
        self.assertEqual(spawn_calls, [])
        self.assertIn("ocupado", status.detail.lower())

    def test_missing_binary_degrades_without_exception(self):
        status = ensure_ollama_available(
            probe=lambda _: (_ for _ in ()).throw(ConnectionError()),
            port_busy=lambda *_: False,
            resolve_binary=lambda: None,
        )

        self.assertEqual(status.state, "missing_binary")
        self.assertIsNone(status.pid)

    def test_free_port_starts_exact_binary_with_sanitized_environment(self):
        probes = iter(
            [
                ConnectionError("aún no iniciado"),
                ConnectionError("arrancando"),
                {"version": "0.32.5"},
            ]
        )
        captured = {}
        now = [0.0]

        def probe(_):
            value = next(probes)
            if isinstance(value, Exception):
                raise value
            return value

        def spawn(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return _FakeProcess()

        def wait(seconds):
            now[0] += seconds

        status = ensure_ollama_available(
            source_env={
                "PATH": r"C:\Windows\System32",
                "SYSTEMROOT": r"C:\Windows",
                "LOCALAPPDATA": r"C:\Users\tester\AppData\Local",
                "OLLAMA_API_KEY": "secret",
                "OPENAI_API_KEY": "secret-2",
            },
            probe=probe,
            port_busy=lambda *_: False,
            resolve_binary=lambda: Path(
                r"C:\Users\tester\AppData\Local\Programs\Ollama\ollama.exe"
            ),
            spawn=spawn,
            monotonic=lambda: now[0],
            wait=wait,
            timeout_seconds=4,
        )

        self.assertEqual(status.state, "started")
        self.assertEqual(status.pid, 4321)
        self.assertEqual(status.version, "0.32.5")
        self.assertEqual(
            captured["args"],
            [
                str(
                    Path(
                        r"C:\Users\tester\AppData\Local\Programs\Ollama\ollama.exe"
                    )
                ),
                "serve",
            ],
        )
        env = captured["kwargs"]["env"]
        self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:11434")
        self.assertEqual(
            env["OLLAMA_ORIGINS"],
            "http://127.0.0.1:8080,http://localhost:8080",
        )
        self.assertNotIn("OLLAMA_API_KEY", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("shell", captured["kwargs"])

    def test_process_exit_before_health_is_startup_failed(self):
        status = ensure_ollama_available(
            probe=lambda _: (_ for _ in ()).throw(ConnectionError()),
            port_busy=lambda *_: False,
            resolve_binary=lambda: Path(r"C:\safe\ollama.exe"),
            spawn=lambda *args, **kwargs: _FakeProcess(returncode=2),
        )

        self.assertEqual(status.state, "startup_failed")
        self.assertNotIn("2", status.detail)

    def test_spawn_error_is_redacted(self):
        def spawn(*_args, **_kwargs):
            raise OSError("falló con OLLAMA_API_KEY=super-secret")

        status = ensure_ollama_available(
            probe=lambda _: (_ for _ in ()).throw(ConnectionError()),
            port_busy=lambda *_: False,
            resolve_binary=lambda: Path(r"C:\safe\ollama.exe"),
            spawn=spawn,
        )

        self.assertEqual(status.state, "startup_failed")
        self.assertNotIn("super-secret", status.detail)
        self.assertNotIn("OLLAMA_API_KEY", status.detail)


class OllamaRuntimeIntegrationTests(unittest.TestCase):
    def test_dashboard_renders_runtime_state_and_detail_safely(self):
        dashboard = (
            Path(__file__).resolve().parents[1] / "agente HADES.html"
        ).read_text(encoding="utf-8")

        self.assertIn('id="aiRuntimeState"', dashboard)
        self.assertIn('id="aiRuntimeDetail"', dashboard)
        self.assertIn("runtime_state", dashboard)
        self.assertIn("runtime_detail", dashboard)
        self.assertIn("aiRuntimeDetail.textContent", dashboard)
        self.assertIn("Object.hasOwn(AI_RUNTIME_STATES, state)", dashboard)
        for state in (
            "healthy",
            "started",
            "disabled",
            "unsupported_endpoint",
            "blocked_stale_listener",
            "missing_binary",
            "startup_failed",
            "not_checked",
        ):
            with self.subTest(state=state):
                self.assertIn(state, dashboard)

    def test_dashboard_metrics_expose_runtime_diagnosis(self):
        import hades_server

        expected = OllamaRuntimeStatus(
            "blocked_stale_listener",
            "Puerto local ocupado por servicio no saludable.",
        )
        result = hades_server._initialize_ollama_runtime(lambda: expected)

        self.assertEqual(result, expected)
        self.assertIn("runtime_state", hades_server.ollama_metrics)
        self.assertIn("runtime_detail", hades_server.ollama_metrics)
        self.assertEqual(
            hades_server.ollama_metrics["runtime_state"],
            "blocked_stale_listener",
        )
        self.assertEqual(
            hades_server.ollama_metrics["runtime_detail"],
            expected.detail,
        )

    def test_cli_checks_runtime_once_and_degrades_without_http_request(self):
        from hades_local import HadesEngine

        calls = []

        def fake_ensure():
            calls.append("ensure")
            return OllamaRuntimeStatus(
                "blocked_stale_listener",
                "Puerto local ocupado por servicio no saludable.",
            )

        engine = HadesEngine(ensure_runtime=fake_ensure)
        first = engine._ask("evidencia")
        second = engine._ask("otra evidencia")

        self.assertEqual(calls, ["ensure"])
        self.assertIn("Error IA:", first)
        self.assertIn("no saludable", first)
        self.assertEqual(first, second)

    def test_dashboard_monitors_start_once_only_when_requested(self):
        import hades_server

        created = []

        class FakeThread:
            def __init__(self, *, target, daemon):
                created.append((target, daemon, self))
                self.started = False

            def start(self):
                self.started = True

        original = hades_server._background_monitors_started
        try:
            hades_server._background_monitors_started = False
            hades_server._start_background_monitors(FakeThread)
            hades_server._start_background_monitors(FakeThread)
        finally:
            hades_server._background_monitors_started = original

        self.assertEqual(len(created), 2)
        self.assertTrue(all(daemon for _, daemon, _ in created))
        self.assertTrue(all(thread.started for _, _, thread in created))


if __name__ == "__main__":
    unittest.main()
