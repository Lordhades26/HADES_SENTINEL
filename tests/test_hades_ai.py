import os
import unittest
from pathlib import Path

from hades_ai import (
    AI_BACKOFF_SECONDS,
    AI_BUDGET_SECONDS,
    AI_RETRIES,
    AI_TIMEOUT_SECONDS,
    CONSULTATIVE_LABEL,
    DEFAULT_MODEL,
    DEFAULT_OLLAMA_URL,
    OLLAMA_URL,
    build_generate_payload,
    format_consultative_output,
    normalize_ollama_generate_url,
    safe_subprocess_env,
)


class HadesAIConfigurationTests(unittest.TestCase):
    def test_secure_defaults(self):
        self.assertEqual(DEFAULT_MODEL, "HADES-SENTINEL-ANALYST:1.0.0")
        self.assertEqual(
            DEFAULT_OLLAMA_URL,
            "http://127.0.0.1:11434/api/generate",
        )
        self.assertEqual(OLLAMA_URL, DEFAULT_OLLAMA_URL)
        self.assertEqual(AI_TIMEOUT_SECONDS, 300)
        self.assertEqual(AI_RETRIES, 0)
        self.assertEqual(AI_BUDGET_SECONDS, 1200)
        self.assertEqual(AI_BACKOFF_SECONDS, 3)

    def test_generate_payload_is_bounded_and_deterministic(self):
        payload = build_generate_payload("evidencia")
        self.assertEqual(payload["prompt"], "evidencia")
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["keep_alive"], "5m")
        self.assertEqual(
            payload["options"],
            {"num_predict": 640, "temperature": 0},
        )

    def test_generate_payload_rejects_empty_prompt(self):
        with self.assertRaises(ValueError):
            build_generate_payload("")

    def test_normalize_url_rejects_credentials_and_unsafe_schemes(self):
        invalid = (
            "file:///tmp/ollama",
            "ftp://127.0.0.1:11434/api/generate",
            "http://user:pass@127.0.0.1:11434/api/generate",
            "http://127.0.0.1:11434/api/tags",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ollama_generate_url(value)

    def test_normalize_url_accepts_http_generate_endpoint(self):
        self.assertEqual(
            normalize_ollama_generate_url(
                "http://localhost:11434/api/generate"
            ),
            "http://localhost:11434/api/generate",
        )

    def test_safe_subprocess_env_drops_secrets_and_overrides_encoding(self):
        source = {
            "PATH": "C:\\tools",
            "SYSTEMROOT": "C:\\Windows",
            "OLLAMA_API_KEY": "secret",
            "OPENAI_API_KEY": "secret-2",
            "PYTHONIOENCODING": "bad",
            "HADES_MODEL": "custom-model",
            "HADES_AI_TIMEOUT": "90",
            "UNRELATED_PRIVATE_VALUE": "do-not-copy",
        }
        env = safe_subprocess_env(source)
        self.assertEqual(env["PATH"], "C:\\tools")
        self.assertEqual(env["SYSTEMROOT"], "C:\\Windows")
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual(env["HADES_MODEL"], "custom-model")
        self.assertEqual(env["HADES_AI_TIMEOUT"], "90")
        self.assertNotIn("OLLAMA_API_KEY", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", env)

    def test_safe_subprocess_env_uses_current_environment_by_default(self):
        env = safe_subprocess_env()
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["PYTHONUTF8"], "1")
        if os.environ.get("PATH"):
            self.assertEqual(env["PATH"], os.environ["PATH"])

    def test_all_consumers_share_central_model_and_url(self):
        import hades_local
        import hades_mcp
        import hades_win_master_advanced

        self.assertEqual(hades_local.HADES_MODEL, DEFAULT_MODEL)
        self.assertEqual(hades_mcp.HADES_MODEL, DEFAULT_MODEL)
        self.assertEqual(hades_win_master_advanced.HADES_MODEL, DEFAULT_MODEL)
        self.assertEqual(hades_mcp.OLLAMA_URL, DEFAULT_OLLAMA_URL)
        self.assertEqual(
            hades_win_master_advanced.WIN_PATHS["ollama"],
            DEFAULT_OLLAMA_URL,
        )
        self.assertEqual(
            hades_local.HadesEngine().ollama_url,
            DEFAULT_OLLAMA_URL,
        )

    def test_dashboard_scan_environment_does_not_inherit_secrets(self):
        from hades_server import _build_scan_env

        env = _build_scan_env(
            {
                "PATH": "C:\\tools",
                "OLLAMA_API_KEY": "secret",
                "HADES_MODEL": "safe-model",
            }
        )
        self.assertEqual(env["PATH"], "C:\\tools")
        self.assertEqual(env["HADES_MODEL"], "safe-model")
        self.assertNotIn("OLLAMA_API_KEY", env)

    def test_versioned_modelfile_has_consultative_contract(self):
        modelfile = (
            Path(__file__).resolve().parents[1]
            / "Modelfile.hades-sentinel-analyst"
        ).read_text(encoding="utf-8")
        lowered = modelfile.lower()
        self.assertIn("FROM dolphin3:8b", modelfile.splitlines())
        self.assertIn(
            "sha256-1eee6953530837b2b17d61a4e6f71a5a"
            "a31c9714cfcf3cb141aa5c1972b5116b",
            modelfile,
        )
        self.assertNotIn("users", lowered)
        self.assertNotIn("FROM dolphin3:latest", modelfile)
        self.assertIn("PARAMETER num_ctx 8192", modelfile)
        self.assertIn("PARAMETER temperature 0", modelfile)
        self.assertIn("consultiva", lowered)
        self.assertIn("no modifica", lowered)
        for forbidden in (
            "sovereign",
            "lealtad absoluta",
            "haedes_cortex",
            "memory_nexus",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_consultative_output_is_visibly_labeled(self):
        rendered = format_consultative_output("Hallazgo inferido.")
        self.assertTrue(rendered.startswith(CONSULTATIVE_LABEL))
        self.assertIn(
            "COMENTARIO CONSULTIVO DE IA — NO VERIFICADO",
            rendered,
        )
        self.assertIn("no altera", rendered.lower())
        self.assertTrue(rendered.endswith("Hallazgo inferido."))

    def test_report_consumers_use_consultative_formatter(self):
        root = Path(__file__).resolve().parents[1]
        master_source = (root / "hades_win_master_advanced.py").read_text(
            encoding="utf-8"
        )
        surveillance_source = (
            root / "hades_surveillance_advanced.py"
        ).read_text(encoding="utf-8")
        self.assertIn("format_consultative_output(ai_out)", master_source)
        self.assertIn(
            "format_consultative_output(ia_trafico)",
            surveillance_source,
        )

    def test_external_tool_launchers_use_safe_environment(self):
        root = Path(__file__).resolve().parents[1]
        for filename in (
            "hades_local.py",
            "hades_mcp.py",
            "hades_win_master_advanced.py",
        ):
            with self.subTest(filename=filename):
                source = (root / filename).read_text(encoding="utf-8")
                self.assertIn("safe_subprocess_env", source)
                self.assertIn("env=safe_subprocess_env()", source)


if __name__ == "__main__":
    unittest.main()
