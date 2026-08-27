# Ollama Runtime Resiliente Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir recuperación conservadora de Ollama sin matar procesos ajenos,
elevar privilegios ni bloquear el pipeline determinista de HADES.

**Architecture:** Un nuevo módulo `hades_ollama_runtime.py` encapsula health
check, validación loopback, detección de puerto, resolución del binario y
arranque de un único proceso propio. `hades_server.py` y `hades_local.py`
consumen un resultado estructurado y degradan sin IA ante cualquier fallo.

**Tech Stack:** Python 3.10, biblioteca estándar, `unittest`, Ollama local.

**Nota del entorno:** `.git` es de sólo lectura en esta sesión; los pasos de
commit se documentan pero no se ejecutarán.

---

### Task 1: Contrato y runtime conservador

**Files:**
- Create: `hades_ollama_runtime.py`
- Create: `tests/test_hades_ollama_runtime.py`

- [x] **Step 1: Escribir pruebas RED del contrato**

Crear casos `unittest` que inyecten las dependencias de red, puerto, binario,
proceso y reloj. Las pruebas deben exigir:

```python
status = ensure_ollama_available(
    probe=lambda _: {"version": "0.32.5"},
    port_busy=lambda *_: True,
)
self.assertEqual(status.state, "healthy")
```

```python
status = ensure_ollama_available(
    probe=failing_probe,
    port_busy=lambda *_: True,
)
self.assertEqual(status.state, "blocked_stale_listener")
self.assertEqual(spawn_calls, [])
```

```python
status = ensure_ollama_available(
    probe=eventual_probe,
    port_busy=lambda *_: False,
    resolve_binary=lambda: valid_ollama_path,
    spawn=recording_spawn,
    monotonic=fake_clock,
    wait=fake_wait,
)
self.assertEqual(status.state, "started")
self.assertNotIn("OLLAMA_API_KEY", captured_env)
```

También probar `disabled`, `missing_binary`, `unsupported_endpoint`,
`startup_failed`, ausencia de `shell=True` y redacción de secretos.

- [x] **Step 2: Ejecutar RED**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime -v
```

Expected: `ModuleNotFoundError: No module named 'hades_ollama_runtime'`.

- [x] **Step 3: Implementar el módulo mínimo**

Crear:

```python
@dataclass(frozen=True)
class OllamaRuntimeStatus:
    state: str
    detail: str
    pid: Optional[int] = None
    version: Optional[str] = None
```

Implementar `ensure_ollama_available()` con estas ramas, en orden:

1. `HADES_SKIP_AI=1` → `disabled`;
2. endpoint distinto de `http://127.0.0.1:11434` → `unsupported_endpoint`;
3. `/api/version` responde → `healthy`;
4. puerto ocupado → `blocked_stale_listener`;
5. binario ausente → `missing_binary`;
6. iniciar `ollama serve` con `safe_subprocess_env()` ampliado;
7. esperar por condición hasta respuesta, salida del proceso o timeout.

El arranque debe usar:

```python
subprocess.Popen(
    [str(binary), "serve"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env=env,
    creationflags=creationflags,
)
```

No implementar búsqueda recursiva, terminación de PIDs externos, UAC, firewall
ni reintentos infinitos.

- [x] **Step 4: Ejecutar GREEN**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime -v
```

Expected: todos los casos PASS.

### Task 2: Integración no bloqueante

**Files:**
- Modify: `hades_server.py`
- Modify: `hades_local.py`
- Modify: `tests/test_hades_ollama_runtime.py`
- Modify: `tests/test_hades_ai.py`

- [x] **Step 1: Escribir pruebas RED de integración**

Exigir que:

```python
self.assertIn("runtime_state", hades_server.ollama_metrics)
```

```python
engine = HadesEngine(ensure_runtime=fake_ensure)
engine._ensure_ai_runtime()
self.assertEqual(fake_ensure.calls, 1)
engine._ensure_ai_runtime()
self.assertEqual(fake_ensure.calls, 1)
```

El falso runtime debe demostrar que `blocked_stale_listener` no lanza excepción
ni cambia la capacidad del motor para ejecutar herramientas deterministas.

- [x] **Step 2: Ejecutar RED**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime tests.test_hades_ai -v
```

Expected: fallos por integración aún inexistente.

- [x] **Step 3: Integrar servidor y CLI**

En `hades_server.py`, ejecutar el chequeo una vez antes de crear los hilos:

```python
ollama_runtime_status = ensure_ollama_available()
ollama_metrics["runtime_state"] = ollama_runtime_status.state
ollama_metrics["runtime_detail"] = ollama_runtime_status.detail
```

Preservar esos campos en cada snapshot de `monitor_ollama()`.

En `hades_local.py`, aceptar `ensure_runtime` opcional en `HadesEngine`, cachear
el resultado y llamarlo únicamente al entrar en `_ask()`. Si el estado no es
`healthy` o `started`, devolver `None` usando el flujo de degradación existente.

- [x] **Step 4: Ejecutar GREEN de integración**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime tests.test_hades_ai -v
```

Expected: todos PASS.

### Task 3: Documentación, seguridad y regresión

**Files:**
- Modify: `README.md`
- Modify: `REPARACION_IA_2026-07-29.md`
- Modify: `docs/superpowers/plans/2026-07-30-ollama-runtime-resiliente.md`

- [x] **Step 1: Documentar estados y límites**

Añadir al README los siete estados, la ausencia de elevación/kill/firewall y el
comportamiento de degradación segura.

- [x] **Step 2: Revisar seguridad**

Confirmar estáticamente en el nuevo runtime y sus puntos de integración:

- sólo loopback;
- argumentos como lista y `shell=False` implícito;
- entorno allowlist sin claves;
- ninguna llamada a `taskkill`, `Stop-Process`, `os.kill` o firewall;
- errores sin secretos;
- LLM consultivo, sin autoridad de riesgo.

- [x] **Step 3: Ejecutar verificación completa**

Run:

```powershell
python tests\run_all.py
python -m unittest tests.test_hades_ollama_runtime -v
python -m compileall -q -f hades_ollama_runtime.py hades_ai.py hades_local.py hades_server.py
git diff --check
```

Expected: exit 0 y cero fallos.

- [x] **Step 4: Registrar bloqueo de commit**

No ejecutar `git add`, `git commit` ni `git push` mientras `.git` permanezca en
modo lectura. Informar el bloqueo sin mezclar cambios previos del usuario.

## Resultado de ejecución — 2026-07-30

- Ciclos RED observados antes de crear runtime, integración y arranque diferido
  de monitores.
- `python tests\run_all.py`: 48/48 PASS.
- `python -m unittest tests.test_hades_ollama_runtime -v`: 11/11 PASS.
- `python -m compileall`: exit 0.
- `git diff --check`: exit 0; sólo avisos informativos LF/CRLF.
- Runtime real: `healthy`, Ollama `0.32.5`.
- Modelo real: `HADES-SENTINEL-ANALYST:1.0.0`, 8B, Q4_K_M,
  `num_ctx=8192`, `num_predict=640`, `temperature=0`.
- CORS operativo: origen local permitido; `https://evil.example` rechazado con
  HTTP 403.
- Commit no creado: `.git/index.lock` permanece sin permiso de escritura.
