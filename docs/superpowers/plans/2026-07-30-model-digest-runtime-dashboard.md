# Model Digest and Runtime Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fijar en la workstation actual el modelo base de Ollama por digest y
mostrar el diagnóstico real del runtime en el panel de IA.

**Architecture:** El Modelfile apuntará al blob inmutable ya presente y
verificado en el almacén local de Ollama. El backend conservará su contrato
actual `/api/ollama`; el frontend convertirá `runtime_state` y `runtime_detail`
en una línea de estado segura mediante `textContent`, sin crear otro endpoint ni
dar autoridad decisoria al LLM.

**Tech Stack:** Ollama 0.32.5, Modelfile, Python 3.10 `unittest`, HTML/CSS/JS
autocontenido.

**Restricción de ejecución:** El árbol actual contiene cambios previos. Sólo se
agregarán al staging los archivos enumerados en este plan. No se hará `push`.
La ruta del blob es workstation-only para `%USERPROFILE%`; otra cuenta
deberá materializar el mismo SHA-256 y regenerar el `FROM`.

---

### Task 1: Fijar el blob del modelo base

**Files:**
- Modify: `tests/test_hades_ai.py`
- Modify: `Modelfile.hades-sentinel-analyst`

- [ ] **Step 1: Escribir la prueba RED del digest**

Cambiar `test_versioned_modelfile_has_consultative_contract` para exigir:

```python
expected_base = (
    r"FROM %USERPROFILE%\.ollama\models\blobs"
    r"\sha256-1eee6953530837b2b17d61a4e6f71a5a"
    "a31c9714cfcf3cb141aa5c1972b5116b"
)
self.assertEqual(modelfile.splitlines()[0], expected_base)
self.assertNotIn("FROM dolphin3:latest", modelfile)
```

Mantener todas las aserciones del contrato consultivo.

- [ ] **Step 2: Ejecutar la prueba para verificar RED**

Run:

```powershell
python -m unittest tests.test_hades_ai.HadesAIConfigurationTests.test_versioned_modelfile_has_consultative_contract -v
```

Expected: `FAIL` porque el Modelfile todavía contiene
`FROM dolphin3:latest`.

- [ ] **Step 3: Aplicar la referencia inmutable mínima**

Sustituir la primera línea por la referencia que emitió Ollama 0.32.5 mediante
`ollama show dolphin3:latest --modelfile`:

```text
FROM %USERPROFILE%\.ollama\models\blobs\sha256-1eee6953530837b2b17d61a4e6f71a5aa31c9714cfcf3cb141aa5c1972b5116b
```

- [ ] **Step 4: Verificar GREEN y validar con Ollama**

Run:

```powershell
python -m unittest tests.test_hades_ai.HadesAIConfigurationTests.test_versioned_modelfile_has_consultative_contract -v
ollama create HADES-SENTINEL-ANALYST:1.0.0 -f Modelfile.hades-sentinel-analyst
ollama show HADES-SENTINEL-ANALYST:1.0.0 --modelfile
```

Expected: prueba `OK`, creación exitosa y salida `FROM` resuelta al mismo blob,
sin depender de `latest`. Si Ollama no está disponible, registrar el bloqueo y
no sustituir esa validación por una afirmación.

### Task 2: Mostrar `runtime_state` y `runtime_detail`

**Files:**
- Modify: `tests/test_hades_ollama_runtime.py`
- Modify: `agente HADES.html`

- [ ] **Step 1: Escribir pruebas RED del contrato visual seguro**

Añadir a `OllamaRuntimeIntegrationTests`:

```python
def test_dashboard_renders_runtime_state_and_detail_safely(self):
    dashboard = (
        Path(__file__).resolve().parents[1] / "agente HADES.html"
    ).read_text(encoding="utf-8")

    self.assertIn('id="aiRuntimeState"', dashboard)
    self.assertIn('id="aiRuntimeDetail"', dashboard)
    self.assertIn("runtime_state", dashboard)
    self.assertIn("runtime_detail", dashboard)
    self.assertIn("aiRuntimeDetail.textContent", dashboard)
    self.assertIn("blocked_stale_listener", dashboard)
    self.assertIn("missing_binary", dashboard)
    self.assertIn("startup_failed", dashboard)
```

Importar `Path` desde `pathlib` al inicio del archivo.

- [ ] **Step 2: Ejecutar la prueba para verificar RED**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime.OllamaRuntimeIntegrationTests.test_dashboard_renders_runtime_state_and_detail_safely -v
```

Expected: `FAIL` porque los elementos del runtime todavía no existen.

- [ ] **Step 3: Añadir presentación accesible al panel existente**

En la línea de estado del panel, añadir dos spans:

```html
<span id="aiRuntimeState">NO COMPROBADO</span>
<span id="aiRuntimeDetail">Runtime de Ollama aún no evaluado.</span>
```

Crear referencias DOM `aiRuntimeState` y `aiRuntimeDetail`. Añadir un mapa
constante para:

```javascript
const AI_RUNTIME_STATES = {
    healthy: ['DISPONIBLE', 'healthy'],
    started: ['INICIADO POR HADES', 'healthy'],
    disabled: ['DESHABILITADO', 'warning'],
    unsupported_endpoint: ['ENDPOINT NO ADMITIDO', 'error'],
    blocked_stale_listener: ['PUERTO BLOQUEADO', 'error'],
    missing_binary: ['OLLAMA NO INSTALADO', 'error'],
    startup_failed: ['FALLO DE ARRANQUE', 'error'],
    not_checked: ['NO COMPROBADO', 'warning'],
};
```

Implementar `applyOllamaRuntimeState(d)` con fallback
`['ESTADO DESCONOCIDO', 'warning']`. Asignar siempre estado y detalle con
`textContent`, nunca con `innerHTML`, y llamarla al inicio de
`applyOllamaSnapshot(d)`, antes del retorno por desconexión.

- [ ] **Step 4: Verificar GREEN**

Run:

```powershell
python -m unittest tests.test_hades_ollama_runtime -v
```

Expected: todos los casos `OK`.

### Task 3: Seguridad, claridad y regresión

**Files:**
- Review: `Modelfile.hades-sentinel-analyst`
- Review: `agente HADES.html`
- Review: `tests/test_hades_ai.py`
- Review: `tests/test_hades_ollama_runtime.py`

- [ ] **Step 1: Revisar fronteras de seguridad**

Confirmar:

```text
- no queda FROM dolphin3:latest;
- el nombre del blob termina en exactamente 64 caracteres hexadecimales;
- runtime_detail sólo llega a textContent;
- no se añade innerHTML con datos del backend;
- el estado no cambia score, severidad, CVE ni alcance;
- no se añaden endpoints, secretos, shell=True ni procesos decisorios del LLM.
```

- [ ] **Step 2: Simplificar sólo el código tocado**

Eliminar duplicación o ramas innecesarias en el mapeo del frontend sin cambiar
comportamiento. No reformatear el HTML completo ni refactorizar archivos ajenos.

- [ ] **Step 3: Ejecutar verificación completa**

Run:

```powershell
python tests\run_all.py
python -m unittest tests.test_hades_ai tests.test_hades_ollama_runtime -v
python -m compileall -q -f hades_ai.py hades_ollama_runtime.py hades_server.py
git diff --check
```

Expected: código cero y cero fallos.

### Task 4: Revisión y commit local acotado

**Files:**
- Add: `Modelfile.hades-sentinel-analyst`
- Add: `agente HADES.html`
- Add: `tests/test_hades_ai.py`
- Add: `tests/test_hades_ollama_runtime.py`
- Add: `docs/superpowers/specs/2026-07-30-model-digest-runtime-dashboard-design.md`
- Add: `docs/superpowers/plans/2026-07-30-model-digest-runtime-dashboard.md`

- [ ] **Step 1: Revisar el diff exacto**

Run:

```powershell
git diff -- Modelfile.hades-sentinel-analyst "agente HADES.html" tests/test_hades_ai.py tests/test_hades_ollama_runtime.py
git status --short
```

Expected: el diff revisado contiene sólo digest, runtime UI y pruebas; los demás
cambios permanecen sin staged.

- [ ] **Step 2: Agregar únicamente los archivos y hunks aprobados**

Run:

```powershell
git add -- Modelfile.hades-sentinel-analyst tests/test_hades_ai.py tests/test_hades_ollama_runtime.py docs/superpowers/specs/2026-07-30-model-digest-runtime-dashboard-design.md docs/superpowers/plans/2026-07-30-model-digest-runtime-dashboard.md
git add -p -- "agente HADES.html"
git diff --cached --check
git diff --cached --stat
```

En el selector interactivo de `agente HADES.html`, aceptar sólo los hunks de
`.ai-status-copy`, `aiRuntimeState`, `AI_RUNTIME_STATES`,
`applyOllamaRuntimeState` y su llamada. Rechazar los hunks previos de
auth/token/fetch.

Expected: código cero; ningún archivo ni hunk fuera del alcance aparece staged.

- [ ] **Step 3: Crear el commit**

Run:

```powershell
git commit -m "feat: fijar modelo base y mostrar estado de Ollama"
```

Expected: commit local creado. No ejecutar `git push`.

## Resultado de ejecución — 2026-07-30

- Ciclo RED→GREEN observado para la referencia inmutable del Modelfile.
- Ciclo RED→GREEN observado para `runtime_state` y `runtime_detail`.
- Ollama real verificado en versión `0.32.5`.
- `ollama show HADES-SENTINEL-ANALYST:1.0.0 --modelfile` ya resuelve al blob
  `sha256-1eee6953530837b2b17d61a4e6f71a5aa31c9714cfcf3cb141aa5c1972b5116b`.
- La reconstrucción por CLI no pudo reescribir el almacén `.ollama` externo al
  workspace: `Access is denied`. El contenido y el blob sí son legibles.
- QA visual en navegador bloqueado por la política local para
  `http://127.0.0.1:8080`; el servidor temporal se cerró después del intento.
- `python tests\run_all.py`: `49/49` casos OK.
- Regresiones específicas: `25/25` casos OK.
- `compileall`: código cero.
- Script inline del dashboard: sintaxis válida.
- Revisión estática: `runtime_detail` usa `textContent`, no `innerHTML`.
- `git diff --check`: código cero; sólo avisos informativos LF/CRLF.
- Commit pendiente de la comprobación final de permisos sobre `.git`.
