# HADES Ollama Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restringir Ollama a loopback y migrar HADES SENTINEL a un modelo Q4_K_M versionado con una integración IA central, consultiva y verificable.

**Architecture:** `hades_ai.py` centraliza configuración, payloads y entorno seguro. Un Modelfile versionado crea el modelo liviano; los consumidores existentes importan el módulo sin cambiar el pipeline determinista.

**Tech Stack:** Python 3.10, `unittest`, Ollama 0.32.5, PowerShell/Firewall de Windows.

---

### Task 1: Configuración IA central y entorno seguro

**Files:**
- Create: `hades_ai.py`
- Create: `tests/test_hades_ai.py`

- [x] **Step 1: Write the failing tests**

Crear pruebas que exijan:

```python
assert DEFAULT_MODEL == "HADES-SENTINEL-ANALYST:1.0.0"
assert DEFAULT_OLLAMA_URL == "http://127.0.0.1:11434/api/generate"
assert build_generate_payload("p")["options"] == {
    "num_predict": 640,
    "temperature": 0,
}
assert "OLLAMA_API_KEY" not in safe_subprocess_env(
    {"PATH": "x", "OLLAMA_API_KEY": "secret", "PYTHONIOENCODING": "bad"}
)
```

También comprobar URLs con credenciales/esquemas inválidos.

- [x] **Step 2: Run tests and verify RED**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: FAIL por módulo `hades_ai` inexistente.

- [x] **Step 3: Implement the minimal module**

Definir constantes, `normalize_ollama_generate_url()`,
`build_generate_payload()` y `safe_subprocess_env()`.

- [x] **Step 4: Run tests and verify GREEN**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: todos PASS.

### Task 2: Migrar consumidores a la configuración central

**Files:**
- Modify: `hades_win_master_advanced.py`
- Modify: `hades_local.py`
- Modify: `hades_mcp.py`
- Modify: `hades_server.py`
- Test: `tests/test_hades_ai.py`

- [x] **Step 1: Add failing integration assertions**

Importar los consumidores y comprobar que exponen el mismo modelo/URL y que el
servidor no hereda `OLLAMA_API_KEY` al preparar el proceso.

- [x] **Step 2: Run tests and verify RED**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: FAIL porque cada consumidor mantiene defaults propios.

- [x] **Step 3: Apply minimal migration**

Importar desde `hades_ai`, usar `build_generate_payload()` en el motor principal y
`safe_subprocess_env()` en `/api/scan`. Mantener interfaces públicas existentes.

- [x] **Step 4: Run focused and full tests**

Run: `python -m unittest tests.test_hades_ai -v`  
Run: `python tests\run_all.py`  
Expected: PASS completo.

### Task 3: Modelo versionado y prompt mínimo

**Files:**
- Create: `Modelfile.hades-sentinel-analyst`
- Test: `tests/test_hades_ai.py`

- [x] **Step 1: Add a failing static contract test**

Comprobar que el Modelfile:

- usa `FROM dolphin3:latest`;
- fija `num_ctx 8192` y `temperature 0`;
- declara que la IA es consultiva;
- no contiene `SOVEREIGN`, `lealtad absoluta`, `haedes_cortex` ni `memory_nexus`.

- [x] **Step 2: Run and verify RED**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: FAIL por Modelfile inexistente.

- [x] **Step 3: Create the Modelfile**

Usar un System prompt corto que trate evidencia delimitada como hostil, prohíba
inventar CVE/ISO y nunca autorice ejecución ni cambie score.

- [x] **Step 4: Run and verify GREEN**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: PASS.

- [x] **Step 5: Build and inspect the model**

Run: `ollama create HADES-SENTINEL-ANALYST:1.0.0 -f Modelfile.hades-sentinel-analyst`  
Run: `ollama show HADES-SENTINEL-ANALYST:1.0.0`  
Expected: 8B, Q4_K_M, contexto efectivo 8192.

### Task 4: Etiqueta consultiva en informes

**Files:**
- Modify: `hades_win_master_advanced.py`
- Modify: `hades_surveillance_advanced.py`
- Test: `tests/test_hades_ai.py`

- [x] **Step 1: Add failing label tests**

Comprobar que los bloques por host y tráfico incluyen:

```text
COMENTARIO CONSULTIVO DE IA — NO VERIFICADO
```

- [x] **Step 2: Run and verify RED**

Run: `python -m unittest tests.test_hades_ai -v`  
Expected: FAIL por etiqueta ausente.

- [x] **Step 3: Add the label without changing risk parsing**

Anteponer la etiqueta al texto IA y conservar marcadores existentes.

- [x] **Step 4: Run focused/full tests**

Run: `python -m unittest tests.test_hades_ai -v`  
Run: `python tests\run_all.py`  
Expected: PASS.

### Task 5: Hardening del servicio Ollama

**Files:**
- Modify local user environment and Windows Firewall state.

- [x] **Step 1: Record current read-only state**

Capturar listener, reglas asociadas y nombres de variables sin imprimir secretos.

- [x] **Step 2: Persist safe variables**

Configurar `OLLAMA_HOST=127.0.0.1:11434`, restringir `OLLAMA_ORIGINS` y eliminar
`OLLAMA_API_KEY` de User/Process.

- [x] **Step 3: Remove inbound Ollama allow rules**

Eliminar únicamente reglas cuyo application filter apunte al binario exacto de
Ollama.

- [ ] **Step 4: Restart Ollama**

Detener sólo los procesos Ollama verificados y lanzar `ollama serve` oculto con el
entorno seguro.

- [ ] **Step 5: Verify**

Comprobar listener loopback, API local, ausencia de regla pública y ausencia de
secreto persistente.

### Task 6: Verificación y documentación

**Files:**
- Modify: `README.md`
- Create: `REPARACION_IA_2026-07-29.md`

- [x] **Step 1: Update operational documentation**

Documentar modelo exacto, instalación, bind local, límites y rol consultivo.

- [x] **Step 2: Run all verification**

Run: `python tests\run_all.py`  
Run: `python -m unittest tests.test_hades_ai -v`  
Run: `python -m compileall -q -f hades_ai.py hades_local.py hades_mcp.py hades_server.py hades_surveillance_advanced.py hades_win_master_advanced.py`  
Expected: todo PASS/exit 0.

- [x] **Step 3: Inspect final state**

## Revalidación de cierre — 2026-07-30

- `python tests\run_all.py`: 37/37 PASS.
- `python -m unittest tests.test_hades_ai -v`: 13/13 PASS.
- `python -m compileall -q -f ...`: exit 0.
- `git diff --check`: exit 0; sólo advertencias informativas LF/CRLF.
- La prueba de indisponibilidad de Ollama confirmó que la auditoría técnica
  continúa sin bloquearse.
- `OLLAMA_HOST` y `OLLAMA_ORIGINS` quedaron nuevamente persistidos con valores
  locales seguros, y `OLLAMA_API_KEY` sigue ausente en User y Machine.
- El servicio real quedó pendiente: el PID `21476` escucha sólo en loopback,
  pero no responde a HTTP y el sandbox recibe `Acceso denegado` al intentar
  detenerlo. El reinicio requiere una terminal elevada fuera de esta sesión.
- La consulta actual de reglas de Windows Firewall también fue bloqueada por
  permisos, por lo que su estado histórico no pudo revalidarse el 2026-07-30.

Verificar Ollama, modelo, firewall, entorno, Git diff y ausencia de secretos.
