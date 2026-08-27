# HADES SENTINEL — Preparación para producción

Auditoría iniciada el 2026-07-25. Objetivo: dejar el agente en condiciones de
salir a producción. Este documento es el registro vivo del progreso.

**Estado global: NO APTO PARA PRODUCCIÓN** — auditoría en curso.

---

## Resumen ejecutivo

| Área | Estado | Detalle |
|---|---|---|
| Suite de pruebas | 🟢 Corregida | `python tests/run_all.py` → **24/24 casos**, exit code verificado |
| Fase 4 del pipeline | 🟢 Corregida | Bug de bloqueo por IA resuelto y verificado (PR #1) |
| Dependencias | 🟢 Corregida | El runner unificado no necesita pytest; docs actualizadas |
| Scripts de operación | 🟢 Corregida | `DETENER_HADES.bat` reescrito y verificado end-to-end |
| Seguridad | ⏳ Pendiente | Auditoría delegada en curso |
| Calidad de código | ⏳ Pendiente | Auditoría delegada en curso |
| Documentación operativa | 🔴 Falla | El README no documenta cómo verificar la build (H-06) |

---

## Hallazgos

### H-01 · Suite de pruebas fragmentada en dos runners incompatibles · P1
**Estado:** ABIERTO

`tests/test_hades_sentinel.py` (13 casos) está escrito en estilo **pytest**:
funciones sueltas `test_*` con `assert`. `python -m unittest discover -s tests`
**no las descubre** — unittest solo reconoce clases `TestCase`. Los tests nuevos
(`test_fase4_ia_no_bloquea.py`, `test_grounding_ia.py`, 11 casos) sí son unittest.

Resultado medido:
- `python -m unittest discover -s tests` → 11 tests OK (**se pierde 13 en silencio**)
- `python tests/test_hades_sentinel.py` → 13 PASS / 0 FAIL
- No existe un comando que ejecute los 24.

**Por qué bloquea producción:** quien verifique la build con el comando estándar
obtiene un "OK" que no cubre la mitad de la suite. Un fallo en los 13 casos de
seguridad/integración (SEC-02, SEC-07, SEC-08, SEC-09, INT-01…) pasaría inadvertido.

### H-02 · `pytest` no declarado ni instalado · P2
**Estado:** ABIERTO

El docstring de la suite indica `python -m pytest tests/...` como forma de
ejecución, pero `pytest` no está en `requirements.txt` ni instalado en el
entorno (`No module named pytest`). La vía documentada no funciona.

### H-03 · `DETENER_HADES.bat` invoca un script inexistente · P2
**Estado:** ABIERTO

El `.bat` llama a `DETENER_HADES.ps1`, eliminado a propósito en el commit
`69f6ce8`. El script de parada de emergencia documentado **no hace nada**.
El cierre limpio depende hoy de `/api/stop` o de matar procesos a mano.

### H-04 · Herramienta `nikto` declarada pero ausente · P3
**Estado:** ABIERTO

El propio status del agente reporta `Tools Missing: nikto`. Hay que decidir:
instalarla, o retirarla de la lista de herramientas esperadas.

### H-05 · Árbol de trabajo con cambios sin commitear · P3
**Estado:** ABIERTO

13 archivos modificados y 2 borrados sin commitear (README, .gitignore,
`hades_server.py`, `agente HADES.html`, borrado de `auth.html` y `hades_auth.py`).
El repo publicado y el código local divergen: no se sabe qué versión es "la buena".

---

### H-06 · El README no documenta cómo verificar la build · P2
**Estado:** ABIERTO

`README.md` no menciona los tests ni cómo ejecutarlos. Un operador que reciba el
repo no tiene forma de saber si su instalación funciona.

---

## Correcciones aplicadas

### C-01 → cierra H-01 y H-02 · Runner único de la suite
`tests/run_all.py` ejecuta los dos estilos de test sin depender de pytest, para
que el agente pueda verificarse también en una red aislada (su propio caso de uso).

**Verificado:**
- `python tests/run_all.py` → `TOTAL: 24/24 casos OK`, exit code **0**
- Con un test canario que falla a propósito → exit code **1** (no da falsos verdes)
- Si `test_hades_sentinel.py` no se pudiera importar, se cuenta como fallo en vez
  de desaparecer en silencio, que era la raíz del problema.

También se corrigió el docstring de la suite, que dirigía a `pytest` (no instalado).

### C-02 → cierra H-03 · Script de parada funcional
`DETENER_HADES.bat` reescrito con el cierre embebido, sin depender de ficheros
externos. Secuencia: parada elegante por `/api/stop` → terminación del árbol del
proceso que ocupa el 8080 → herramientas de escaneo huérfanas → borrado del token
→ **verificación con código de salida**. Mata solo el proceso del puerto y sus
hijos, nunca `taskkill /im python.exe`.

**Verificado end-to-end:** agente levantado (PID 26268, puerto escuchando) →
`.bat` ejecutado → exit code 0, puerto libre, 0 procesos de escaneo, token borrado,
proceso terminado.

---

## Bitácora

| Fecha | Iteración | Acción |
|---|---|---|
| 2026-07-25 | 1 | Inventario y suite. 6 hallazgos. **H-01, H-02 y H-03 cerrados y verificados**. Auditoría de seguridad delegada a Codex. |
| 2026-07-26 | 2 | Llega la auditoría de Codex (3,0M tokens, `AUDITORIA_CODEX.md`): **NO APTO**, 2 hallazgos ALTA + 6 MEDIA + 6 de robustez. Reparación de P0/P1 **delegada a Codex**; el loop se detiene aquí por decisión del usuario. |

---

## Auditoría externa (Codex) — veredicto NO APTO

Informe completo con archivo y línea en `AUDITORIA_CODEX.md`. Lo esencial:

| ID | Sev | Hallazgo |
|---|---|---|
| S-01 | **ALTA** | El fallback estático sirve **toda la raíz** sin pasar por `_request_allowed()`. Una web maliciosa con DNS rebinding puede leer `informes/`, fuentes, logs y `.git`: IPs, MAC, servicios y vulnerabilidades de la red auditada. |
| S-02 | **ALTA** | `_parse_host_block()` extrae CVE del bloque completo, **incluida la respuesta de la IA**. Un CVE inventado por el modelo (o un banner de un host hostil) sube la severidad de BAJO a ALTO. Rompe el principio de IA consultiva. |
| S-03 | MEDIA | Los validadores rechazan metacaracteres pero aceptan **inyección de argumentos** (`--help`, `-oNloot`) e IP/CIDR inválidos (`999.999.999.999`, `/99`). |
| S-05 | MEDIA | `_read_json_body()` es fail-open: sin límite de tamaño, sin `Content-Type`, y un cuerpo inválido **inicia un escaneo** en vez de fallar. |
| S-06 | MEDIA | Resolución de binarios por `shutil.which()`: secuestro por PATH, sin verificación de integridad. |
| S-07 | MEDIA | Informes sensibles sin ACL, cifrado ni retención. |
| R-01 | MEDIA | Carrera en `/api/scan`: dos POST concurrentes pueden lanzar dos agentes sobre el mismo directorio de informe. |
| R-02 | MEDIA | `taskkill` no verifica `returncode`: puede dejar Nmap/Tshark/Nuclei huérfanos tras "detener". |
| R-03 | MEDIA | `log_buffer` y las salidas de herramientas crecen **sin cota** en memoria. |

Bien resueltos según la auditoría: bind solo a loopback IPv4, guardia same-origin de las
APIs (CSRF y rebinding en `/api/*` sí se bloquean), sin CORS, lanzamiento del hijo con
`Popen([...])` sin shell, y el control determinista que avisa de CVE inventados.

**Nota de método:** la verificación activa de S-01 y S-02 quedó sin ejecutar. Los
hallazgos vienen del análisis de Codex con línea exacta y de sus pruebas dirigidas
(reportó haber reproducido `sin_cve → BAJO` / `ia_inventa → ALTO`), pero **no los
confirmé yo con un ataque real** contra el servidor levantado. Conviene hacerlo antes
de dar por cerrado cualquiera de los dos.

---

## Traspaso a Codex (2026-07-26)

Reparación de P0/P1 delegada a Codex reusando la sesión de su propia auditoría
(`019f9c3d-8187-7c02-8719-067535262e50`), con este alcance:

1. **P0-1 (S-01)** — guardia en todo GET/HEAD, `do_HEAD` explícito, allowlist de assets,
   bloqueo de listados, dotfiles, `informes/`, `*.log`, `*.py` y symlinks.
2. **P0-2 (S-02)** — extraer CVE solo de `[NMAP]` y `[NUCLEI]`, nunca de la sección IA;
   `cves_confirmados` separado de `texto_ia`; `_assess_risk()` puntúa solo lo confirmado.
3. **P1 (S-03)** — `ipaddress` en vez de regex, rechazar valores que empiecen con `-`,
   en los tres módulos duplicados.
4. **P1 (S-05)** — límite de cuerpo 8 KiB, `Content-Type` exigido, esquema estricto
   (`duration` 5-300), códigos 4xx explícitos, 404 en rutas POST desconocidas.
5. **P1 (R-01, R-02)** — arranque serializado con `Lock`, verificación real de la
   terminación del árbol de procesos.

Condiciones dadas: la suite debe seguir en verde (`python tests/run_all.py` → 24/24),
una prueba de regresión por arreglo en `tests/test_produccion_p0_p1.py`, fixtures
sintéticos (el repo es público), sin commit ni push, y entregable `REPARACIONES_CODEX.md`.
