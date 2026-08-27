# Auditoría de código — HADES SENTINEL

**Fecha:** 2026-07-29  
**Alcance:** estado actual del working tree de `HADES SENTINEL`  
**Modalidad:** revisión estática defensiva + ejecución de pruebas locales, sin escaneos reales de red  
**Dictamen:** **NO APTO PARA PRODUCCIÓN / INFORMES A CLIENTES** hasta corregir P0 y P1.

## Resumen ejecutivo

El agente contiene varias mejoras de seguridad reales: escucha únicamente en loopback, valida objetivos, limita los cuerpos HTTP, ejecuta el proceso principal con una lista de argumentos, separa la evidencia técnica del texto del LLM y calcula el riesgo ejecutivo mediante una heurística determinista. La suite existente pasa completa.

Sin embargo, el generador DOCX inserta una metodología ofensiva fija que afirma que se comprometieron credenciales, se obtuvo acceso, se desplegó Meterpreter, se implantó persistencia y luego se erradicó. Ninguna de esas acciones forma parte del pipeline implementado. Esto convierte el informe en evidencia técnicamente falsa y puede generar consecuencias contractuales, legales y de compliance. Es el bloqueo principal.

También existen riesgos operacionales importantes: el script de parada mata globalmente herramientas de terceros por nombre, varias rutas de ejecución conservan `shell=True`, la UI inserta logs mediante `innerHTML`, dos auditorías iniciadas en el mismo minuto pueden compartir y sobrescribir el mismo directorio, y el cierre por señal no descarga los modelos de Ollama aunque el código lo promete.

## Verificación realizada

- `python tests\run_all.py`: **24/24 PASS**.
- `python -m compileall` sobre los ocho módulos Python principales: **OK**.
- Analizadores adicionales: `bandit`, `ruff` y `semgrep` no están instalados.
- No se realizaron escaneos Nmap/Nuclei/Tshark contra redes ni objetivos.
- El repositorio estaba sucio antes de la auditoría: múltiples archivos modificados/eliminados y archivos nuevos sin versionar. No se alteró código fuente.

## Hallazgos

### P0-01 — El informe ejecutivo afirma intrusiones y acciones que nunca ocurrieron

**Severidad:** Crítica  
**Categoría:** integridad de evidencia, compliance, confianza humano-agente  
**Archivos:** `hades_report_docx.py:435-465`, `hades_report_docx.py:757-767`

La constante `PHASES` contiene afirmaciones fijas:

- `Metasploit ssh_login`
- `Registro de la credencial comprometida`
- `Sesión vía ssh_login`
- `Payload msfvenom + multi/handler`
- `Ejecución remota y sesión Meterpreter`
- `Múltiples mecanismos de persistencia y malware implantado`
- `Eliminación de todos los artefactos`

El pipeline real ejecuta descubrimiento, Nmap, Tshark, Nuclei, OpenSSL, análisis consultivo de Ollama y generación de informes. No ejecuta Metasploit, fuerza bruta, explotación, payloads, persistencia ni erradicación. No existe código que produzca evidencia para esas afirmaciones.

`build_iso27001_docx()` recorre siempre `PHASES` y presenta cada entrada como “Método / Hallazgo / Acción / Mitigación”. Por lo tanto, cualquier DOCX generado afirma actividades no realizadas, incluso en una red sin esos hallazgos.

**Impacto:** falsificación involuntaria del alcance y resultados de un pentest; decisiones ejecutivas basadas en hechos inexistentes; posible incumplimiento contractual; pérdida de trazabilidad ISO 27001; riesgo legal si el documento se entrega a un cliente o auditor.

**Remediación obligatoria:**

1. Eliminar las afirmaciones fijas de explotación.
2. Construir las fases exclusivamente desde eventos/evidencias estructuradas producidas por las herramientas.
3. Para toda fase no ejecutada, imprimir explícitamente `NO EJECUTADA — fuera del alcance`.
4. Etiquetar por separado: `Observado`, `Inferido por heurística`, `Comentario consultivo de IA`.
5. Agregar una prueba que genere un DOCX desde un escaneo vacío y compruebe que no aparecen `Metasploit`, `Meterpreter`, `credencial comprometida`, `malware implantado` ni `persistencia`.

### P1-02 — El script de parada mata procesos ajenos al agente

**Severidad:** Alta  
**Categoría:** disponibilidad, alcance destructivo  
**Archivo:** `DETENER_HADES.bat:28-33`

Después de terminar el proceso que escucha en 8080, el script ejecuta `Get-Process -Name` y `Stop-Process -Force` para todos los procesos llamados `nmap`, `tshark`, `dumpcap`, `nuclei` y `openssl`.

Esto no distingue descendientes de HADES de herramientas iniciadas por el usuario, otro agente, Wireshark u otra auditoría. Puede destruir capturas o escaneos independientes y perder evidencia.

**Remediación:**

- Eliminar la terminación global por nombre.
- Mantener un PID raíz y terminar únicamente su árbol verificado.
- En Windows, preferir un Job Object con `KILL_ON_JOB_CLOSE` o el mecanismo ya encapsulado en `hades_processes.py`.
- Si se necesita recuperación de huérfanos, registrar PIDs y tiempos de inicio firmados por la propia ejecución; no inferir propiedad por nombre.

### P1-03 — Ejecución de comandos con `shell=True` y parámetros componibles

**Severidad:** Alta en superficies de automatización; Media en uso local controlado  
**Categoría:** CWE-78 / OWASP A05 Injection / ASI02 Tool Misuse  
**Archivos:** `hades_win_master_advanced.py:102-116`, `hades_win_master_advanced.py:226-242`, `hades_mcp.py:41-69`, `hades_local.py:91-94`

El ejecutor principal y los adaptadores CLI/MCP construyen strings y los entregan al shell. La validación actual bloquea metacaracteres en objetivos normales, lo cual reduce el riesgo, pero no elimina el patrón peligroso:

- `HADES_NMAP_HOST_TIMEOUT` se incorpora a `flags` sin una validación estricta.
- `nmap_scan(ip, flags=...)` acepta un string de flags arbitrario.
- `run_tool(tool, args)` es una API genérica que vuelve a concatenar argumentos.
- Un futuro método MCP o refactor puede reutilizar estos ejecutores sin pasar por `validate_target`.

**Remediación:**

- Cambiar todos los ejecutores a listas de argumentos y `shell=False`.
- Reemplazar el pipe `echo | openssl` por entrada vía `stdin`.
- Convertir los flags configurables en campos tipados y allowlists.
- Validar `HADES_NMAP_HOST_TIMEOUT` con una expresión estricta como `^\d+(?:ms|s|m)?$` y límites mínimos/máximos.
- No exponer una API genérica `run_tool(tool, args_string)` a agentes; usar herramientas específicas con esquemas cerrados.

### P1-04 — Sinks DOM XSS en la consola y el widget de eventos

**Severidad:** Media-Alta  
**Categoría:** CWE-79 / OWASP A05 Injection  
**Archivo:** `agente HADES.html:1467-1479`, `agente HADES.html:1712-1718`

`pushLswLine()` interpola `message` dentro de `line.innerHTML`. `logToConsole()` concatena el mensaje directamente en `consoleLog.innerHTML`.

Los mensajes proceden del backend y del stdout de herramientas/subprocesos. Hoy gran parte de los logs normales son textos internos o valores validados, pero el diseño no mantiene esa garantía: errores de herramientas, nombres de interfaz, banners, futuras salidas de Nmap/Nuclei o mensajes del LLM pueden contener HTML. El dashboard tiene capacidad para iniciar y detener escaneos desde su mismo origen, por lo que ejecutar JavaScript allí rompe la frontera de confianza.

**Remediación:**

- Usar `textContent` o nodos de texto para todo mensaje.
- Crear por separado los elementos `span` y asignar `textContent`.
- Añadir una prueba con `<img src=x onerror=...>` y verificar que se visualiza literalmente, sin crear nodos.
- Añadir CSP compatible con la aplicación; idealmente mover el JavaScript inline a un asset local y usar `script-src 'self'`.

### P1-05 — Colisión y sobreescritura de informes dentro del mismo minuto

**Severidad:** Media-Alta  
**Categoría:** integridad y pérdida de evidencia  
**Archivo:** `hades_surveillance_advanced.py:136-146`

El directorio se llama `informe_%Y%m%d_%H%M` y se crea con `exist_ok=True`. Dos auditorías iniciadas durante el mismo minuto escriben el mismo `INFORME_MAESTRO.md`, `trafico_red.txt` y DOCX. El servidor evita concurrencia, pero permite iniciar otra corrida inmediatamente después de terminar la anterior.

**Remediación:**

- Incluir segundos y un sufijo aleatorio/UUID: `%Y%m%d_%H%M%S_<run_id>`.
- Crear con `exist_ok=False` y reintentar ante colisión.
- Escribir primero a archivo temporal y reemplazar atómicamente.
- Incluir `run_id`, objetivo y hash de evidencia en el informe.

### P1-06 — El cierre por señal no libera Ollama como promete

**Severidad:** Media  
**Categoría:** disponibilidad/recursos, comportamiento inconsistente  
**Archivo:** `hades_server.py:74-150`

El comentario establece que al cerrar el servidor no debe quedar nada ejecutándose, y `_unload_ollama_models()` dice que se llama durante la parada de emergencia. Sin embargo, `_emergency_cleanup()` sólo invoca `_kill_active_tree()`. La descarga de modelos ocurre en `/api/stop`, pero no necesariamente ante `SIGINT`, `SIGTERM`, cierre de consola o `atexit`.

**Impacto:** RAM/VRAM puede seguir ocupada después de cerrar HADES; la documentación y los logs crean una garantía falsa.

**Remediación:**

- Invocar `_unload_ollama_models()` dentro de `_emergency_cleanup()` después de terminar el árbol.
- Separar idempotencia por recurso o garantizar que el único lock cubra ambos pasos.
- Añadir pruebas de `SIGINT`/`atexit` con HTTP simulado.

### P1-07 — `/api/logs` usa GET destructivo y un buffer global sin sincronización

**Severidad:** Media  
**Categoría:** integridad, concurrencia, CSRF parcial  
**Archivo:** `hades_server.py:369-370`, `hades_server.py:591-605`, `hades_server.py:631-637`

Cada GET de `/api/logs` devuelve y luego vacía el buffer. La guardia acepta peticiones sin `Origin`; una carga de recurso/navegación hacia loopback puede llegar sin ese header y drenar logs aunque la política del navegador impida leer la respuesta. Además, `add_log()` agrega sin lock mientras el handler reemplaza la lista completa, por lo que existe una carrera y pueden perderse eventos.

**Remediación:**

- Hacer GET idempotente con IDs monotónicos y un cursor `since`.
- Proteger el buffer con lock o usar `queue.Queue`/deque acotada.
- No vaciar estado como efecto secundario de GET.
- Para APIs, exigir un token efímero por arranque además de Host/Origin, o al menos `Sec-Fetch-Site`/Origin apropiados para solicitudes de navegador.

### P2-08 — Cadena de suministro no reproducible ni verificada

**Severidad:** Media  
**Categoría:** OWASP A03 Supply Chain Failures  
**Archivos:** `requirements.txt:9-10`, `build_pendrive.sh:49-54`, `hades_win_master_advanced.py:326-338`

- Python usa restricciones `>=` sin lock ni hashes.
- El builder descarga `releases/latest/download/ollama-linux-amd64` y lo hace ejecutable sin checksum o firma.
- PyInstaller se instala sin versión fijada.
- Las plantillas Nuclei se actualizan sin pin de versión o manifiesto de integridad.

**Impacto:** builds diferentes según fecha, riesgo de compromiso upstream y dificultad para reproducir un informe.

**Remediación:**

- Mantener lockfile con versiones exactas y hashes.
- Fijar release y SHA-256 de Ollama/PyInstaller.
- Registrar versión/hash de Nmap, Nuclei, plantillas, OpenSSL, Tshark, Python, dependencias y modelo dentro de cada informe.
- Separar “actualización de herramientas” de “ejecución de auditoría”; producción debería usar artefactos previamente aprobados.

### P2-09 — Las pruebas pasan, pero no cubren los riesgos de mayor impacto

**Severidad:** Media  
**Categoría:** assurance / regresión  
**Archivos:** `tests/`

La suite valida objetivos, guardia Host/Origin, parsing, grounding básico, terminación y flujo de Fase 4. No existe prueba que detecte:

- afirmaciones ficticias del DOCX;
- sinks `innerHTML`;
- colisiones de directorios;
- terminación global de procesos ajenos;
- descarga de Ollama en señales/atexit;
- pérdida concurrente de logs;
- comandos sin shell.

Además, la salida de prueba mostró mojibake (`â€”`, `AUDITORÃA`) aunque los casos pasan, señal de que la configuración de codificación de la consola aún no es uniforme.

## Aspectos positivos confirmados

- El servidor escucha en `127.0.0.1:8080`.
- La guardia valida `Host` y `Origin` contra allowlists.
- No se expone un webroot genérico; los assets están allowlisteados.
- Los POST requieren JSON, `Content-Length` y máximo de 8 KiB.
- `target` y `duration` tienen esquema estricto en `/api/scan`.
- El lanzamiento del pipeline usa `Popen([...])` sin shell.
- La terminación Python intenta limitarse al árbol de procesos conocido.
- Los CVE confirmados del reporte se extraen sólo de líneas NSE/Nuclei, excluyendo por construcción el bloque de IA.
- `_assess_risk()` es determinista y no consume la conclusión del LLM.
- La prompt de análisis delimita salida hostil como datos y la respuesta IA recibe controles de cobertura.
- El informe técnico se persiste antes de esperar a Ollama.

## Prioridad de corrección

1. **Bloquear entrega de DOCX** y corregir P0-01.
2. Corregir terminación global P1-02.
3. Eliminar `shell=True` de las rutas P1-03.
4. Eliminar sinks DOM inseguros P1-04.
5. Evitar colisiones P1-05 y completar cleanup P1-06.
6. Rediseñar logs P1-07.
7. Hacer reproducible la cadena de suministro P2-08.
8. Agregar pruebas de regresión para todos los puntos anteriores.

## Dictamen final

HADES SENTINEL tiene una base técnica recuperable y controles defensivos mejores que los de una herramienta local típica, pero **no debe considerarse listo para producción ni usarse para emitir informes a clientes** en el estado auditado. La suite verde demuestra que el comportamiento probado funciona; no valida la veracidad del documento ejecutivo ni las fronteras de seguridad que hoy faltan.
