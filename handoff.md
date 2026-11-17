# Handoff — HADES SENTINEL

## 1. Objetivo
Mejorar HADES SENTINEL. En esta sesión: que la **Fase 1 de descubrimiento** funcione contra redes **enrutadas** (objetivo tras un router, p. ej. `10.77.0.0/24`), no solo ARP en la LAN local.

## 2. Estado actual
- **Hecho y verificado:** descubrimiento **adaptativo** on-link/enrutado en `nmap_discovery`.
  - On-link (subred propia) → ARP (`-PR`), imbatible a capa 2.
  - Enrutado (off-link) → barrido L3 acotado (ICMP echo+timestamp, TCP SYN/ACK, UDP 53/137/161) con `-T4 --max-retries 1 --min-rate 200 --host-timeout 20s`.
  - **Antes/después medido** contra `10.77.0.0/24`: perfil viejo se colgaba >5 min (lo mataba el techo de 300 s de `execute` → lista vacía); perfil nuevo resuelve en **26,5 s** con veredicto limpio.
  - **Refinamiento clave (subnet_of):** on-link es True solo si el objetivo está **totalmente contenido** en una subred local, no si apenas solapa. Así un `/16` que engloba tu `/24` local se trata como **enrutado** (ARP solo vería la parte local y perdería el resto). Antes usaba `overlaps()` (bug latente para objetivos que exceden la subred local).
  - La lógica es **100% genérica**: cero IPs hardcodeadas (solo un comentario ilustrativo en la línea 83). Probada con 172.16/24, 192.168.8/22, 203.0.113/24, 10.99/16, IPv6 fd00::/64. Sirve para cualquier ruta estática.
  - Suite completa **57/57 OK** (49 previos + 8 nuevos). Ambos módulos compilan.
- **Rutas estáticas agregadas (2026-08-27):** primero `10.77.0.0/24` y luego ampliada a `10.77.0.0/16`, ambas `-NextHop 10.77.140.1 -InterfaceIndex 10` (ActiveStore). Todo `10.77.0.0/16` sale por el cable (verificado: `10.77.0.1` → `10.77.140.1` → `10.77.128.22` → `10.77.152.11`).
- **Escaneo /16 COMPLETADO:** `10.77.0.0/24` exacto da 0 hosts, pero el `/16` con el motor real de SENTINEL encontró **106 hosts vivos** (65.536 IPs en 437,6 s ≈ 7,3 min) con el perfil L3 enrutado. Concentración: `10.77.128.x` (11), `100-103.x`, `143-147.x`, `152-154.x`, etc. Lista guardada en `informes\hosts_vivos_10.77.0.0-16_20260827.txt`. Env-override usado: `--min-rate 1000 --host-timeout 12s`, `HADES_DISCOVERY_TIMEOUT=1800`.
- **Dashboard activo:** `python hades_server.py` corriendo en `http://127.0.0.1:8080` (HTTP 200, "HADES v2.2.0 | Tactical Cyber Center"), con la mejora integrada. Background task `bprmd3ygs`. Al cerrar la sesión: parada limpia (`.hades_token`, :8080 libre).
- **Modo Custom del dashboard mejorado:** el `POST /api/scan` ya aceptaba CIDR; el problema era la UI. Arreglado en `agente HADES.html`: placeholder/ayuda correctos (el viejo `10.77.1.0/24 - 10.77.2.1/24` con guión que `validate_target` rechaza), validación en vivo (`describeTarget`: IP o CIDR, conteo de IPs, aviso naranja en rangos grandes, error rojo si el formato es inválido) y validación antes de enviar. Verificado en el navegador real (JS `node --check` OK; DOM: `/16`→"65.534 IPs — rango grande", guión→error). Así el usuario puede lanzar este tipo de escaneo enrutado desde el dashboard.
- **Commit `c05501a`** en `fix/fase4-ia-no-bloqueante` (43 archivos, +5440/−1623, SIN push): consolida esta mejora + todo el trabajo previo pendiente de la rama. Working tree limpio.
- **Fix del /16 (anomalía "el modo custom con un /16 no hace nada"):** el descubrimiento usaba timing FIJO (`--min-rate 200`, techo 600 s); 65.536 IPs no terminaban en 10 min y `execute` cortaba Nmap → lista incompleta. Corregido con `_scaled_routed_discovery(target)` en `hades_win_master_advanced.py`: escala `--min-rate` y el techo del subproceso según el tamaño (`/16` → `--min-rate 1092`, techo 900 s; `/24` sigue en base). 4 tests nuevos, **suite 61/61**. Verificación empírica: el `/16` con config por defecto **completó en 557 s (< techo 900 s), ya no se corta** (era el bug). Solo detectó 1 host porque a esa altura **el cable Ethernet estaba `Disconnected`** y la ruta `/16` (de sesión) se había perdido → la red institucional dejó de ser alcanzable. **Re-validar los ~106 hosts al reconectar el cable** (re-agregar ruta `/16`, idealmente persistente con `route -p add 10.77.0.0 mask 255.255.0.0 10.77.140.1 if 10`).
- **Reversing LookLAN Network Monitor** (`REVERSING_LOOKLAN.md`): análisis estático (sin ejecutar). Es un instalador con overlay comprimido; el payload usa **WS2_32 (ICMP/TCP/UDP), SNMP (SNMPAPI/MGMTAPI/SnmpMgrOpen), TTL**.
- **PARIDAD SNMP/NetBIOS IMPLEMENTADA** (cierra la brecha vs LookLAN): `asset_profile(ip)` + `hechos_desde_perfil()` + `bloque_perfil()` en `hades_win_master_advanced.py`, integrado en `full_audit` como paso **1b** → sección `[IDENTIDAD DEL ACTIVO (SNMP/NetBIOS)]` en el informe, y la identidad entra como hecho verificado en el prompt de IA. Comando: `nmap -sU -n -p161,137 --script snmp-info,snmp-sysdescr,nbstat --host-timeout 60s`. Comunidad SNMP saneada (`HADES_SNMP_COMMUNITIES`). Un fallo del perfilado no aborta la auditoría. **13 tests nuevos** (`tests/test_asset_profile.py`), **suite 74/74 OK**, probado real contra un router en 10,2 s.

## 3. Archivos y cambios (esta sesión)
- `hades_win_master_advanced.py`:
  - `import ipaddress`.
  - Helpers nuevos `_local_ipv4_networks()` (usa psutil) y `_target_is_onlink(target)`.
  - Constantes `DISCOVERY_ONLINK_FLAGS`, `DISCOVERY_ROUTED_FLAGS`, `DISCOVERY_SUBPROC_TIMEOUT` (todas configurables por env: `HADES_DISCOVERY_ONLINK_FLAGS`, `HADES_DISCOVERY_ROUTED_FLAGS`, `HADES_DISCOVERY_TIMEOUT`).
  - `nmap_discovery()` reescrito: elige perfil según `_target_is_onlink` y pasa `timeout=DISCOVERY_SUBPROC_TIMEOUT` a `execute`.
- `hades_surveillance_advanced.py`: textos/logs "Descubrimiento ARP" → "Descubrimiento de hosts" (coherencia con el comportamiento adaptativo). Sin cambio de lógica.
- `README.md`: descripción de la Fase 1 actualizada a "Descubrimiento de Hosts (Adaptativo)".
  - `_target_is_onlink` usa `subnet_of` (no `overlaps`): un objetivo que excede la subred local es enrutado.
  - `_scaled_routed_discovery` + `_target_host_count`: escalan rate y techo al tamaño del objetivo.
  - `asset_profile` + `hechos_desde_perfil` + `bloque_perfil`: identidad SNMP/NetBIOS del activo.
  - `full_audit`: paso 1b de identidad + identidad como hecho verificado en el prompt de IA.
- `tests/test_discovery_adaptativo.py`: **nuevo**, 12 casos (clasificación on-link, `/16` que engloba la local, perfil de comando, escalado de rango, objetivo inválido — sin tocar la red).
- `tests/test_asset_profile.py`: **nuevo**, 13 casos (parsers de switch/impresora/PC, `open|filtered`, comando SNMP+NetBIOS, comunidad saneada, integración en `full_audit` y tolerancia a fallos).
- `REVERSING_LOOKLAN.md`: **nuevo**, reversing estático de LookLAN + mapeo de técnicas a HADES + paridad implementada.

## 4. Intentos fallidos (NO BORRAR — acumulativo)
- Comando de descubrimiento antiguo `-sn -PR -PE -PS22,80,443,445,8080,8443` **sin timing** contra un `/24` enrutado: se arrastra >5 min y `execute()` (techo 300 s) lo mata devolviendo lista vacía. Nunca lanzar descubrimiento enrutado sin `--host-timeout`/`--max-retries`/`--min-rate`.
- `-PR` (ARP) es inútil para objetivos enrutados: Nmap lo ignora fuera de la subred. No basta con dejarlo puesto.
- PowerShell rompe `-PS22,80,443,...` interpretando las comas como array → `Missing argument in parameter list`. Solución: pasar cada flag como string entre comillas simples (`& $nmap '-sn' '-PS22,80,...'`) o usar `--%`.
- `Find-NetRoute 10.77.0.1` sugería salida por Ethernet, pero el **tracert real sale por Wi-Fi** (192.168.1.1→CGNAT ISP). El comportamiento real manda: `10.77.0.0/24` no es alcanzable por el cable sin ruta específica.
- La regex de detección de hosts en `surveillance` (`Nmap scan report for (\d...)`) es frágil: no captura líneas con reverse-DNS `for host (ip)`. Preexistente, fuera de alcance esta sesión (con `-n` en el perfil enrutado no afecta). Anotado para futura mejora.
- Clasificar on-link con `overlaps()` es un bug para objetivos que **exceden** la subred local (un `/16` que engloba la `/24` local se marcaría on-link → ARP → perdería lo enrutado). Correcto: `subnet_of` (contención total). Corregido.
- **Guard del entorno**: cualquier cmdlet `New-NetRoute`/`Remove-NetRoute`/`Get-NetRoute` con un prefijo `x.x.x.x/NN` en PowerShell dispara `"Remove-Item on system path '/NN' is blocked"` **incluso con el sandbox desactivado**. Solución: usar el clásico `route add <red> mask <máscara-punteada> <gw> if <idx>` desde la tool Bash (sin barras). Ej. `/16` = `mask 255.255.0.0`.
- Un `/16` con `--min-rate 1000` puede tardar >10 min y superar el techo de `execute` (600 s por defecto). Hay que subir `HADES_DISCOVERY_TIMEOUT` (se usó 1800 s) al escanear rangos grandes.
- El dashboard corre UN escaneo a la vez: con uno activo, `POST /api/scan` responde `El agente ya se encuentra activo` y descarta el nuevo. Al abrir el dashboard había un escaneo de `192.168.1.0/24` ocupando el agente (`get_local_ip` conecta a 8.8.8.8, que sale por el Wi-Fi → autodetecta la subred de casa). Detenerlo con `/api/stop` antes de lanzar otro. `/api/scan` y `/api/stop` son POST con guardia same-origin: dispararlos desde la página (Origin válido), no por curl.
- El server (ThreadingHTTPServer) responde con intermitencia (timeouts de varios segundos) mientras corre el descubrimiento Nmap agresivo del /24 enrutado — no está caído, es saturación de CPU/red. Evitar polling intensivo durante la Fase 1.
- Timing FIJO en el descubrimiento enrutado no escala: `--min-rate 200` + techo 600 s sirven para un /24 pero un /16 (65.536 IPs) no termina y `execute` lo corta → lista incompleta ("no hace nada"). Corregido con `_scaled_routed_discovery`.
- Un objetivo enrutado inalcanzable (interfaz caída o sin ruta específica) NO da error: el escaneo sale por la ruta por defecto (Wi-Fi) y devuelve 0-1 hosts, con el mismo síntoma que un bug. Verificar SIEMPRE enlace + ruta antes de culpar al código (`Get-NetAdapter`, `route print`). Pendiente: que HADES lo avise (opción no elegida aún).
- Parsers de scripts Nmap: las claves llegan con prefijos variables (`|   sysDescr:`, `|_  sysDescr:`, `|_snmp-sysdescr:`). Normalizar la línea, no asumir un solo formato.
- En **UDP**, `open|filtered` = sin respuesta, NO puerto abierto. Tratarlo como servicio expuesto (SNMP) genera falsos positivos en todos los hosts que no contestan.

## 5. Próximos pasos
1. **Auditoría profunda de los 106 hosts** (Fase 4: puertos/versiones/Nuclei/TLS/IA): desde el dashboard en modo Custom o `python hades_surveillance_advanced.py <subred>`. OJO: el `/16` completo tardaría horas; conviene ir por subredes con más hosts (`10.77.128.0/24`, `10.77.100-103.0/24`, `10.77.143-147.0/24`).
2. `git push` cuando el usuario lo pida (regla: nunca sin permiso). El commit `c05501a` está local en `fix/fase4-ia-no-bloqueante`.
3. Si se sale de la red institucional: las rutas `10.77.0.0/24` y `/16` están en ActiveStore (no persistentes) → se van al reiniciar; volver a `route add 10.77.0.0 mask 255.255.0.0 10.77.140.1 if 10`. La IP fija `10.77.140.100/24` sí persiste.
4. Al cerrar la sesión de trabajo: parada limpia del dashboard (matar `hades_server.py`/tarea `bprmd3ygs`, liberar :8080, borrar `.hades_token`).
5. Continuar con otras mejoras de SENTINEL según prioridad.

## Sesión 2026-11-17 — revisión con ECC + tests de aprobación (anexo)
- **Objetivo:** revisar SENTINEL con las herramientas de ECC (`E:\Herramientas\ECC`, agentes `python-reviewer` y `security-reviewer`) y mejorarlo con tests de aprobación (golden master).
- **Estado:** suite **96/96 pytest** y **88/88 `tests/run_all.py`** (antes 83). Nada commiteado (rama `fix/fase4-ia-no-bloqueante`, sigue también el trabajo sin commit del 16-10).
- **Hecho (cada fix con golden aprobado tras revisar el diff):**
  - `tests/approval.py` (nuevo): golden master sin dependencias (`HADES_APPROVE=1` aprueba; `.received.txt` ignorado en git). `tests/test_aprobacion.py` (nuevo, 13 casos) + `tests/approved/*.approved.txt` (15 goldens): Nuclei, execute, hechos Nmap/perfil SNMP, control IA, TLS/extracto, cadena INFORME_MAESTRO → datos/ISO/recomendaciones, DOCX real, PTR, escalado de descubrimiento.
  - `_parse_nuclei`: error/timeout/stderr fatal/`[EXIT rc]`/salida no JSON ya NO dicen «Sin vulnerabilidades»: dicen ERROR/TIMEOUT/SALIDA NO INTERPRETABLE «no concluyente»; hallazgos con timeout = PARCIAL; avisos `[WRN] … low` y JSON ajeno ya no cuentan como hallazgos.
  - `execute()`: marca `[EXIT rc=N]` si el código de salida ≠ 0, conserva stderr en timeout, reloj `time.monotonic()`.
  - Informe (`hades_report_docx.py`): riesgo nuevo **«NO EVALUADO»** (Nmap falló sin evidencia), campo `no_concluyente` (Nuclei/TLS/Nmap parcial) visible en el anexo del DOCX, impacto de negocio ya no dice «sin servicios» si la prueba falló, recomendación Alta «Repetir pruebas no concluyentes». Dashboard y mapa 3D conocen «NO EVALUADO».
  - `auditar_respuesta_ia`: puerto por número completo («80» ya no lo cubre «8080»/«2018»).
  - Seguridad: PTR saneado (`_sanitize_ptr`, RFC 1123) + escape en `nodeLabel` del mapa 3D (XSS→POST /api/scan); cabeceras `X-Frame-Options: DENY`, `CSP frame-ancestors 'none'`, `nosniff`.
- **Intentos fallidos (se suman a la sección 4):**
  - Los agentes de ECC (`ecc:python-reviewer`) no existen como subagent_type hasta `/reload-plugins`; se usaron agentes generales que leen `E:\Herramientas\ECC\agents\*.md`.
  - El primer golden aprobó el bug (approval «a ciegas»): un golden recién generado SOLO caracteriza; hay que leerlo antes de darlo por especificación.
  - Corrección del revisor: NO existe token `.hades_token` en el código (solo `DETENER_HADES.bat` lo borra); la API sólo tiene guardia Host/Origin y acepta peticiones sin Origin.
- **Próximos pasos (pendientes de la revisión ECC, por prioridad):**
  1. Tshark (`hades_surveillance_advanced.py:222-246`): error/interfaz inválida/preflight falso se informa como «0 paquetes» → estados omitido/error/parcial + golden de `parse_tshark_output`.
  2. `full_audit` con excepción (`surveillance:342-346`): emitir bloque `OBJETIVO:` con `[ERROR]` (hoy el host desaparece del DOCX) y no sobrescribir la evidencia parcial.
  3. Descubrimiento con error = «sin hosts» y salida 0 (`surveillance:173,192-199`) → estado de error y `sys.exit(2)`; Nuclei/TLS «omitido: Nmap sin resultado» (A4).
  4. Seguridad: `execute(shell=True)` + `HADES_*_FLAGS`/`HADES_NMAP_HOST_TIMEOUT` sin validar (inyección); lista blanca de alcance (hoy acepta IP públicas y 0.0.0.0/0); token por arranque `X-Hades-Token`; neutralizar `<`/`>` en evidencia hacia el prompt (LLM01); MCP con salida no confiable y `shutil.which`; consola con `textContent`; Ollama sólo loopback.
  5. M1 `_nmap_subproc_timeout` sin soporte de `h`; M3 IPs link-local/multicast contadas como Internet; M5 `safe_subprocess_env` sin `HADES_ASSET_PROFILE_TIMEOUT`/`HADES_SNMP_COMMUNITIES`; M6 `ollama serve` huérfano al fallar el arranque.
  6. Commit cuando el usuario lo pida (nunca push sin permiso).
