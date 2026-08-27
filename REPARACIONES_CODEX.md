# Reparaciones P0/P1 — HADES SENTINEL

Fecha: 2026-07-26  
Estado: los cinco bloques solicitados quedaron implementados y cubiertos por
regresiones. `AUDITORIA_CODEX.md` y `PRODUCCION_READINESS.md` no fueron
modificados.

## Resultado de verificación

- Línea base previa: `python tests/run_all.py` → `24/24 casos OK`, exit `0`.
- Ciclo rojo inicial: `python -m unittest tests/test_produccion_p0_p1.py -v`
  reprodujo los cinco defectos: 2 fallos y 3 errores.
- Regresión dirigida final: el mismo comando → `Ran 1 test`, `OK`, exit `0`;
  contiene cinco `subTest` identificados por arreglo.
- Compilación: `python -m compileall -q ...` sobre todos los módulos modificados
  → sin salida, exit `0`.
- Suite final: `python tests/run_all.py` → bloque funcional `13/13`, bloque
  `unittest` `11/11`, total `24/24 casos OK`, exit `0`.

El caso nuevo agrupa las cinco regresiones como `subTest` dentro de un único
método para conservar literalmente el contrato histórico de 24 casos del runner.
La regresión existente de CVE inventado fue trasladada al bloque P0-2, por lo que
no se perdió cobertura.

## P0-1 — S-01: lectura de archivos y DNS rebinding

### Implementación

- `hades_server.py:57-70`: allowlist explícita derivada de las referencias reales
  del dashboard:
  - `agente HADES.html`;
  - `assets/logo_hades_sentinel_doc.png`;
  - `network_map_3d.js`;
  - `vendor/hades-graph-bundle.js`.
- `hades_server.py:497-530`: resolución exacta del asset, confinamiento a `_HERE`,
  rechazo de componentes symlink y exigencia de archivo regular.
- `hades_server.py:621-672`: `_request_allowed()` se ejecuta antes de resolver
  cualquier ruta GET o HEAD. `do_HEAD` es explícito y comparte la misma ruta
  segura; HEAD no escribe cuerpo ni vacía el buffer de logs.
- Se eliminó el fallback `super().do_GET()`. Cualquier ruta no allowlisted devuelve
  404, incluidos directorios, dotfiles, `.git`, `informes/`, `*.log` y `*.py`.

### Prueba

`tests/test_produccion_p0_p1.py:159-208` comprueba:

- GET y HEAD con `Host` de rebinding → 403;
- HEAD legítimo del dashboard → 200 y cuerpo vacío;
- código, logs, informes, dotfiles y directorios → 404;
- cada asset requerido → 200;
- un asset allowlisted convertido en symlink → rechazado.

## P0-2 — S-02: procedencia de CVE y salida IA

### Implementación

- `hades_report_docx.py:164-242`: el objeto de host usa campos separados
  `cves_confirmados` y `texto_ia`; se retiraron los campos ambiguos `cves` y `ai`.
- `hades_report_docx.py:227-236`: sólo se extraen CVE desde líneas de scripts NSE
  de `[NMAP]` y findings con severidad de `[NUCLEI]`. Un CVE en banner de servicio,
  texto general o `[ANÁLISIS IA HADES]` no es evidencia confirmada.
- `hades_report_docx.py:307-333`: `_assess_risk()` puntúa exclusivamente con
  `cves_confirmados`, findings Nuclei, puertos y sistema operativo técnicos.
- Todos los consumidores DOCX/ISO/matriz/recomendaciones fueron migrados a los
  campos con procedencia.

### Prueba

`tests/test_produccion_p0_p1.py:210-252` usa sólo datos sintéticos y demuestra que:

- CVE de NSE y Nuclei entran en `cves_confirmados`;
- CVE de banner y de IA quedan fuera;
- `texto_ia` se conserva como texto consultivo;
- un host cuyo único CVE viene de IA queda `INFORMATIVO`;
- el control previo de CVE inventado por el modelo sigue activo.

## P1-1 — S-03: validadores semánticos

### Implementación

- `hades_validation.py:1-79`: módulo único con `ipaddress.ip_address`,
  `ipaddress.ip_network(strict=False)`, hostname DNS por etiquetas y URL HTTP(S)
  sin credenciales, query, fragmento ni caracteres incompatibles con CLI.
- `hades_validation.py:23-50`: rechazo temprano de tipos no textuales, vacío y
  cualquier valor que empiece con `-`.
- `hades_win_master_advanced.py:64-69`, `hades_local.py:11-12` y
  `hades_mcp.py:14-15`: los tres entry points delegan al módulo único.

### Prueba

`tests/test_produccion_p0_p1.py:254-282` ejecuta los cuatro puntos públicos y
rechaza `--help`, `-oNloot`, `999.999.999.999`, `10.0.0.0/99` y hostnames
malformados. También confirma IPv4, IPv6, CIDR y hostname válidos.

## P1-2 — S-05: contrato HTTP POST

### Implementación

- `hades_server.py:674-700`: `Content-Type: application/json` obligatorio,
  `Content-Length` obligatorio, máximo 8 KiB, UTF-8 y JSON estrictos.
- `hades_server.py:702-713`: esquema exacto `{target, duration}`; `target` debe ser
  `str` y objetivo válido; `duration` debe ser `int` real (no `bool`) entre 5 y
  300.
- `hades_server.py:715-734`: rutas POST desconocidas devuelven 404 antes de leer
  parámetros de negocio.
- Los errores de frontera devuelven explícitamente 400, 411, 413 o 415 y retornan
  antes del punto único de creación de proceso (`hades_server.py:533-535`).
- `/api/stop` exige objeto JSON vacío; el dashboard ahora envía `{}` en
  `agente HADES.html:1837-1843`.

### Prueba

`tests/test_produccion_p0_p1.py:284-344` cubre 411, 415, 413, JSON malformado,
claves faltantes/extra, tipos inválidos, límites de duración, ruta desconocida y
contrato de `/api/stop`. Un mock en el punto de creación confirma cero procesos
lanzados por todas las entradas inválidas.

## P1-3 — R-01/R-02: lifecycle de escaneos

### Implementación

- `hades_server.py:81-98`: el estado global se lee y limpia bajo `_scan_lock`.
- `hades_server.py:750-807`: validación previa, `Popen` y publicación de
  `active_process` ocurren bajo el mismo `threading.Lock`; el monitor trabaja con
  una referencia local y sólo limpia el proceso que él mismo supervisa.
- `hades_processes.py:64-127`: terminación centralizada. Inventaría descendientes,
  ejecuta `taskkill /F /T` con lista de argumentos y `shell=False`, comprueba
  `returncode`, y si hace falta escala a `terminate`, `kill` y `wait`. Verifica
  padre y descendientes antes de devolver éxito.
- `hades_server.py:84-98` y `hades_win_master_advanced.py:81-89` usan el mismo
  terminador. Si no puede confirmar el árbol, conservan la referencia y no
  informan éxito.
- Se retiraron los `taskkill` globales por nombre/título: podían matar herramientas
  ajenas y no permitían verificar pertenencia al árbol del agente.

### Prueba

`tests/test_produccion_p0_p1.py:346-423` lanza dos POST válidos simultáneos y
demuestra un solo proceso (`200` + `400`). También simula `taskkill` con retorno
no cero y verifica la secuencia `terminate`/`kill`/`wait`, el uso de
`shell=False`, el caso de padre ya finalizado con descendientes y la ausencia de
los taskkill globales legacy.

## Pendientes y límites deliberados

- No quedan pendientes dentro de P0-1, P0-2, P1-1, P1-2 ni P1-3.
- No se hizo la conversión global de todos los comandos de escaneo que todavía
  usan `shell=True` en motores legacy. Es un rediseño mayor de construcción de
  argumentos y herramientas externas; hacerlo parcialmente contravendría la
  regla de alcance. El riesgo S-03 solicitado sí quedó cerrado por validación
  semántica única y pruebas en los tres entry points.
- La confirmación completa de descendientes usa `psutil`, ya declarado en
  `requirements.txt`. Si no está disponible y `taskkill /T` falla, el terminador
  falla cerrado: devuelve `False` en vez de afirmar que el árbol murió.
- No se ejecutó un escaneo real de red ni se usaron fixtures del equipo auditado;
  toda la evidencia nueva es sintética.
