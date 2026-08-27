# Auditoria de produccion (Codex)

**Fecha de revisión:** 2026-07-25  
**Alcance:** `hades_server.py`, `hades_win_master_advanced.py`,
`hades_surveillance_advanced.py`, `hades_local.py`, `hades_mcp.py` y
`hades_report_docx.py`.

La evaluación considera el modelo de amenaza indicado: el servicio escucha sólo en
`127.0.0.1:8080`, el operador local es de confianza y los escenarios relevantes son
un host remoto que está siendo auditado, una página maliciosa abierta por el
operador y errores operativos normales. Los escenarios que requieren que el
atacante ya controle la cuenta local se marcan como teóricos y no se usan para
inflar severidades.

Verificaciones ejecutadas sin modificar los módulos:

- Parseo AST de los seis archivos con Python 3.10.11: correcto.
- 11 pruebas `unittest`: correctas.
- 13 pruebas funcionales/seguridad/integración/rendimiento invocadas sin su runner
  que escribe evidencia: correctas.
- Pruebas dirigidas de validadores y de separación IA/heurística: revelaron dos
  fallos no cubiertos por la suite, detallados en S-02 y S-03.

## 1. Seguridad

### Superficie HTTP observada

| Método | Ruta | Función | Guardia |
|---|---|---|---|
| GET | `/api/logs` | Lee y vacía logs en memoria | `_request_allowed()` |
| GET | `/api/status` | Estado del proceso | `_request_allowed()` |
| GET | `/api/sysinfo` | Métricas del equipo | `_request_allowed()` |
| GET | `/api/ollama` | Estado y métricas del modelo | `_request_allowed()` |
| GET | `/api/graph` | Inventario, topología y tráfico del último informe | `_request_allowed()` |
| GET/HEAD | `/`, dashboard y cualquier otro archivo | Archivos estáticos bajo la raíz del proyecto | La raíz tiene tratamiento especial; el resto se delega al handler estático |
| POST | `/api/scan` | Inicia auditoría | `_request_allowed()` |
| POST | `/api/stop` | Mata procesos y descarga Ollama | `_request_allowed()` |

Las rutas API GET están en `hades_server.py:568-617`; la raíz y el fallback
estático, en `hades_server.py:619-629`; los POST, en
`hades_server.py:640-765`. `HEAD` queda heredado de
`SimpleHTTPRequestHandler` porque no hay una implementación propia
(`hades_server.py:503-513`).

### S-01 — ALTA — DNS rebinding permite leer informes, configuración y código por el fallback estático

**Evidencia:** el handler fija como directorio estático todo `_HERE`, es decir, la
raíz completa del proyecto (`hades_server.py:39`, `hades_server.py:503-513`).
Sólo las rutas `/api/*` invocan `_request_allowed()`; cualquier otra ruta cae en
`super().do_GET()` sin validar `Host` ni `Origin`
(`hades_server.py:568-629`). Por lo tanto, la protección de DNS rebinding descrita
en `hades_server.py:552-566` no cubre los archivos estáticos.

**Explotabilidad concreta:** una página maliciosa que realice DNS rebinding hacia
`127.0.0.1` llega con `Host: dominio-atacante:8080`. Las APIs responden 403, pero
el fallback estático acepta ese Host. El origen atacante puede listar directorios
y leer cualquier archivo servido bajo la raíz: informes de red, fuentes Python,
logs, `.git`, `.ollama_last_metrics.json` y `signature.local.json`. Esto expone
IPs, MAC, servicios, tráfico, vulnerabilidades y datos personales. No requiere
acceso local previo; sí requiere que el operador visite la página y que el
navegador/red permitan el rebinding.

**Path traversal:** no se encontró una ruta HTTP propia que concatene un path
controlado por el cliente para escribir fuera del proyecto. El handler estándar
normaliza `..`, y `/api/scan` usa rutas fijas
(`hades_server.py:668-686`; `hades_surveillance_advanced.py:132-146`). Sin
embargo, servir toda la raíz ya es exposición excesiva y el handler estándar
puede seguir enlaces simbólicos presentes bajo esa raíz.

**Corrección obligatoria:** aplicar `_request_allowed()` antes de **todo** GET y
HEAD; deshabilitar listados; servir por allowlist únicamente los tres o cuatro
assets necesarios desde un directorio dedicado; rechazar dotfiles, `informes/`,
logs, fuentes y symlinks. Añadir pruebas reales de GET/HEAD con Host hostil.

### S-02 — ALTA — La salida de IA y texto controlable por el host sí alteran la severidad “determinista”

**Evidencia:** el informe declara que la IA es sólo consultiva
(`hades_report_docx.py:12-13`) y `_assess_risk()` afirma basarse en evidencia
(`hades_report_docx.py:294-320`). Sin embargo, `_parse_host_block()` extrae CVE
de **todo** el bloque, no sólo de las secciones técnicas
(`hades_report_docx.py:211-212`); el mismo bloque contiene la respuesta del modelo
(`hades_report_docx.py:223-226`). Cada CVE suma tres puntos y fuerza como mínimo
riesgo ALTO (`hades_report_docx.py:299-313`).

Una prueba dirigida con el parser real produjo:

```text
sin_cve [] BAJO
ia_inventa ['CVE-2026-99999'] ALTO
```

**Qué puede pasar:** un banner o salida de herramienta proveniente de un host
hostil entra en el prompt (`hades_win_master_advanced.py:635-660`). Aunque el
prompt indica que `<scan_data>` es no confiable
(`hades_win_master_advanced.py:646-648`), los delimitadores no se escapan; un
banner puede intentar cerrarlos e inducir al modelo a emitir un CVE. El CVE
inventado queda además señalado por el control de cobertura
(`hades_win_master_advanced.py:559-567`), pero luego el generador vuelve a
capturarlo como “evidencia” y eleva la severidad. Incluso sin IA, un texto
`CVE-*` dentro de un banner de Nmap se toma como CVE confirmado.

La salida del modelo no llega directamente a shell, `eval`, SQL ni una herramienta:
se agrega al informe como texto (`hades_win_master_advanced.py:661-670`) y
`python-docx` la inserta como texto (`hades_report_docx.py:844-848`,
`hades_report_docx.py:864-868`). El impacto demostrado es integridad de la
clasificación y del informe, no ejecución de código.

**Corrección obligatoria:** mantener campos separados con procedencia:
`cves_nmap_confirmados`, `cves_nuclei_confirmados` y `texto_ia`. Extraer CVE sólo
de resultados estructurados de Nuclei/NSE explícitamente reconocidos; nunca buscar
en el bloque completo ni en IA. Construir el DOCX desde un objeto tipado, no
reparseando texto concatenado. Añadir el caso anterior como regresión.

### S-03 — MEDIA — Los validadores bloquean metacaracteres de shell pero permiten inyección de argumentos

**Evidencia:** `_HOST_RE` y `_TARGET_RE` permiten que el valor comience con `-`
(`hades_win_master_advanced.py:66-82`, `hades_local.py:10-15`,
`hades_mcp.py:14-19`). La prueba con las funciones reales confirmó que las tres
aceptan `--help` y `-oNloot`. También aceptan IP `999.999.999.999` y CIDR
`10.0.0.0/99`.

Esos valores se interpolan después de las opciones de Nmap
(`hades_win_master_advanced.py:223-231`,
`hades_win_master_advanced.py:245-259`, `hades_local.py:145-158`,
`hades_mcp.py:115-124`). Nmap procesa opciones aunque aparezcan al final, de modo
que `--help` cambia la operación y otras opciones compactas pueden modificar la
salida. No se demostró escape a un comando del sistema: caracteres como `&`, `|`,
`;`, comillas, espacios y saltos de línea sí son rechazados.

**Explotabilidad concreta:** por HTTP la guardia de mismo origen impide a una web
remota entregar este target, por lo que el escenario real es una entrada errónea
del dashboard, un cliente MCP no confiable o una futura reutilización de estas
funciones. Afecta disponibilidad e integridad del escaneo, no da por sí solo RCE.

**Corrección sugerida:** reemplazar regex por `ipaddress.ip_address`,
`ipaddress.ip_network(strict=False)` y validación RFC de hostname; rechazar todo
valor que empiece con `-`; pasar argumentos como lista con `shell=False` y usar
`--` cuando la herramienta lo soporte. Validar octetos, prefijo CIDR y longitud.

### S-04 — BAJA — Persisten interpolaciones teóricas en comandos `shell=True`

Se revisó cada construcción que alcanza `execute()`/`run_cmd()`:

| Punto | Origen interpolado | Evaluación |
|---|---|---|
| `hades_server.py:80-82` | PID de `Popen` | Entero del SO; no inyectable. |
| `hades_server.py:95-100` | Lista constante de ejecutables | No recibe entrada. |
| `hades_server.py:348-357` | PowerShell constante | No recibe entrada. |
| `hades_server.py:678-686` | target/duration hacia Python | Correctamente usa lista y `shell=False` implícito. |
| `hades_server.py:733-736` | Filtros `taskkill` constantes | No recibe entrada. |
| `hades_win_master_advanced.py:223-231` | target | Sin metacaracteres, pero vulnerable a S-03. |
| `hades_win_master_advanced.py:245-259` | target y `flags` | Target: S-03. `flags` es público y sin validar; hoy sólo se usa el default interno. |
| `hades_win_master_advanced.py:278-312` | target y rutas de templates | Target restringido; rutas entre comillas. Categorías son parámetro programático, no HTTP. |
| `hades_win_master_advanced.py:343-355` | ruta fija de Nuclei | Sin entrada. |
| `hades_win_master_advanced.py:358-371` | host y puerto | Host restringido; puerto convertido a `int`. |
| `hades_surveillance_advanced.py:35-66`, `hades_surveillance_advanced.py:213-222` | nombre de interfaz devuelto por Tshark y duración | Duración termina como `int`; el nombre no se valida antes de insertarlo entre comillas. |
| `hades_local.py:94-99`, `hades_local.py:145-158` | target | Sin metacaracteres, pero vulnerable a S-03. |
| `hades_mcp.py:45-75`, `hades_mcp.py:115-124` | argumentos construidos desde target | Flujo actual restringido, pero `run_tool()` es inseguro si otro llamador le entrega `args` libre. |

Además, `HADES_NMAP_HOST_TIMEOUT` se incorpora a `flags` sin validación
(`hades_win_master_advanced.py:243-255`). Una variable de entorno maliciosa sí
podría introducir metacaracteres. El nombre de interfaz proviene del inventario
local de Tshark (`hades_surveillance_advanced.py:40-57`); una comilla en un
adaptador/extcap manipulado rompería el quoting. Ambos requieren control previo de
la configuración local, por eso la severidad es BAJA.

**Corrección sugerida:** eliminar `shell=True` y construir arrays de argumentos en
todos los casos. Validar configuración al inicio con tipos y límites; no exponer
`flags` crudos en una API pública.

### S-05 — MEDIA — Parseo JSON fail-open, sin esquema ni límite de cuerpo

**Evidencia:** `_read_json_body()` confía en `Content-Length`, no impone tamaño,
no comprueba `Content-Type` y convierte cualquier error en `{}`
(`hades_server.py:631-638`). `/api/scan` interpreta `{}` como un escaneo automático
de 30 segundos (`hades_server.py:655-665`). Si `target` es un número, lista u
objeto JSON, `.strip()` lanza una excepción no manejada
(`hades_server.py:661-663`). `duration` se transforma a texto sin límites
(`hades_server.py:664-679`) y luego se convierte con `int()` sin `try/except`
(`hades_surveillance_advanced.py:413-425`).

**Qué puede pasar:** un JSON malformado puede iniciar un escaneo en vez de fallar;
un cuerpo grande consume memoria; tipos válidos pero inesperados tumban el hilo
HTTP; duraciones negativas o enormes abortan el hijo o dejan captura/proceso por
un periodo desproporcionado. Una web cross-origin normal queda bloqueada antes de
leer el cuerpo (`hades_server.py:645-647`), por lo que el riesgo remoto está
reducido; sigue siendo un fallo de frontera de confianza y operación.

**Corrección sugerida:** máximo de cuerpo (por ejemplo 8 KiB), `Content-Type:
application/json`, errores 400/411/413 explícitos, esquema estricto
`target: str`, `duration: int`, y límites razonables (por ejemplo 5–300 s).
Rechazar campos desconocidos y nunca sustituir entrada inválida por una acción.

### S-06 — MEDIA — Resolución de binarios permite secuestro por PATH y no verifica integridad

**Evidencia:** los módulos legado/MCP priorizan `shutil.which()` sobre las rutas
conocidas (`hades_local.py:43-51`, `hades_mcp.py:30-43`), y luego ejecutan el
resultado (`hades_local.py:151-158`, `hades_mcp.py:45-75`). El motor avanzado usa
rutas absolutas para Nmap, Tshark y OpenSSL, lo cual está bien
(`hades_win_master_advanced.py:20-31`), pero Nuclei se ejecuta desde una carpeta
del perfil de usuario y no hay comprobación de hash, firma, propietario o versión
(`hades_win_master_advanced.py:26-31`, `hades_win_master_advanced.py:283-312`).

**Explotabilidad concreta:** requiere que un atacante local o una instalación
comprometida pueda alterar PATH o sustituir el ejecutable; no es alcanzable desde
una web remota por sí solo. En producción afecta la confianza de la cadena de
herramientas y puede ejecutar código con los privilegios del agente.

**Corrección sugerida:** resolver desde configuración allowlisted y absoluta,
rechazar `.bat`/scripts inesperados, registrar versión, verificar firma/hash en
instalación y arranque, y fallar cerrado si el binario cambia.

### S-07 — MEDIA — Los informes sensibles se guardan sin política de protección o retención

**Evidencia:** se persisten resumen y datos raw de Tshark
(`hades_surveillance_advanced.py:228-236`), IPs y metadatos de todos los hosts
(`hades_surveillance_advanced.py:178-204`, `hades_surveillance_advanced.py:315-351`)
y el informe DOCX (`hades_report_docx.py:916-925`). No hay creación con ACL
restrictiva, cifrado, expiración, borrado seguro ni redacción. La firma local puede
contener nombre, cargo y QR (`hades_report_docx.py:72-94`).

**Qué puede pasar:** otro usuario con permisos heredados, una copia de respaldo
mal protegida o S-01 pueden revelar topología y hallazgos de seguridad. No se
encontraron claves API, contraseñas o tokens hardcodeados en los seis módulos.
`.ollama_last_metrics.json` almacena sólo métricas/modelo, no el prompt
(`hades_win_master_advanced.py:386-408`; `hades_local.py:119-141`).

**Corrección sugerida:** ACL sólo para la cuenta del servicio/operador, directorio
de datos fuera del webroot, política de retención, opción de cifrado, redacción en
logs y clasificación explícita de los artefactos.

### S-08 — BAJA — El MCP puede reflejar entrada sensible completa en errores y no separa prompts

**Evidencia:** el modo por argumentos concatena el request original y, ante error,
lo devuelve en `raw_input` (`hades_mcp.py:134-141`). Un request puede contener un
prompt, nombres de modelo o datos sensibles. `ollama_query` envía el prompt como
JSON, no shell, lo cual corrige la antigua inyección de comandos
(`hades_mcp.py:79-95`), pero acepta un prompt arbitrario y devuelve la salida del
modelo directamente (`hades_mcp.py:125-130`).

**Explotabilidad concreta:** el reflejo sólo afecta a quien capture stdout del MCP;
no hay escritura de log propia en ese modo y la salida del modelo no ejecuta
herramientas dentro de este módulo. Es un riesgo de fuga e inyección indirecta para
un orquestador futuro que trate la respuesta como instrucciones.

**Corrección sugerida:** no incluir `raw_input` en errores, registrar sólo ID y
tipo de fallo; aplicar límites a prompt/modelo; devolver un objeto marcado
`untrusted_model_output`; exigir al consumidor tratarlo como dato.

### Controles que están bien resueltos

- El servidor sólo enlaza IPv4 loopback (`hades_server.py:776-778`); no se observó
  escucha accidental en LAN.
- La guardia exige Host loopback exacto y, cuando existe, Origin same-origin
  (`hades_server.py:552-566`). Las pruebas de CSRF y DNS rebinding para **APIs**
  pasan. Permitir Origin ausente mantiene `curl`/scripts locales y no abre el POST
  cross-origin normal de navegador, que sí envía Origin.
- No se habilita CORS (`hades_server.py:515-524`), por lo que una web cross-origin
  no puede leer respuestas API.
- El lanzamiento principal del hijo usa `Popen([...])`, no shell
  (`hades_server.py:668-686`).
- Los prompts técnicos declaran explícitamente la salida de escaneo/captura como no
  confiable (`hades_win_master_advanced.py:646-659`,
  `hades_surveillance_advanced.py:248-264`) y existe un control determinista que
  avisa de omisiones/CVE inventados (`hades_win_master_advanced.py:540-577`). El
  defecto S-02 está en el reparseo posterior, no en ausencia total de defensa.

## 2. Robustez y errores

### R-01 — MEDIA — Carrera al iniciar/detener y corrupción de estado global

**Evidencia:** `/api/scan` comprueba `active_process` y luego inicia un hilo; el
hilo asigna el proceso más tarde (`hades_server.py:649-678`). Dos requests
concurrentes pueden pasar la comprobación y lanzar dos agentes. Ambos usarían un
directorio basado sólo en minuto y `exist_ok=True`
(`hades_surveillance_advanced.py:136-146`), escribiendo el mismo
`INFORME_MAESTRO.md`. `/api/stop`, el lector y el `finally` comparten y reasignan
`active_process` sin lock (`hades_server.py:689-711`,
`hades_server.py:718-759`).

**Qué puede pasar:** doble escaneo por doble clic/reintento, informes truncados o
mezclados, el hilo lector accediendo a `None`, y estado “idle” mientras queda un
proceso. No requiere atacante.

**Corrección sugerida:** una máquina de estados protegida por `Lock`
(`IDLE/STARTING/RUNNING/STOPPING`), asignar un objeto local `proc` antes de
responder, UUID por ejecución/directorio, idempotency key y un único supervisor.

### R-02 — MEDIA — `taskkill` no se verifica y puede dejar procesos huérfanos

**Evidencia:** `_kill_active_tree()` sólo intenta `active_process.kill()` si
`subprocess.run()` lanza excepción; un `taskkill` con código de retorno no cero no
lanza y aun así se cierra el pipe y se pierde la referencia
(`hades_server.py:70-93`). El mismo patrón aparece en
`clean_up_current_process()` (`hades_win_master_advanced.py:94-107`). En timeout,
`execute()` asume que la limpieza terminó y devuelve
(`hades_win_master_advanced.py:161-174`).

**Qué puede pasar:** Nmap/Tshark/Nuclei siguen trabajando tras “detener” el agente,
consumen red/CPU y ya no pueden ser controlados por PID. Los hilos lectores son
daemon y sólo se esperan con timeout (`hades_win_master_advanced.py:140-178`).

**Corrección sugerida:** `shell=False`, comprobar `returncode`, luego
`terminate/kill/wait` con escalamiento y verificar que el árbol murió; en Windows
usar Job Objects o un process group propio en lugar de matar por nombre global.

### R-03 — MEDIA — Salidas y logs crecen sin cota

**Evidencia:** `execute()` acumula stdout/stderr completos en listas hasta 300 s o
más (`hades_win_master_advanced.py:123-183`). El servidor agrega cada línea del
hijo a `log_buffer` sin límite (`hades_server.py:52-54`,
`hades_server.py:375-377`, `hades_server.py:689-710`) y sólo lo vacía cuando el
dashboard consulta `/api/logs` (`hades_server.py:572-580`).

**Qué puede pasar:** con el dashboard cerrado o una herramienta/host que produzca
salida abundante, el proceso agota memoria. Un host auditado puede influir en
banners y cantidad de findings, aunque Nmap/Nuclei imponen sus propios límites.

**Corrección sugerida:** ring buffer por bytes/líneas, streaming a archivo con
rotación, límite por comando y truncado explícito; conservar un resumen y el path
de evidencia en vez de todo en RAM.

### R-04 — MEDIA — Configuración numérica inválida puede impedir importar o arrancar

**Evidencia:** cuatro variables de entorno se convierten con `int()` al definir la
clase, sin fallback ni límites (`hades_win_master_advanced.py:211-214`). Una
duración HTTP inválida falla al comienzo del hijo
(`hades_surveillance_advanced.py:423-425`). `NMAP_HOST_TIMEOUT` acepta texto libre
y además se interpola en shell (`hades_win_master_advanced.py:243-275`).

**Qué puede pasar:** un error de despliegue como `HADES_AI_TIMEOUT=120s` impide
importar el motor completo; valores negativos/cero producen presupuestos o
reintentos incoherentes; el servidor ya respondió “iniciado” aunque el hijo muera.

**Corrección sugerida:** objeto de configuración tipado, validado una vez al
arranque con mensajes accionables y rangos; no iniciar servidor si la configuración
es inválida.

### R-05 — BAJA — Resolución DNS crea un hilo sin timeout por IP externa

**Evidencia:** cada IP nueva crea un thread daemon que llama
`socket.gethostbyaddr()` sin timeout propio (`hades_server.py:380-400`). El mapa
encola todas las IPs externas y destinos encontrados
(`hades_server.py:469-479`). La captura lista hasta 200 IPs externas
(`hades_surveillance_advanced.py:91-106`).

**Qué puede pasar:** tráfico con muchas IPs spoofeadas/controladas puede disparar
cientos de resoluciones y threads; DNS lento los retiene. Está limitado de facto
por las 200 IPs que persiste la captura, por eso no es ALTA.

**Corrección sugerida:** pool pequeño, cola acotada, timeout/caché TTL, validación
con `ipaddress` y presupuesto total por actualización del mapa.

### R-06 — BAJA — Varias rutas fallan en silencio o no responden correctamente

**Evidencia:** un fallo de `Popen` dentro del hilo no está envuelto por un
`try/except` exterior y el cliente ya recibió éxito
(`hades_server.py:670-715`). Un POST a una ruta desconocida cae al final sin 404
ni body (`hades_server.py:640-765`), problemático con HTTP/1.1. Los logs HTTP se
silencian por completo (`hades_server.py:542-544`) y múltiples excepciones de
escritura/limpieza se descartan (`hades_server.py:525-540`,
`hades_server.py:80-103`).

**Qué puede pasar:** dashboard desincronizado, conexiones que esperan hasta
timeout y fallos imposibles de diagnosticar.

**Corrección sugerida:** respuesta 404/405/415 consistente, capturar error de
creación antes de responder 202, estado de ejecución con motivo de fallo y logging
estructurado de excepciones.

### Estado compartido

`system_metrics` y `ollama_metrics` se sustituyen como diccionarios completos
(`hades_server.py:241-319`, `hades_server.py:321-369`), operación suficientemente
atómica en CPython para lectores simples, aunque conviene usar snapshots
inmutables/lock si se soportarán otros intérpretes. En cambio, `active_process`,
`log_buffer`, `_rdns_cache` y `_rdns_inflight` se modifican desde múltiples hilos
sin un contrato de sincronización (`hades_server.py:52-54`,
`hades_server.py:375-400`); R-01, R-03 y R-05 son efectos concretos de ello.

El `current_process` global de `execute()` también quedaría corrupto si dos
llamadores ejecutaran herramientas en paralelo
(`hades_win_master_advanced.py:91-107`, `hades_win_master_advanced.py:123-183`).
Hoy `HadesSurveillance.run()` llama las herramientas secuencialmente, así que ese
último riesgo es teórico en el flujo actual.

## 3. Calidad de codigo

### Q-01 — MEDIA — Duplicación real de lógica sensible

**Evidencia:**

- Filtrado de scaffolding IA duplicado en
  `hades_win_master_advanced.py:41-60` y `hades_local.py:17-32`.
- Registro de métricas Ollama duplicado en
  `hades_win_master_advanced.py:386-410` y `hades_local.py:119-143`.
- Validación de target duplicada, con el mismo defecto S-03, en
  `hades_local.py:10-15` y `hades_mcp.py:14-19`, además de una variante en
  `hades_win_master_advanced.py:62-82`.
- Resolución de herramientas y rutas Windows duplicada en
  `hades_local.py:34-61` y `hades_mcp.py:21-43`.

**Qué puede pasar:** una corrección de seguridad se aplica a un motor y no a los
otros; las pruebas actuales ya prueban principalmente el validador de
`hades_local.py`, no las tres variantes.

**Corrección sugerida:** módulos únicos `validation.py`, `tool_runner.py`,
`ollama_client.py` y `config.py`, con tests parametrizados para todos los entry
points.

### Q-02 — MEDIA — Funciones monolíticas con demasiadas responsabilidades

**Evidencia:** `HadesSurveillance.run()` hace preflight, descubrimiento, captura,
prompts, interacción, persistencia y DOCX en unas 243 líneas
(`hades_surveillance_advanced.py:136-378`). `build_iso27001_docx()` mezcla cálculo
de riesgo, layout y render de todas las secciones en unas 240 líneas
(`hades_report_docx.py:634-873`). `full_audit()` coordina cuatro herramientas,
persistencia, prompt y control de IA (`hades_win_master_advanced.py:580-672`).
`do_POST()` mezcla validación, lifecycle, logging y cleanup
(`hades_server.py:640-765`).

**Qué puede pasar:** dificultad para aislar errores y probar carreras, política de
seguridad o render por separado.

**Corrección sugerida:** separar servicios de dominio, adaptadores de herramientas,
repositorio de informes, supervisor de procesos y handlers HTTP delgados.

### Q-03 — BAJA — Código muerto y variables sin uso; no hay imports propios rotos

**Evidencia:** `any(s in svcs for s in ())` siempre es falso
(`hades_report_docx.py:459-468`); `nuclei_results` se llena y nunca se consume
(`hades_win_master_advanced.py:603-608`). Los monitores arrancan al importar el
módulo, no dentro de `start_server()` (`hades_server.py:321-373`), lo que crea
side effects en tests y consumidores.

No se encontraron referencias a módulos propios borrados: los únicos imports
propios son `hades_surveillance_advanced.py` → `hades_win_master_advanced.py`
(`hades_surveillance_advanced.py:26-29`) y las importaciones dinámicas de
`hades_report_docx` (`hades_surveillance_advanced.py:357-360`,
`hades_server.py:448-451`), todos presentes y con sintaxis válida.

**Corrección sugerida:** eliminar expresiones/variables muertas, mover side effects
a entry points y añadir lint (`ruff`/`pyflakes`) en CI.

### Q-04 — MEDIA — La suite pasa pero no cubre los riesgos decisivos

**Evidencia:** la validación central sigue aceptando opciones aunque existe una
prueba de metacaracteres; los validadores reales están en
`hades_win_master_advanced.py:62-82`, `hades_local.py:10-15` y
`hades_mcp.py:14-19`. La separación IA/heurística tampoco está garantizada por
las funciones que reparsan el informe (`hades_report_docx.py:211-242`,
`hades_report_docx.py:294-320`). El HTTP usa estado multihilo
(`hades_server.py:503-513`, `hades_server.py:640-765`) sin pruebas de requests
concurrentes.

**Corrección sugerida:** incorporar regresiones para `--help`, CIDR inválido,
Host hostil en estáticos/HEAD, cuerpo JSON enorme/malformado, dos scans simultáneos,
stop durante lectura, `taskkill` no cero, salida masiva y CVE emitido sólo por IA.

## 4. Preparacion para produccion

Falta, como mínimo:

1. **Cerrar los dos defectos ALTA:** allowlist estática con guardia universal
   (`hades_server.py:503-629`) y separación estricta entre evidencia técnica y IA
   (`hades_report_docx.py:211-242`, `hades_report_docx.py:294-320`).
2. **Runner seguro único:** reemplazar los ejecutores `shell=True` por argv,
   validar targets/configuración y centralizar resolución e integridad de binarios
   (`hades_win_master_advanced.py:62-82`,
   `hades_win_master_advanced.py:123-192`, `hades_mcp.py:30-75`).
3. **Contrato HTTP de producción:** esquema JSON, límites de body/duración,
   códigos 4xx consistentes, 404/405, rate/concurrency limit y pruebas de Host,
   Origin, GET y HEAD (`hades_server.py:515-566`,
   `hades_server.py:631-765`).
4. **Supervisor de procesos:** estado bloqueado, Job Object/process group,
   cancelación verificada, límites de salida y deadline global por auditoría
   (`hades_server.py:52-103`, `hades_server.py:649-759`,
   `hades_win_master_advanced.py:91-192`).
5. **Logging operativo:** hoy el acceso HTTP se silencia
   (`hades_server.py:542-544`) y el resto usa `print`
   (`hades_win_master_advanced.py:194-196`). Faltan logs JSON con nivel, timestamp,
   run/correlation ID, rotación, redacción, eventos de inicio/stop/error y una
   política para no registrar prompts, firmas o evidencia sensible.
6. **Protección de datos:** sacar informes y configuración local del webroot,
   aplicar ACL/retención/cifrado y documentar clasificación, exportación y borrado
   (`hades_surveillance_advanced.py:132-146`,
   `hades_surveillance_advanced.py:228-236`, `hades_report_docx.py:72-94`).
7. **Configuración validada:** puerto, bind, rutas, modelo, timeouts, presupuesto y
   límites deben estar en configuración tipada, con defaults documentados y
   validación al arranque; hoy están repartidos entre constantes y entorno
   (`hades_server.py:38-50`, `hades_win_master_advanced.py:26-39`,
   `hades_win_master_advanced.py:211-243`).
8. **Empaquetado reproducible:** declarar versión mínima de Python y de binarios,
   fijar versiones/hash de dependencias, crear lock/SBOM, verificar firmas y
   proporcionar instalación/upgrade/rollback. Los imports opcionales actuales
   degradan silenciosamente (`hades_server.py:328-332`) o abortan el generador
   (`hades_report_docx.py:25-34`).
9. **Documentación operativa:** prerrequisitos y privilegios mínimos de Npcap/Nmap,
   capacidad esperada, puertos, health check, backup/retención, recuperación de
   procesos huérfanos, respuesta cuando Ollama cae y procedimiento de incidentes.
   El endpoint actual sólo expone “running/idle”
   (`hades_server.py:582-589`), no salud de dependencias ni estado degradado.
10. **CI de calidad y seguridad:** ejecutar las 24 pruebas, lint/type-check,
    análisis de dependencias, pruebas de abuso HTTP/concurrencia y smoke tests de
    cada binario antes de publicar. Los entry points actuales no comparten tipos ni
    validación (`hades_local.py:177-187`, `hades_mcp.py:109-152`,
    `hades_surveillance_advanced.py:407-431`).

## 5. Veredicto

# NO APTO

No debe salir a producción en el estado revisado. Que el dashboard escuche sólo en
loopback reduce mucho la exposición, y las APIs sí tienen una defensa same-origin
razonable, pero no compensa:

1. **Obligatoria P0:** impedir la lectura por DNS rebinding de toda la raíz,
   informes y configuración (S-01).
2. **Obligatoria P0:** garantizar que IA/banners no alimenten la clasificación
   heurística ni la lista de CVE confirmados (S-02).
3. **Obligatoria P1:** eliminar `shell=True`, bloquear inyección de argumentos y
   validar tipos/rangos/configuración (S-03, S-04, S-05).
4. **Obligatoria P1:** serializar lifecycle de scans y verificar la terminación
   real de árboles de procesos (R-01, R-02).
5. **Obligatoria P1:** limitar memoria, threads, cuerpo HTTP, duración y volumen de
   salida (R-03, R-05).
6. **Obligatoria P1:** proteger informes y binarios, e implementar logging,
   configuración, empaquetado y operación reproducibles (S-06, S-07 y sección 4).
7. **Obligatoria P2 antes de GA:** consolidar duplicados, dividir funciones
   monolíticas y ampliar pruebas con los casos de abuso demostrados (sección 3).

Tras corregir P0/P1 y ejecutar pruebas de regresión, corresponde una nueva auditoría
antes de cambiar el veredicto a **APTO CON RESERVAS** o **APTO**.
