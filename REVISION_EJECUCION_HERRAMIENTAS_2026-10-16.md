# Revisión de ejecución: Nmap, Nuclei, Tshark y OpenSSL

Fecha: 2026-10-16. Alcance: rutas de ejecución del motor `hades_win_master_advanced.py`, orquestación `hades_surveillance_advanced.py` y entrada secundaria `hades_mcp.py`. Revisión local, sin escaneo ni captura de una red de terceros. La operación prevista presupone autorización del titular de la red; esta revisión se centra en la fiabilidad técnica y la evidencia del informe.

## Conclusión

Los cuatro binarios existen y respondieron a la consulta de versión en este equipo. El mayor riesgo para producción no es su ausencia: el motor devuelve texto en lugar de un resultado estructurado con código de salida, estado de timeout y errores. Como consecuencia, una herramienta fallida puede alimentar un informe que afirma ausencia de hallazgos. La evidencia de Nmap, Nuclei, Tshark y TLS debe prevalecer sobre la interpretación de la IA; ISO/IEC 27001 debe figurar como marco de referencia de gestión, sin convertir el escaneo en una certificación.

## Verificación local realizada

| Herramienta | Binario resuelto por el proyecto | Versión observada | Verificación |
|---|---|---|---|
| Nmap | `C:\Program Files (x86)\Nmap\nmap.exe` | 7.80, Npcap 0.9982 | `--version`, salida 0 |
| Nuclei | `%USERPROFILE%\Documents\HADES\nuclei\nuclei.exe` | 3.8.0 | `--version`, salida 0; `-h` confirma `-j`, `-duc`, `-timeout` y `-retries` |
| Tshark | `C:\Program Files\Wireshark\tshark.exe` | 4.6.6 | `--version`, salida 0; `-D` enumera Ethernet y Wi-Fi; ayuda confirma `separator=/t` |
| OpenSSL | `C:\Program Files\OpenSSL-Win64\bin\openssl.exe` | 4.0.0 | `version`, salida 0; ayuda confirma opciones `-verify_hostname`, `-verify_ip` y `-verify_return_error` |

La disponibilidad del binario y su ayuda no prueban permisos de captura, alcance de las plantillas, conectividad con objetivos ni corrección de resultados. No se ejecutó un escaneo activo ni una captura durante esta revisión.

## Hallazgos priorizados

### P0 — El estado de ejecución se pierde

`execute()` en `hades_win_master_advanced.py:199-273` usa `subprocess.Popen(..., shell=True)` y devuelve solamente `stdout` más texto de `stderr`. No conserva `returncode`, duración, herramienta, parámetros ni estado de finalización como campos. Un timeout agrega `[TIMEOUT]` a salida parcial; un error agrega `[ERROR]`. El preflight en `hades_surveillance_advanced.py:160-170` comprueba `os.path.exists`, no ejecutabilidad, versión, privilegios de Npcap ni dependencias. Esto impide distinguir de modo confiable `éxito sin hallazgos`, `fallo`, `parcial` y `omitido`.

**Acción:** introducir un objeto de resultado común con `status`, `exit_code`, `timed_out`, `stdout`, `stderr`, `started_at`, `duration`, `command_argv` y versión de herramienta; propagarlo al informe. Usar argumentos como lista sin shell para herramientas externas cuando sea posible. Validar explícitamente las opciones configurables por entorno y el puerto TLS.

### P0 — Nuclei informa «sin vulnerabilidades» ante error o timeout

`nuclei_scan()` en `hades_win_master_advanced.py:465-500` ejecuta plantillas web; `_parse_nuclei()` en `:502-531` ignora líneas `[ERROR]`, `[TIMEOUT]` y `[STDERR]`, y si no queda un finding devuelve `Sin vulnerabilidades detectadas`. Reproducción local con texto sintético: tanto `[ERROR]: no se pudo ejecutar` como `[TIMEOUT] Comando excedio 300s` produjeron ese mensaje. Un resultado vacío de `-silent` también se traduce a «sin hallazgos» sin comprobar el exit code. Si una categoría de plantillas falta, se omite silenciosamente mientras exista al menos otra. `nuclei_update_templates()` en `:534-543` comprueba solo la presencia del directorio `http`; la fase 3 ignora su retorno (`hades_surveillance_advanced.py:278-279`).

**Acción:** separar fallos de resultados negativos; conservar salida JSONL íntegra y `template-id`, severidad, URL, matcher/evidencia y versión/hash del conjunto de plantillas. Validar las cuatro categorías antes de iniciar. Marcar cobertura `solo HTTP(S) detectado`, nunca `dispositivo sin vulnerabilidades`. Mantener un procedimiento de actualización/verificación firmado o curado para instalaciones sin Internet.

### P1 — Tshark puede capturar una interfaz ajena a la red auditada

`detect_active_interface()` en `hades_surveillance_advanced.py:36-67` selecciona por nombre y prioridad `Wi-Fi`, luego `Ethernet`, sin comprobar que la interfaz tenga la ruta hacia el CIDR objetivo ni siquiera que esté activa. `tshark -D` en este equipo enumeró ambas; la selección actual escogería Wi-Fi. Si `-D` falla, se usa la cadena fija `Wi-Fi`. En `:209-240` la captura se declara completada incluso si `execute()` devolvió error; `parse_tshark_output()` ignora líneas no tabuladas y da cero paquetes. Reproducción sintética con `[ERROR]: acceso denegado` dio `Paquetes/conexiones capturadas: 0`. El archivo `trafico_red.txt` es un volcado de campos, no un `.pcap`.

**Acción:** vincular interfaz a ruta y subred objetivo o exigir selección explícita al operador; probar apertura de captura antes del ciclo y registrar estado/error. Guardar `.pcapng` cuando se requiera trazabilidad técnica, con control de acceso y retención definidos. Mantener el resumen de campos como derivado. La etiqueta `IPs externas (internet)` en `:71-126` usa solo la negación de tres rangos RFC1918 y puede clasificar erróneamente direcciones internas no privadas, link-local o CGNAT; comparar con redes autorizadas y rutas reales.

### P1 — OpenSSL muestra datos TLS, pero no verifica por completo la identidad

`ssl_audit()` en `hades_win_master_advanced.py:545-559` invoca `openssl s_client -connect host:port -showcerts` con un pipe `echo`; no pasa `-verify_hostname`/`-verify_ip` ni `-verify_return_error`. El comportamiento de SNI por defecto depende de la entrada y de la versión de OpenSSL; al trabajar por IP no se proporciona el nombre DNS esperado. Se devuelve texto incluso si el handshake o la validación falla. `_resumen_tls()` en `:751-761` extrae algunas líneas, sin un estado TLS estructurado. La fase TLS corre solo para URLs inferidas como `https://` (`:892-905`): servicios TLS no web quedan fuera. `port` acepta enteros fuera de 1–65535.

**Acción:** distinguir handshake, confianza de cadena, vigencia e identidad DNS/IP, usando el nombre esperado del activo cuando se conoce; registrar errores y versión/cifrado como evidencia. Escanear otros servicios TLS únicamente cuando entren en el alcance pactado.

### P1 — Nmap hace inventario de servicios, no una evaluación exhaustiva de CVE

`nmap_discovery()` (`hades_win_master_advanced.py:304-335`) selecciona sondas L2/L3 según subred; `nmap_scan()` (`:338-353`) usa `-sV -O --traceroute` sobre el conjunto TCP predeterminado de Nmap. No incluye un barrido UDP general ni `--script vuln`; solo `asset_profile()` (`:371-390`) prueba UDP/137 y UDP/161 para identidad. Así, un puerto abierto o una versión detectada son evidencia de exposición/servicio, no prueba automática de vulnerabilidad. `parse_discovered_hosts()` en `hades_surveillance_advanced.py:388-394` busca líneas `Nmap scan report for ...`; si Nmap falla o no detecta hosts, `run()` devuelve `Sin hosts activos` (`:191-199`) sin comprobar el fallo. No hay registro estructurado de hosts con timeout o no alcanzables.

**Acción:** etiquetar cobertura por protocolo/puertos y razones de exclusión; separar `0 hosts confirmados` de `descubrimiento fallido/parcial`. Para cada host conservar resultado Nmap completo, versión, flags, tiempos y errores. Agregar verificaciones específicas y controladas según el contrato de alcance, sin presentar la detección de servicios como un catálogo completo de vulnerabilidades.

### P2 — Ruta MCP secundaria con semántica distinta

`hades_mcp.py:46-85` usa otra resolución de binarios y `run_tool(tool, args)`, que en Windows interpola `args` en `shell=True`; devuelve texto sin estado. El `quick_scan` de esa ruta llama `nmap -sV -T4` (`:124`), diferente del motor principal. La validación actual de objetivo limita la entrada usada allí, pero la interfaz genérica `run_tool` no garantiza esa propiedad a futuros llamadores. Conviene unificar el ejecutor y la evidencia antes de ofrecer ambas entradas como equivalentes.

## Orden de corrección y criterio de aceptación

1. **Estados verificables:** cada invocación produce `ok`, `no_findings`, `error`, `timeout`, `partial` u `omitted`; fallo de binario, Npcap, plantilla o handshake nunca se convierte en `no_findings`.
2. **Cobertura explícita:** el informe indica puertos/protocolos/plantillas realmente ejecutados, objetivos omitidos y por qué. Nuclei queda descrito como evaluación web de URLs detectadas.
3. **Tshark en interfaz correcta:** selección documentada para Ethernet/Wi-Fi y ruta al objetivo; una interfaz equivocada o inaccesible es error visible. Guardar evidencia cruda si el contrato requiere trazabilidad.
4. **TLS verificado:** separar identidad, cadena, vigencia, protocolo y cifrado; cualquier imposibilidad de evaluación queda como `indeterminado`, no como conexión segura.
5. **Informe humano e IA:** citas a la salida real de las herramientas y límites de cobertura. La IA resume y prioriza consultivamente; no crea CVE, certificados válidos ni conformidad ISO sin evidencia.

## Límites de la revisión

Esta revisión confirmó versiones, opciones de ayuda, enumeración de interfaces y reproducciones sintéticas de interpretación de errores. No verificó tráfico en Ethernet, precisión de hallazgos en un activo real, permisos efectivos de captura, validez de certificados de terceros ni completitud de las plantillas. El antecedente de escaneo Ethernet aportado por el operador se reconoce como prueba de funcionamiento en un entorno concreto, no como validación de todas las ramas de error.
