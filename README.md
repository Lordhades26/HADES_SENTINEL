# HADES SENTINEL
> Agente de auditoría de red que ejecuta herramientas técnicas locales y convierte sus resultados en informes con ISO/IEC 27001:2022 como marco de referencia.

HADES se ejecuta después del acuerdo y la autorización del titular de la red. El alcance operativo debe corresponder a lo pactado con el cliente. Nmap, Tshark, Nuclei y OpenSSL producen los resultados técnicos; la IA local aporta una interpretación consultiva y no sustituye la evidencia de esas herramientas ni la revisión del analista. La referencia a ISO/IEC 27001:2022 ayuda a relacionar hallazgos con controles, pero el escaneo no certifica el SGSI ni determina por sí solo su conformidad.

## Características
- **Auditoría de Red Local (On-Premise):** Las herramientas de escaneo y el modelo por defecto operan en el equipo. Antes de usar datos sensibles, debe verificarse la configuración efectiva del endpoint de IA y de las actualizaciones de plantillas.
- **Referencia a ISO/IEC 27001:2022:** Relaciona hallazgos técnicos con controles del Anexo A para apoyar el análisis del cliente, sin afirmar conformidad automática.
- **Pipeline de Escaneo Determinista de 5 Fases:**
  1. *Descubrimiento de Hosts (Adaptativo):* Barrido de hosts activos mediante Nmap que se ajusta al objetivo: ARP en la propia subred (capa 2, máxima fiabilidad) o sondas de capa 3 acotadas (ICMP echo/timestamp, TCP SYN/ACK y UDP a puertos comunes, con timing limitado) cuando el objetivo está enrutado tras un router.
  2. *Live Tshark Capture:* Captura de tráfico en tiempo real para análisis de flujos y protocolos.
  3. *Nuclei Update:* Verificación de plantillas locales; si faltan, el agente intenta descargarlas, por lo que una instalación aislada debe incluirlas previamente.
  4. *Auditoría Profunda:* Escaneo de puertos, versiones y certificados SSL/TLS; Nuclei evalúa los servicios web detectados con las plantillas disponibles. Los CVE se reportan sólo cuando constan en la evidencia de herramientas.
  5. *Consolidación de Informes:* Compilación automática del reporte técnico consolidado e informe ejecutivo.
- **Generación de Reportes con Marca Blanca (White-Label):** Configuración de plantillas en formato Microsoft Word (`.docx`) altamente personalizables para añadir logotipos de clientes, colores corporativos primarios y secundarios, y pies de página comerciales.
- **Dashboard Web Interactivo y Seguro:** Panel táctico en puerto `8080` que ofrece consola integrada, un mapa de red en 3D dinámico y monitores de rendimiento para el seguimiento del uso de CPU, GPU y RAM.
- **Dashboard Local sin Fricción:** El panel se abre directamente, sin pantalla de inicio de sesión. El aislamiento se apoya en que el servidor escucha solo en loopback (`127.0.0.1`) y en una guardia de mismo origen que rechaza peticiones con `Origin`/`Host` ajenos, cerrando los vectores CSRF y de DNS rebinding sin pedir credenciales al usuario.
- **Análisis por Inteligencia Artificial Consultiva:** Integración opcional con modelos de lenguaje locales a través de Ollama para la generación de análisis consultivos adicionales sin comprometer la privacidad del entorno de red.
- **Matriz de Riesgos Corporativa:** Cuantificación determinista de la probabilidad e impacto de cada amenaza, representada mediante una tabla visual a nivel ejecutivo.
- **Cierre y Parada Limpia de Procesos:** Mecanismo integrado para la detención limpia de todos los subprocesos de red y herramientas del sistema en ejecución, impidiendo procesos huérfanos.

## Tecnologías
- **Lenguaje Principal:** Python 3.10+ (gestión del backend, procesamiento de reportes y orquestación).
- **Descubrimiento y Escaneo:** Nmap (análisis de red, detección de puertos y versiones de sistemas operativos).
- **Análisis de Tráfico:** Tshark / Wireshark (captura activa de tramas de red local y flujos de paquetes).
- **Detección de Vulnerabilidades:** Nuclei (ejecutor de pruebas de seguridad y firmas de CVE de ProjectDiscovery).
- **Auditoría TLS/SSL:** OpenSSL (validación profunda de certificados y suites de cifrado).
- **Inteligencia Artificial Local:** Ollama (servicio local de inferencia de modelos sin consumo de recursos de internet).
- **Librerías Python Clave:**
  - `python-docx` (generación automática y diseño personalizado de archivos Word `.docx`).
  - `psutil` (monitoreo del sistema local y gestión de procesos del agente).
- **Frontend del Dashboard:** HTML5, CSS3, JavaScript (incluyendo visualización tridimensional para la cartografía de red local).

## Modelo de IA local

HADES usa por defecto `HADES-SENTINEL-ANALYST:1.0.0`, un wrapper versionado
sobre `dolphin3:8b` (Llama 3.1 8B, cuantización Q4_K_M). La configuración
operativa está centralizada en `hades_ai.py`: endpoint
`http://127.0.0.1:11434/api/generate`, contexto de 8192 tokens, salida máxima
de 640 tokens, temperatura 0, sin reintentos, streaming y límite de 300 segundos por análisis
(1.200 por corrida); si se agota, se conserva el texto parcial.

La IA es exclusivamente consultiva: no ejecuta acciones, no confirma CVE que
no estén presentes literalmente en la evidencia y no altera hallazgos,
severidades ni la matriz de riesgo determinista. Todo bloque generado queda
marcado como no verificado y requiere validación humana.

Para reconstruir el modelo:

```powershell
ollama create HADES-SENTINEL-ANALYST:1.0.0 -f .\Modelfile.hades-sentinel-analyst
ollama show HADES-SENTINEL-ANALYST:1.0.0
```

Ollama debe escuchar únicamente en `127.0.0.1:11434`. No se requiere una API
key para el servicio local y el dashboard no accede directamente a Ollama
desde el navegador. Las variables `HADES_MODEL`, `HADES_OLLAMA_URL` y
`HADES_AI_TIMEOUT` permiten ajustes operativos explícitos.

### Recuperación conservadora de Ollama

`hades_ollama_runtime.py` comprueba el servicio local al iniciar el dashboard y
antes del primer uso de IA en modo CLI. Si la API ya responde, no reinicia ni
duplica el proceso. Si el puerto está libre y encuentra un `ollama.exe` local
verificable, puede iniciar `ollama serve` oculto con un entorno saneado.

El runtime nunca mata procesos preexistentes, solicita elevación, modifica
Windows Firewall ni ejecuta rutas recibidas desde el dashboard. Si el puerto
está ocupado por un listener que no responde, informa
`blocked_stale_listener` y HADES continúa sin IA.

Estados de diagnóstico:

- `healthy`: servicio ya disponible;
- `started`: servicio iniciado de forma segura por HADES;
- `disabled`: IA deshabilitada mediante `HADES_SKIP_AI=1`;
- `missing_binary`: no se encontró un binario local verificable;
- `blocked_stale_listener`: puerto ocupado por un servicio no saludable;
- `startup_failed`: el proceso propio no inició correctamente;
- `unsupported_endpoint`: endpoint distinto del loopback local permitido.

Ninguno de estos estados cambia evidencia, severidad, riesgo ni el código de
salida de la auditoría determinista.

## Alcance, token y estados de las herramientas

- **Alcance autorizado.** Por defecto sólo se escanean redes privadas
  (RFC 1918, CGNAT 100.64/10, link-local, loopback y ULA IPv6) con un prefijo
  mínimo /16 (IPv4) o /64 (IPv6). Para el alcance acordado con el titular de
  la red: `HADES_ALCANCE="198.51.100.0/24,10.20.0.0/16"`. Los hostnames se
  resuelven y todas sus IP deben quedar dentro. Aplica al dashboard, al motor,
  al MCP y a `hades_local.py`.
- **Token de sesión.** Cada arranque del dashboard genera un token que se
  inyecta en la página y se guarda en `.hades_token` (sólo para el usuario).
  `POST /api/scan` y `/api/stop` lo exigen en la cabecera `X-Hades-Token`;
  `DETENER_HADES.bat` lo lee del archivo.
- **Estados de herramientas.** Un error, corte por tiempo o salida ilegible
  nunca se informa como «sin hallazgos»: Nuclei/TLS/Tshark quedan como
  ERROR, TIMEOUT, PARCIAL, OMITIDO o «no concluyente», y un host cuyo Nmap
  falló aparece con riesgo **NO EVALUADO**. Códigos de salida de la vigilancia:
  0 completa, 1 algún host sin auditar, 2 descubrimiento fallido o sin Nmap.
- **Variables con flags** (`HADES_DISCOVERY_*_FLAGS`, `HADES_NMAP_HOST_TIMEOUT`)
  se validan: valores con `& | ; $ ( ) "` u otros metacaracteres se rechazan.
- **Tests de aprobación:** `tests/approval.py` + `tests/approved/`. Si un
  golden cambia, revisar el `.received.txt` y aprobar con `HADES_APPROVE=1`.

## Estructura del Proyecto
```bash
HADES_SENTINEL/
├── .github/                       # Plantillas de GitHub y archivos de configuración comunitaria
│   ├── ISSUE_TEMPLATE/            # Plantillas estandarizadas para reporte de errores y nuevas características
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   └── feature_request.yml
│   ├── FUNDING.yml                # Canales y enlaces de financiación del proyecto
│   └── PULL_REQUEST_TEMPLATE.md   # Plantilla estándar para propuestas de código
├── assets/                        # Recursos visuales del proyecto y documentación
│   ├── logo_hades_sentinel_doc.png # Logotipo adaptado para documentos oficiales
│   ├── logo_hades_sentinel.png     # Logotipo oficial del proyecto para la interfaz
│   └── screenshots/               # Capturas de pantalla del dashboard y reportes en acción
│       ├── 01_dashboard_live.png
│       ├── 02_dashboard_resources.png
│       ├── 03_traffic_capture.png
│       ├── 04_severity_table.png
│       ├── 05_risk_matrix.png
│       └── 06_iso27001_mapping.png
├── vendor/                        # Librerías de terceros locales empaquetadas sin conexión externa
│   └── hades-graph-bundle.js      # Biblioteca para renderizado de gráficos tridimensionales
├── .gitignore                     # Archivo de exclusiones de Git (evita subir credenciales e informes de escaneo)
├── agente HADES.html              # Archivo de inicio del agente interactivo local
├── build_pendrive.sh              # Script Bash para empaquetar el ecosistema de forma portable en un USB
├── CONTRIBUTING.md                # Directrices de contribución técnica al repositorio
├── DETENER_HADES.bat              # Script Batch de Windows para detención forzosa y limpia de procesos activos
├── FLUJO_DE_ESCANEO.md            # Documentación detallada del flujo y ciclo de vida del escaneo
├── hades_local.py                 # Módulo de interfaz local CLI para la ejecución rápida
├── hades_ai.py                    # Contrato central del modelo IA consultivo y entorno seguro
├── hades_mcp.py                   # Conector y adaptador Model Context Protocol (MCP) para agentes de IA
├── hades_report_docx.py           # Generador automático del reporte ejecutivo ISO/IEC 27001 en formato Word
├── hades_server.py                # Servidor backend multi-hilo para el dashboard con protección CSRF
├── hades_surveillance_advanced.py # Coordinador del motor del pipeline de escaneo de 5 fases
├── hades_win_master_advanced.py   # Controlador de llamadas de sistema a binarios externos locales (Nmap, etc.)
├── install_tools.sh               # Script Bash para instalar las herramientas y binarios base requeridos
├── LANZAR_DASHBOARD.bat           # Script Batch de Windows para iniciar el servidor web y lanzar el navegador
├── LANZAR_HADES.bat               # Script Batch de Windows para ejecutar la auditoría de red mediante terminal
├── LICENSE                        # Licencia del proyecto (MIT)
├── LICENSE-APACHE                 # Licencia alternativa Apache 2.0
├── LICENSE-MIT                    # Archivo de licencia MIT secundaria
├── MANUAL_USUARIO.md              # Guía completa de instalación, despliegue y manual operativo del usuario
├── Modelfile.hades-sentinel-analyst # Modelo local versionado sobre Dolphin 3 Q4_K_M
├── network_map_3d.js              # Controlador en JavaScript para el mapa interactivo tridimensional
├── README.md                      # Documentación general y técnica principal del proyecto
├── requirements.txt               # Dependencias Python necesarias para el funcionamiento del agente
├── SECURITY.md                    # Política de seguridad y reporte seguro de incidentes
└── uninstall.sh                   # Script Bash para remover la instalación y binarios locales
```
