# HADES SENTINEL — auditoría para una oferta a Estado y defensa

**Fecha:** 2026-10-16  
**Alcance:** código y documentos del árbol de trabajo local; revisión estática, pruebas locales y lectura de un DOCX generado. En esta revisión no se repitió un escaneo activo ni se hizo un ensayo en una instalación aislada. El historial del proyecto registra un escaneo Ethernet real de `10.77.0.0/16` con 106 hosts detectados; el responsable del proyecto confirma que también se ejecutaron escaneos de vulnerabilidades en esa red.  
**Supuesto operativo confirmado por el responsable:** HADES se utiliza después de acordar el servicio y obtener autorización del dueño de la red. El contrato y el alcance se gestionan fuera del agente.  
**Veredicto:** **EL MOTOR YA FUE PROBADO EN RED REAL; EL PRODUCTO AÚN NO ESTÁ APTO PARA EMITIR INFORMES A CLIENTES SIN REVISIÓN**. La prioridad es la fidelidad del informe y su trazabilidad, seguida de la reproducibilidad de una instalación sin internet.

## 1. Qué hace hoy el sistema

1. `hades_server.py` sirve un dashboard sólo en `127.0.0.1:8080`, acepta un objetivo y una duración, e inicia `hades_surveillance_advanced.py` en un proceso hijo. El servidor restringe `Host`/`Origin`, limita JSON a 8 KiB y sirve archivos estáticos por lista permitida (`hades_server.py:523-746`). Esto es una protección útil para una consola local, pero no equivale a control de usuarios ni a una plataforma multioperador.
2. `hades_surveillance_advanced.py:137-379` ejecuta descubrimiento Nmap, captura Tshark, posible actualización de plantillas Nuclei, auditoría secuencial de cada host y generación de Markdown y DOCX.
3. `hades_win_master_advanced.py:304-353` distingue redes locales y enrutadas. El barrido `/16` ajusta tasa y tiempo. La auditoría por host usa Nmap `-sV -O --traceroute`, SNMP/NetBIOS, Nuclei sólo en HTTP(S), OpenSSL para HTTPS y Ollama para un comentario consultivo (`:338-545`, `:846-974`).
4. `hades_report_docx.py:124-420,679-965` vuelve a interpretar el Markdown con expresiones regulares, calcula riesgo por reglas y genera el DOCX con referencias a controles del Anexo A.
5. La IA no modifica directamente la puntuación de riesgo y se etiqueta como consultiva. La evidencia técnica se intenta persistir antes de esperar a Ollama (`hades_surveillance_advanced.py:325-349`). Son decisiones correctas, pero la publicación del informe aún no pasa una puerta de revisión humana.

## 2. Verificaciones de esta revisión

| Verificación | Resultado | Límite |
|---|---|---|
| `python tests/run_all.py` | **75/75 OK** tras la corrección del generador, exit 0 | Mayormente pruebas con mocks; no acredita cobertura ni exactitud en redes reales. |
| `python -m compileall -q` sobre los nueve módulos Python principales | exit 0 | Sólo sintaxis/importación compilable. |
| Inventario local de binarios y plantillas | Nmap, Tshark, OpenSSL, Nuclei y cuatro categorías HTTP de plantillas presentes **en este PC** | No acredita que estén incluidos en una entrega offline. |
| Historial local de ejecución | `handoff.md` registra 106 hosts en el `/16`; se conservan 17 informes maestros, nueve con sección Nuclei, uno con marcadores de severidad y tres con cadenas `CVE-` | Se observó existencia de artefactos; esta revisión no adjudicó cada hallazgo ni repitió esas corridas. |
| Lectura con `python-docx` del DOCX más reciente bajo `informes/` | Contiene la afirmación de autorización interna y texto `Metasploit ssh_login`/`msfvenom` | Confirma que el defecto del generador alcanzó un entregable real; no se expuso el contenido sensible del cliente. |
| `normalize_ollama_generate_url('https://example.com/api/generate')` | Devuelve la URL como válida | Prueba local sin realizar ninguna conexión externa. |

**Estado de Git:** rama `fix/fase4-ia-no-bloqueante`, cambios sin commit en motor, vigilancia, DOCX y pruebas; `AUDITORIA_CODIGO_2026-07-29.md` figura borrado. `handoff.md` termina en agosto y no describe todos los cambios de octubre. Las cifras 74/74 no deben confundirse con una versión reproducible y congelada.

## 3. Bloqueos P0: corregir antes de cualquier piloto con datos de una organización

### P0-1. El DOCX afirmaba actividades que HADES no realizó — corregido en el árbol local

En la revisión inicial, `hades_report_docx.py` insertaba **siempre** una tabla de seis fases con `Metasploit ssh_login`, `msfvenom`, Meterpreter, persistencia y erradicación. Ninguna de esas acciones forma parte de la ruta principal `full_audit()`. Un DOCX histórico revisado contiene esos textos. También afirmaba una “auditoría interna autorizada por la dirección” sin identificar el acuerdo real. La autorización previa existe como proceso comercial según el responsable. **Corrección aplicada y verificada:** el generador actual describe las etapas reales del motor, presenta ISO como referencia y remite la autorización al acuerdo previo sin inventar firmante. Los DOCX ya emitidos no se modificaron automáticamente; deben regenerarse antes de cualquier entrega.

**Estado y siguiente aceptación:** la prueba `tests/test_report_metodologia_real.py` genera un DOCX nuevo y comprueba ausencia de las acciones ficticias; pasa junto a la suite 75/75. Sigue pendiente incorporar en la portada una referencia concreta a la orden de trabajo y al alcance aprobado, aportados por el operador, sin obligar a HADES a gestionar el contrato. La metodología debería derivarse de eventos reales del `run_id`, con estado de cada herramienta.

### P0-2. El diseño permite enviar evidencia de red a un endpoint externo

`hades_ai.py:28-56` valida forma y ruta de `HADES_OLLAMA_URL`, pero **no exige loopback**; `hades_win_master_advanced.py:624-644` envía el prompt con datos de escaneo a esa URL. `hades_ollama_runtime.py:38-53` restringe el arranque gestionado de Ollama, pero esa restricción no protege al cliente HTTP. `safe_subprocess_env()` además propaga `HADES_OLLAMA_URL` (`hades_ai.py:125-155`). El README promete procesamiento íntegramente local.

**Corrección y aceptación:** limitar el cliente de IA a `127.0.0.1`/`::1` según política explícita, sin redirecciones; bloquear salida por firewall en el perfil air gap y probar que cualquier URL remota falla antes de construir una petición. Registrar una excepción formal sólo si un cliente futuro admite un servidor interno autorizado.

### P0-3. No existe trazabilidad suficiente para sostener cada conclusión

`hades_surveillance_advanced.py:137-151` usa carpeta por **minuto** (`informe_YYYYMMDD_HHMM`) con `exist_ok=True`; dos corridas del mismo minuto pueden sobrescribir `INFORME_MAESTRO.md`. `_persist()` captura errores de escritura y continúa. `full_audit()` también captura el error del callback de persistencia (`hades_win_master_advanced.py:908-913`), mientras el log dice que la evidencia quedó asegurada. `execute()` devuelve texto de stdout/stderr y marcadores de timeout, no un resultado tipado con código de salida (`hades_win_master_advanced.py:199-273`). El DOCX reinterpreta el Markdown por regex (`hades_report_docx.py:124-284`), sin IDs de evidencia, hashes ni versión de firmas/modelo por hallazgo.

**Corrección y aceptación:** `run_id` único, esquema JSON tipado inmutable por host y hallazgo, captura de comando/versión/código de salida/tiempo/hash de evidencia, escritura atómica y manifest firmado. Una falla de persistencia debe marcar el informe **incompleto** y bloquear su emisión. Dos corridas simultáneas o dentro del mismo minuto no deben compartir artefactos.

### P0-4. “Sin hallazgos” puede significar “la herramienta falló”

`_parse_nuclei()` omite líneas `[ERROR]`, `[STDERR]`, `[TIMEOUT]` y puede devolver “Sin vulnerabilidades detectadas” cuando no quedan findings (`hades_win_master_advanced.py:502-528`). La Fase 1 con salida vacía termina en “Sin hosts activos” (`hades_surveillance_advanced.py:191-199`), también si Nmap falló o expiró. El preflight de Nuclei comprueba el ejecutable, no la integridad/versionado de plantillas (`hades_surveillance_advanced.py:160-170`). No hay estado por fase `OK / parcial / falló / no ejecutada` propagado hasta el DOCX.

**Corrección y aceptación:** separar ausencia de hallazgos, ausencia de cobertura y error. Si Nmap/Nuclei/TLS falla o llega a timeout, el resumen ejecutivo y la tabla del host deben mostrar cobertura incompleta; nunca “sin vulnerabilidades” ni una severidad tranquilizadora por defecto.

### P0-5. Falta trasladar el alcance acordado a controles operativos del escaneo

La autorización y el acuerdo con el dueño de la red ocurren **antes** de ejecutar HADES. El software, sin embargo, no recibe el CIDR aprobado, exclusiones o ventana acordados como datos comprobables. La API acepta IP, hostname o CIDR válidos (`hades_server.py:733-746`) y en modo dashboard audita **todos** los hosts descubiertos sin selección posterior (`hades_surveillance_advanced.py:288-291`). Un `/16` puede activar miles de sondas y una Fase 4 secuencial de horas. Las variables `HADES_DISCOVERY_*` permiten modificar el ritmo (`hades_win_master_advanced.py:120-166`). Para redes OT/defensa, conviene traducir el alcance comercial aprobado a límites técnicos verificables.

**Corrección y aceptación:** importar o registrar la referencia del encargo y los CIDR/exclusiones aprobados; validar ruta/interfaz, aplicar perfiles de intensidad y límites de hosts/tiempo, y probar la parada. El escáner debe advertir o rechazar un objetivo fuera del alcance registrado. Esto documenta y ejecuta el acuerdo previo; no lo reemplaza.

## 4. Brechas P1 para producción comercial

| Área | Evidencia actual | Entregable exigido |
|---|---|---|
| **Cobertura real de dispositivos** | Nmap profundo usa puertos TCP por defecto, versión y SO; no ejecuta NSE `vuln` en el perfil por defecto (`hades_win_master_advanced.py:338-353`). Nuclei sólo apunta a categorías `http/*` y URLs web (`:171-175,:465-545,:976-999`). | Matriz por tipo de activo y protocolo (Windows/Linux, red, impresora, IoT/OT) con detecciones seguras para SMB/RDP/SSH/SNMP/DNS/TLS y clasificación explícita de “no evaluado”. No prometer detección general de CVE en todo dispositivo. |
| **Offline reproducible** | Plantillas en `%USERPROFILE%/nuclei-templates`, modelo `FROM` un blob de `C:\Users\DELL 5420`, binarios en rutas instaladas (`hades_win_master_advanced.py:34-46,171-175`; `Modelfile...:1`). Si faltan plantillas se intenta descarga (`:531-543`). `build_pendrive.sh` empaqueta otro flujo Linux basado en `hades_local.py`, no el pipeline Windows/DOCX. | Instalador Windows offline del **mismo producto**, con binarios, wheels, modelo, plantillas curadas, licencias, hashes, SBOM, firma y prueba en máquina limpia desconectada. Actualización de firmas por paquete firmado e importación controlada. |
| **Calidad de IA** | `full_audit()` resume Nmap/Nuclei/TLS por caracteres y llama a Ollama con `num_predict=260` (`hades_win_master_advanced.py:624,918-958`); un informe complejo puede truncarse. El control de cobertura sólo añade avisos (`:762-844,:967-973`). | Salida estructurada por hallazgo con citas `evidence_id`, tipo de certeza, limitaciones y recomendación. Rechazar o dejar en borrador texto que cite CVE inexistente, atribuya producto sin fuente o omita hallazgos críticos. Evaluación ciega con corpus etiquetado y métricas de precisión, recall y citas correctas; revisión humana antes de entregar. |
| **Riesgo/ISO** | `_assess_risk()` suma puntos por puertos y CVE (`hades_report_docx.py:330-363`); `_business_impact()` infiere robo/ransomware/acceso por puerto abierto (`:502-525`). `map_iso_controls()` agrega controles por reglas globales, incluso tres siempre (`:366-420`). | Separar **observación**, **vulnerabilidad confirmada**, **riesgo contextual** y **control relacionado**. Incorporar criticidad del activo, exposición, compensaciones, impacto validado por cliente, tratamiento de riesgos y Declaración de Aplicabilidad. Anexo A como referencia, nunca como declaración automática de cumplimiento. |
| **Seguridad local** | Dashboard sin usuarios, sólo loopback y guardia de origen; logs del agente se insertan con `innerHTML` (`agente HADES.html:1510,1778`), aunque el mapa sí escapa campos. | Corregir los sinks DOM; añadir CSP y pruebas con texto hostil. Para despliegue multiusuario o remoto: identidad, roles, auditoría de acciones y sesión apropiadas al entorno. |
| **Confidencialidad y retención** | `informes/` se excluye de Git, pero los reportes quedan en archivos locales sin política de cifrado, acceso, retención o borrado verificable; el Markdown incluye IPs, MAC, servicios y tráfico. | Política por cliente, ACL de directorio, cifrado de disco o artefacto, separación de clientes, exportación protegida, retención y destrucción, registro de acceso. Revisión de manejo de información sensible antes de trabajo de defensa. |
| **Calidad de entrega** | Versiones divergentes: dashboard 2.2.0, vigilancia 2.1.0, CLI 1.3.0; documentación `FLUJO_DE_ESCANEO.md` incluye pasos viejos y sugiere un auditor IA certificado. `requirements.txt` tiene mínimos, sin lockfile. | Una versión de producto, build reproducible y firmada, CI, dependencias fijadas, matriz de sistemas compatibles, manual operativo vigente, soporte/actualización, política de vulnerabilidades y plan de incidentes. |

## 5. ISO 27001 y propuesta de valor correcta

ISO/IEC 27001:2022 define requisitos de un **sistema de gestión de seguridad de la información** y un proceso de riesgos de la organización; la Declaración de Aplicabilidad exige justificar controles en su contexto. Un escaneo y un DOCX pueden aportar evidencia para controles como A.8.8, A.8.20 y A.8.21, pero **no certifican la entidad ni prueban por sí solos que un control esté implantado**. El producto debería venderse como “levantamiento técnico de exposición y vulnerabilidades con evidencia trazable y referencias a ISO/IEC 27001:2022”, no como auditoría de cumplimiento automático.

**Posicionamiento técnico:** Nmap, Nuclei, Tshark y OpenSSL son herramientas ejecutadas por el motor; sus salidas son evidencia técnica real de la corrida cuando el proceso finaliza correctamente. La IA local interpreta y redacta después de esa recolección; no debe inventar pruebas ni convertir un puerto abierto en CVE confirmado. La norma ISO es el **marco de referencia para contextualizar y ordenar recomendaciones**. “Herramienta real” no significa cobertura completa de todos los protocolos ni que todo hallazgo sea concluyente: el informe debe mostrar qué se ejecutó, qué respondió, qué falló y qué quedó sin evaluar.

Estructura objetivo del informe:

1. Portada: cliente, alcance aprobado, `run_id`, fecha, versión/hashes de motor, firmas y modelo, estado `borrador / revisado / emitido`.
2. Resumen ejecutivo: cobertura, hallazgos confirmados, incertidumbres, riesgos contextualizados y prioridades; cero afirmaciones de explotación no realizada.
3. Inventario y metodología **ejecutada**: activos, redes, perfiles, herramientas, versiones, duración, exclusiones, fallas y limitaciones.
4. Hallazgo por activo: ID, evidencia cruda con hash, regla/firma y versión, servicio y puerto, condición observada, certeza, CVE sólo con vínculo probado, remediación y responsable/plazo acordados.
5. Referencia ISO: control potencialmente relacionado, motivo y evidencia observada; campo para validación de aplicabilidad y eficacia por el cliente. No marcar conformidad automáticamente.
6. Comentario IA consultivo con citas a IDs de hallazgo, controles de calidad, revisor humano, fecha y decisión editorial. El comentario no altera la evidencia ni la severidad determinista.
7. Anexo técnico y cadena de custodia: resultados completos, hashes, errores y omisiones, límites del escaneo y estado de las fuentes offline.

**Fuentes normativas verificadas:**

- ISO, [ISO/IEC 27001:2022](https://www.iso.org/standard/27001): requisitos SGSI y gestión de riesgo adaptada a la organización.
- Grupo de Prácticas de Auditoría ISO/IEC 27001, [Declaración de Aplicabilidad](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/ISO-IECJTC1-SC27-WG1_N3298_Auditing%20Practices%20Note%20-%20SoA.pdf): selección/justificación de controles según contexto y riesgo.
- BCN Chile, [Ley 21.663](https://www.bcn.cl/leychile/navegar?idNorma=1202434): marco de ciberseguridad y competencias estatales; para un cliente concreto hay que validar las bases, clasificación de información y políticas institucionales aplicables. Esta revisión no reemplaza asesoría jurídica ni acredita homologación para defensa.
- OWASP, [LLM09:2025 Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/): riesgo de decisiones apoyadas en afirmaciones generadas sin validación.

## 6. Ruta recomendada y puertas de aceptación

### Etapa A — integridad del informe y control de escaneo (P0)

- Mantener la regresión que impide texto ficticio en el DOCX. Incorporar la referencia verificable del encargo previo, evidencia tipada, estados de fase y `run_id` único.
- Restringir IA a endpoint autorizado local. Distinguir fallo de Nmap/Nuclei/TLS de resultado negativo.
- Trasladar el alcance autorizado ya acordado a CIDR/exclusiones y límites del escaneo; añadir perfil seguro y preflight de ruta/interfaz.
- **Puerta:** 100% de afirmaciones del DOCX de prueba trazables a evidencia o a datos aprobados del encargo; cero afirmaciones de explotación inventadas; cero conexiones externas en ensayo air gap; ningún fallo de herramienta reportado como “sin hallazgos”.

### Etapa B — cobertura y evaluación (P1)

- Definir mercados objetivo y perfiles de activo. Empezar por una oferta acotada: redes TI Windows/Linux/equipos de red; OT/defensa sólo con perfil y autorización específicos.
- Construir corpus de laboratorio con positivos, negativos, falsos positivos, banners adversarios, datos incompletos, TLS/SNMP/Nuclei y fallo offline. Medir precisión de hallazgos, recall por protocolo, errores de CVE y calidad de citas IA.
- Revisar y firmar por analista cada informe de piloto. Validar con responsables de TI que prioridad e impacto reflejen el contexto real.
- **Puerta:** cobertura publicada por protocolo; tasas de falsos positivos/negativos medidas; reproducibilidad de cada hallazgo; revisión humana documentada.

### Etapa C — producto entregable y financiamiento

- Paquete offline Windows reproducible y firmado, actualización por medios controlados, SBOM/licencias, prueba en equipo limpio y sin Internet.
- Manual de operación, despliegue, permisos, recuperación, retención, soporte y respuesta a vulnerabilidades del producto.
- Piloto autorizado en una institución **no crítica** primero; luego evaluación específica con un organismo de Estado/defensa conforme a sus reglas de acceso, clasificación y contratación.
- **Puerta:** acta de piloto con alcance, métricas, muestras de informe verificadas, incidentes, límites conocidos, costos de operación y plan de mantenimiento. Esto constituye evidencia razonable para una postulación; no equivale a acreditación gubernamental.

## 7. Lo que no se verificó

- Esta revisión no repitió el escaneo de red real ya documentado por el proyecto y confirmado por el responsable; tampoco comprobó el comportamiento en una máquina nueva desconectada.
- No se auditó el binario real de Nmap/Nuclei/Ollama, ni el contenido de las plantillas descargadas o el modelo; sólo rutas y existencia local.
- No se revisó un corpus de informes con adjudicación humana ni se midieron falsos positivos/negativos del sistema.
- No se evaluaron requisitos particulares de una licitación o de información clasificada: dependen del organismo y del encargo.
