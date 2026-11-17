# Plan de corrección paso a paso — HADES SENTINEL

**Fecha de base:** 2026-10-16  
**Estado de partida:** el operador confirma una prueba Ethernet con detección de vulnerabilidades. La revisión local confirmó que Nmap, Nuclei, Tshark y OpenSSL están instalados y que `python tests/run_all.py` terminó 75/75; esto no equivale a una versión lista para clientes.  
**Fuentes internas:** `AUDITORIA_PRODUCCION_ESTADO_DEFENSA_2026-10-16.md` y `REVISION_EJECUCION_HERRAMIENTAS_2026-10-16.md`.  
**Producto objetivo para primera salida:** aplicación Windows local, un operador por estación, redes con o sin Internet, escaneo dentro del alcance previamente acordado con el titular de la red, informe técnico y ejecutivo revisados por una persona. La IA local redacta y sugiere; el motor determinista decide estados, evidencia y severidad. ISO/IEC 27001:2022 es referencia para ordenar recomendaciones, no certificación automática.

## Reglas de avance

- Una etapa se cierra con artefacto, prueba reproducible y evidencia registrada. La suite existente en verde es condición necesaria, no suficiente.
- `error`, `timeout`, `parcial`, `omitido`, `sin respuesta` y `sin hallazgos` son estados diferentes en toda la cadena. Ningún fallo se presenta como resultado negativo.
- Un hallazgo sólo se entrega si remite a evidencia técnica real de esta corrida. Una afirmación de la IA sin evidencia se elimina o queda marcada para revisión, sin cambiar la severidad.
- Las pruebas activas se ejecutan sólo en laboratorio propio o en el alcance acordado para el piloto. Los ejemplos de prueba automatizada usan datos sintéticos.
- Las decisiones sobre clasificación de información, retención, homologación, adquisición pública y políticas de defensa se validan con la institución destinataria; el software no debe prometer una aprobación genérica.

## Secuencia y dependencias

| Hito | Trabajo | Dependencia | Resultado que desbloquea |
|---|---|---|---|
| 0 | Congelar línea base y alcance del producto | ninguna | versión comparable y backlog cerrado |
| 1 | Ejecución y estados tipados | 0 | herramientas confiables para informar |
| 2 | Alcance, interfaz y límites operativos | 1 | piloto seguro y repetible |
| 3 | Evidencia, almacenamiento e informe | 1–2 | informe auditable |
| 4 | IA consultiva y referencia ISO | 3 | texto defendible ante cliente |
| 5 | Seguridad y confidencialidad | 0–4 | uso con información sensible |
| 6 | Instalación y operación offline | 1–5 | paquete reproducible |
| 7 | Validación de laboratorio y piloto | 1–6 | datos de desempeño y calidad |
| 8 | Liberación, soporte y dossier de financiamiento | 7 | candidatura y versión de producción |

Las etapas 5 y 6 pueden prepararse en paralelo una vez fijado el esquema de evidencia; la puerta de producción exige cerrar todas. Estimación orientativa para un equipo con ingeniería, QA y analista de seguridad dedicados: **12–20 semanas hasta un piloto controlado**, más el tiempo que requieran acuerdos institucionales, ensayos y homologaciones. Es una estimación de planificación, no un plazo prometido.

## Hito 0 — Línea base, alcance comercial y criterios de liberación

**Tareas**

1. Crear una rama/release candidate a partir del árbol local, revisar los cambios sin commit y recuperar o documentar el archivo `AUDITORIA_CODIGO_2026-07-29.md` marcado como borrado. No mezclar artefactos de auditorías pasadas con la versión candidata.
2. Fijar una única versión de producto para dashboard, motor, CLI, DOCX, plantillas y modelo. Registrar commits, versiones de dependencias y hash del paquete.
3. Definir tres perfiles comerciales y técnicos: **laboratorio**, **piloto institucional** y **producción local**. Para la primera liberación, comprometer cobertura real: descubrimiento, inventario de servicios TCP, perfilado puntual SNMP/NetBIOS, plantillas Nuclei HTTP(S), captura en interfaz seleccionada y comprobaciones TLS de servicios admitidos. Documentar protocolos no evaluados.
4. Aprobar un formato de encargo operativo: identificador del acuerdo previo, CIDR/hosts permitidos, exclusiones, ventana, intensidad máxima, interfaz esperada, contacto de parada y política de conservación. El acuerdo con el titular existe fuera de HADES; esta ficha lo traduce a parámetros ejecutables.
5. Convertir este plan en issues con responsable, estimación y evidencia de cierre. Definir quién puede declarar un informe `emitido`.

**Entregables:** manifiesto de versión, matriz de alcance/cobertura, plantilla de ficha operativa, backlog priorizado.  
**Puerta:** cualquier tercero del equipo puede reconstruir el mismo código y explicar exactamente qué funciones están dentro de la versión candidata.

## Hito 1 — Motor de herramientas sin falsos negativos

**Tareas**

1. Sustituir el contrato de `execute()` (`hades_win_master_advanced.py:199`) por un resultado tipado: `tool`, `argv`, `version`, `started_at`, `duration`, `exit_code`, `status`, `stdout_path/hash`, `stderr_path/hash`, `timed_out`, `error`. Usar argumentos como lista y evitar `shell=True`; donde se requiera shell, aislarlo y justificarlo.
2. Definir transiciones permitidas: `not_run → running → succeeded|no_findings|partial|failed|timed_out|cancelled`. `no_findings` exige ejecución completa, código de salida aceptado y parser válido. Un timeout con hallazgos queda `partial` con hallazgos conservados.
3. **Nmap:** conservar salida completa y estructurar hosts, puertos, servicio, versión, sondas y errores. Distinguir `0 hosts confirmados` de descubrimiento fallido. Registrar puertos TCP realmente cubiertos y perfiles UDP puntuales. Hacer explícito que `-sV/-O` no confirma CVE ni sustituye comprobaciones específicas.
4. **Nuclei:** validar las cuatro carpetas de plantillas y su manifiesto antes de ejecutar; conservar JSONL original, `template-id`, severidad, URL y evidencia/matcher. Corregir `_parse_nuclei()` para que error/timeout jamás produzca «sin vulnerabilidades». Registrar omisiones por URL, categoría y motivo. Versionar o hashear plantillas locales.
5. **Tshark:** validar interfaz y permisos antes de iniciar; reflejar fallo de captura como fallo, no como cero paquetes. Capturar `.pcapng` sólo si el contrato de datos lo exige; si se conserva, aplicar cifrado/retención. Mantener el resumen tabular derivado con referencia al archivo origen.
6. **OpenSSL:** validar puerto 1–65535; separar `handshake`, cadena, vigencia, identidad esperada DNS/IP, protocolo y cifrado. Usar verificación explícita cuando se conoce la identidad; mostrar `indeterminado` si no se conoce. Registrar handshake y errores crudos.
7. Unificar la ruta secundaria `hades_mcp.py` con el mismo ejecutor o retirarla del producto distribuido hasta lograr paridad. Preflight debe comprobar ejecución y versiones, no sólo existencia de archivos.

**Pruebas de aceptación:** binario ausente, salida vacía exit 0, exit no cero, JSONL malformado, falta de plantillas, acceso de captura denegado, timeout con y sin hallazgos, certificado vencido/identidad incorrecta y cancelación. En todos los casos el estado debe persistir igual en motor, API, Markdown y DOCX. Repetir suite existente.  
**Puerta:** cero casos conocidos en que un fallo de herramienta termine etiquetado como «sin hallazgos».

## Hito 2 — Alcance autorizado, ruta de red y control de impacto

**Tareas**

1. Añadir a cada corrida la ficha operativa aprobada del hito 0; verificar que cada objetivo expandido, URL y host descubierto pertenezca a los rangos permitidos y no a exclusiones. Mostrar la referencia del encargo sin afirmar aprobación interna inventada.
2. Resolver la interfaz de captura contra la ruta al objetivo; permitir selección explícita cuando haya varias NIC, VPN o redes sin puerta de enlace. Eliminar prioridad fija Wi-Fi y fallback silencioso. Registrar identificador de interfaz, IP, máscara y ruta usada sin incluir datos innecesarios en el informe ejecutivo.
3. Crear perfiles de intensidad **conservador**, **estándar** y **personalizado aprobado** con límites de tasa, concurrencia, hosts, tiempo y captura. Para OT/entornos sensibles, usar el perfil conservador y exclusiones de protocolo/host acordadas.
4. Mantener parada manual y automática por ventana/tiempo; registrar cancelación por fase y comprobar que no queden procesos hijos. Un `/16` no debe iniciar auditoría profunda ilimitada sin límite de hosts/tiempo del encargo.
5. Probar red local Ethernet, Wi-Fi, red enrutada y red sin Internet en laboratorio. Añadir casos con dos interfaces activas y con ruta ambigua.

**Entregables:** esquema de encargo, validador de alcance, selector de interfaz, límites por perfil, bitácora de parada.  
**Puerta:** intento fuera de alcance bloqueado y registrado; la interfaz seleccionada coincide con la ruta o con la elección explícita del operador; el timeout termina todos los procesos del trabajo.

## Hito 3 — Cadena de evidencia y nuevo modelo de informe

**Tareas**

1. Generar `run_id` único desde el inicio; guardar cada corrida en carpeta exclusiva, sin colisión por minuto. Escribir de forma atómica y reportar fallos de disco; un error de persistencia bloquea la emisión.
2. Crear un esquema versionado JSON por corrida, activo y hallazgo. Cada hallazgo incluye `finding_id`, `evidence_id`, fuente, comando/perfil, estado, marca de tiempo, hash de evidencia, servicio/puerto, condición observada, certeza y límites. El JSON es la fuente de verdad; Markdown y DOCX son renderizados, no parsers independientes de texto libre.
3. Mantener separadas cuatro categorías: observación, vulnerabilidad confirmada por prueba, inferencia de riesgo y control ISO relacionado. Un puerto abierto no genera por sí solo CVE, explotación ni impacto empresarial específico.
4. Añadir cobertura y omisiones por host y por fase. El resumen ejecutivo debe mostrar `evaluado`, `parcial`, `no evaluado` y motivo. Una fase fallida no obtiene severidad baja por defecto.
5. Implementar estados `borrador`, `revisado`, `emitido` con identidad del revisor, fecha y registro de cambios. Solo una persona revisora puede emitir. Guardar manifiesto de hashes de artefactos y versión de reglas, plantillas y modelo; definir firma del paquete de entrega si el cliente la requiere.
6. Actualizar DOCX para mostrar metodología realmente ejecutada, alcance acordado, resumen de evidencias y vínculo entre recomendaciones y hallazgos. Regenerar cualquier informe histórico que se quiera usar como muestra comercial; nunca enviar los DOCX antiguos con fases ficticias.

**Pruebas de aceptación:** dos corridas simultáneas no comparten archivos; disco lleno o permiso denegado detiene emisión; cada conclusión del DOCX remite a un `evidence_id` válido; error de fase visible hasta la portada.  
**Puerta:** un analista ajeno a la implementación puede reconstruir de qué herramienta, salida y corrida proviene cada hallazgo.

## Hito 4 — IA interna e ISO 27001 con control editorial

**Tareas**

1. Enviar al modelo sólo hallazgos estructurados, cobertura y fragmentos de evidencia seleccionados. Evitar truncar silenciosamente: fragmentar por host/hallazgo y registrar lo que el modelo vio. Tratar banners, páginas web y tráfico como datos no confiables.
2. Exigir salida estructurada con referencias a `finding_id`/`evidence_id`, certeza, impacto condicionado y recomendación. Rechazar CVE o afirmaciones fácticas sin cita válida; dejar el comentario en `borrador` si omite hallazgos relevantes o contradice el estado técnico.
3. Mantener cálculo de severidad/riesgo fuera del LLM. Definir reglas transparentes y versionadas; incorporar criticidad del activo e información contextual validada por el cliente, con opción `desconocido`.
4. Mapear cada control ISO/IEC 27001:2022 como **referencia posible** justificada por evidencia. Separar aplicabilidad y eficacia de controles: esas decisiones corresponden al SGSI del cliente y a su Declaración de Aplicabilidad. El informe no usa lenguaje de certificación o conformidad automática.
5. Evaluar la IA sobre un corpus congelado con casos reales anonimizados y sintéticos: hallazgos confirmados, benignos, fallas de herramienta, certificados inválidos, prompts maliciosos en banners y escaneos parciales. Medir citas correctas, CVE inventados, omisiones críticas y desacuerdos con revisores. Fijar umbrales antes del piloto y conservar actas de adjudicación.
6. Permitir operar sin IA. Su caída debe dejar el informe técnico íntegro y etiquetar el comentario consultivo como `no generado`.

**Puerta:** ningún CVE inventado ni hecho sin fuente alcanza el estado `emitido` en el corpus de liberación; todo informe de piloto recibe revisión humana documentada.

## Hito 5 — Seguridad, privacidad y operación institucional

**Tareas**

1. Restringir la API de Ollama a loopback en el producto local, impedir redirecciones a destinos externos y probar fuga de prompts. Si se contempla servidor IA interno, diseñar una política separada y explícita por cliente.
2. Corregir inserciones de logs con `innerHTML` en `agente HADES.html:1510,1778`; usar nodos de texto y revisar otras superficies DOM. Añadir pruebas con nombres de host y banners hostiles. Mantener el dashboard en loopback hasta que exista una arquitectura multiusuario probada.
3. Validar rutas de binarios, integridad y permisos; fijar dependencias. Revisar `shell=True` y argumentos configurables en los puntos de entrada. Realizar revisión de seguridad del backend y de la cadena de actualización.
4. Definir clasificación de reportes, ACL por cliente, cifrado de disco/artefactos, almacenamiento temporal, exportación, copia de seguridad, retención y destrucción. Minimizar datos de captura; el `.pcapng` sólo debe conservarse si es necesario para el encargo.
5. Implementar bitácora de operador: inicio, cambios de alcance, parada, exportación, revisión y emisión. Para una edición remota o multioperador, diseñar identidad, roles y sesiones como producto separado; no presentar el dashboard local como ese producto.
6. Preparar procedimiento de incidentes, reporte de vulnerabilidades, mantenimiento y parches de firmas/binarios. Hacer una revisión independiente de seguridad antes de liberar.

**Puerta:** pruebas de fuga al endpoint IA y de inyección DOM negativas, revisión de seguridad sin fallos críticos abiertos, y política de datos aprobada para el tipo de información del piloto.

## Hito 6 — Paquete Windows reproducible, con y sin Internet

**Tareas**

1. Empaquetar el pipeline Windows que genera el DOCX: Python/dependencias fijadas, Nmap/Npcap, Nuclei y plantillas curadas, Tshark/Npcap, OpenSSL, Ollama/modelo y recursos del dashboard. El `build_pendrive.sh` actual prepara otro flujo Linux y no sirve como prueba de esta entrega.
2. Eliminar rutas absolutas de la máquina del desarrollador, en especial `Modelfile.hades-sentinel-analyst`; resolver rutas desde instalación/configuración. Crear manifiesto con hashes, versiones, licencias y SBOM. Determinar el derecho de redistribución de cada componente antes de incluirlo.
3. Diseñar actualización offline por paquete importable, autenticado y reversible, con versiones de binarios, reglas y plantillas. No intentar descargar durante una corrida aislada; registrar fecha de última actualización y cobertura en el informe.
4. Instalar en Windows limpio y desconectado; comprobar arranque, selección de interfaz, escaneo de laboratorio, inferencia local, DOCX, parada y desinstalación. Repetir con Internet habilitado para verificar que no cambie la semántica ni salgan datos sin autorización.
5. Documentar requisitos de hardware, Windows/Npcap, privilegios, consumo, almacenamiento, copia de seguridad, recuperación y degradación sin IA.

**Puerta:** una persona que no desarrolló el producto puede instalar y completar el caso de prueba offline usando sólo el paquete y el manual; hashes y versiones del resultado coinciden con el manifiesto.

## Hito 7 — Ensayo y piloto controlado

**Tareas**

1. Construir laboratorio con servicios web vulnerables y sanos, certificados válidos/vencidos/discordantes, hosts filtrados, varias NIC y segmentos sin Internet; conservar resultados esperados y falsos positivos conocidos.
2. Ensayar escenarios de fallo: Npcap sin permisos, binario ausente, plantillas corruptas, falta de disco, timeout, caída de Ollama, cancelación y reinicio. Medir tasa de estados correctamente clasificados, cobertura por protocolo, duración por tamaño de red, consumo y capacidad de recuperación.
3. Ejecutar un piloto con alcance acotado y acuerdo previo del dueño de la red. Un analista contrasta una muestra de hallazgos con la salida cruda, valida falsos positivos y firma cada informe. Comparar la calidad del informe con la prueba Ethernet ya realizada, sin reutilizar hallazgos históricos como prueba nueva.
4. Registrar tickets de defectos y repetir el piloto tras correcciones que afecten evidencia, alcance o informe. Mantener un registro de limitaciones conocidas y excluidas por contrato.

**Criterios de salida:** 100 % de fallos inducidos del laboratorio aparecen como error/parcial/omitido; 100 % de hallazgos emitidos en la muestra auditada poseen evidencia rastreable; cero afirmaciones de explotación o conformidad ISO sin prueba; cero procesos de escaneo huérfanos tras parada; informe y operación aceptados por el revisor del piloto. Documentar tamaño de muestra y límites para no exagerar estas métricas.

## Hito 8 — Liberación y expediente de financiamiento

**Tareas**

1. Publicar una versión candidata firmada con notas de cambio, matriz de compatibilidad, manifiesto/SBOM, instrucciones de verificación, política de soporte y procedimiento de actualización offline.
2. Cerrar manual de operador, guía de instalación, guía de revisión de informes, límites de cobertura, política de tratamiento de datos y respuesta a incidentes. Actualizar `PRODUCCION_READINESS.md`, que conserva cifras y estados de julio de 2026.
3. Preparar dossier para financiamiento: problema institucional, solución y diferenciación offline, arquitectura, pruebas Ethernet y piloto con autorización, métricas con denominadores, brechas aún abiertas, presupuesto por hito, cronograma, costos de licencias/soporte y plan de adopción. Usar muestras anonimizadas y evidencias de demostración reproducibles.
4. Separar el mensaje comercial de la aceptación técnica: solicitar financiamiento con resultados medidos y un plan de madurez; no afirmar certificación ISO 27001, homologación de defensa ni cobertura universal de CVE.
5. Reunir acta de liberación con visto bueno de ingeniería, seguridad, analista revisor y responsable del producto. Un defecto P0 o un piloto sin validación mantiene la versión en estado `piloto`, no `producción`.

**Puerta final:** paquete reproducible, instalación offline demostrada, piloto documentado, controles de datos aprobados, pruebas y revisión independientes, y muestra de informe que cualquier revisor pueda rastrear a evidencia original.

## Primer bloque de trabajo recomendado

Para empezar sin reescribir todo el sistema: **(1)** congelar versión y pruebas; **(2)** crear `ToolResult` y sus casos de error; **(3)** corregir Nuclei y Nmap para propagar `failed/partial/no_findings`; **(4)** unir esos estados a un JSON mínimo por corrida; **(5)** hacer que DOCX muestre cobertura y bloquee emisión ante fallos. Después abordar selección de interfaz y alcance antes de un nuevo piloto. Este orden ataca directamente el conflicto observado en la interpretación de informes.
