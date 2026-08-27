# Auditoría de funcionamiento completa — HADES SENTINEL

**Fecha:** 2026-07-30  
**Repositorio:** `HADES SENTINEL`  
**Rama:** `fix/fase4-ia-no-bloqueante`  
**HEAD auditado:** `5750945`  
**Resultado:** **NECESITA CORRECCIONES — no aprobar para producción todavía**

## 1. Alcance y criterio

La auditoría cubrió:

- suite funcional y unitaria;
- compilación sintáctica Python y JavaScript;
- servidor HTTP local y endpoints del dashboard;
- protecciones de mismo origen y DNS rebinding;
- integración real con Ollama y modelo instalado;
- fijación reproducible del modelo base;
- comportamiento consultivo del LLM ante evidencia hostil;
- degradación por herramientas ausentes;
- lanzadores y detención en Windows;
- revisión estática de entrada, ejecución de procesos y renderizado en el navegador;
- estado operativo y trazabilidad Git.

No se lanzó un escaneo intrusivo completo contra la LAN: no se proporcionó un
objetivo expresamente autorizado y esa acción afectaría sistemas externos al
repositorio. La ruta de ejecución sí fue cubierta con pruebas automatizadas,
validación de API y revisión estática.

## 2. Resumen ejecutivo

El núcleo funciona y la mejora solicitada está presente: el modelo instalado
resuelve al blob fijado por digest y el dashboard expone `runtime_state` con
estados explícitos. Las 49 pruebas pasan, el servidor responde, las métricas
funcionan y las guardas HTTP rechazaron orígenes y hosts no autorizados.

La aprobación de producción queda bloqueada por dos hallazgos:

1. Los logs se incorporan al dashboard mediante `innerHTML` sin escape. Es un
   sumidero de DOM XSS dentro del origen privilegiado del agente.
2. `DETENER_HADES.bat` mata por nombre todos los procesos `nmap`, `tshark`,
   `dumpcap`, `nuclei` y `openssl`, y termina cualquier proceso que escuche en
   8080 sin verificar que pertenezca a HADES.

## 3. Matriz de resultados

| Área | Resultado | Evidencia |
|---|---:|---|
| Suite global | APROBADO | `python tests/run_all.py -v`: 49/49 |
| Unittest directo | APROBADO | 36/36 |
| Sintaxis Python | APROBADO | `python -m compileall -q -f .`: código 0 |
| Sintaxis JavaScript | APROBADO | JS inline válido; `network_map_3d.js` válido como módulo |
| Whitespace/parches | APROBADO | `git diff --check`: sin errores; solo avisos LF/CRLF |
| Dashboard HTML | APROBADO | `/`: HTTP 200, 87.415 bytes |
| Estado API | APROBADO | `/api/status`: `idle`, puerto 8080 |
| Estado Ollama | APROBADO | `/api/ollama`: conectado, versión 0.32.5, `healthy` |
| Métricas | APROBADO CON AVISO | `/api/sysinfo`: disco 83,5% |
| Grafo | APROBADO | `/api/graph`: JSON válido |
| Rutas desconocidas | APROBADO | HTTP 404 |
| Guardia Origin | APROBADO | origen externo: HTTP 403; local: HTTP 200 |
| Guardia Host | APROBADO | petición TCP con `Host: evil.example`: HTTP 403 |
| Modelo fijado | APROBADO | Modelfile instalado resuelve al blob fijado |
| Inferencia real | APROBADO | HTTP 200; 31,379 s; 64 tokens; 6,1 tokens/s |
| Modelo descargado tras uso | APROBADO | `/api/ps`: cero modelos cargados tras `keep_alive: 0` |
| Herramientas externas | DEGRADADO | Nikto ausente; Nmap/OpenSSL/Tshark/curl/Ollama presentes |
| Renderizado seguro de logs | REPROBADO | uso de `innerHTML` con mensajes no codificados |
| Detención acotada | REPROBADO | mata herramientas globales y propietario arbitrario de 8080 |
| Trazabilidad de entrega | BLOQUEADO | árbol muy sucio y `.git` no escribible en este entorno |

## 4. Evidencia funcional

### 4.1 Pruebas

- `python tests/run_all.py -v`: **49/49 OK**
  - 13 comprobaciones funcionales.
  - 36 pruebas `unittest`.
- `python -m unittest discover -s tests -p test_*.py -v`: **36/36 OK**.
- `python -m compileall -q -f .`: **código 0**.
- El JavaScript embebido en `agente HADES.html` fue parseado correctamente.
- `network_map_3d.js` fue parseado como módulo ECMAScript.

### 4.2 Dashboard y servidor

Se inició una instancia temporal enlazada a loopback y se detuvo al finalizar.
El puerto 8080 quedó cerrado después de la prueba.

- `/`: HTTP 200 y documento completo.
- `/index.html`: está correctamente mapeado al mismo dashboard mediante
  `STATIC_ASSETS` (`hades_server.py:59-70`).
- `/api/status`: HTTP 200, estado `idle`.
- `/api/ollama`: HTTP 200, `connected: true`, `runtime_state: healthy`.
- `/api/sysinfo`: HTTP 200 con CPU, RAM, GPU, disco, temperatura y ventilador.
- `/api/graph`: HTTP 200 y estructura válida.
- ruta inexistente: HTTP 404.

La UI contiene:

- `#aiRuntimeState` (`agente HADES.html:1284`);
- tabla inmutable de estados `AI_RUNTIME_STATES`
  (`agente HADES.html:1563`);
- selección defensiva mediante `Object.hasOwn`
  (`agente HADES.html:1599`);
- actualización mediante `textContent`
  (`agente HADES.html:1608`).

### 4.3 Guardas HTTP

Las comprobaciones cubren tanto API como assets antes del enrutamiento
(`hades_server.py:622-660`):

- `Origin: https://evil.example` fue rechazado con 403.
- un origen loopback permitido obtuvo 200.
- una petición TCP cruda con `Host: evil.example` fue rechazada con
  `403 Forbidden: Cross-origin request`.

Esto confirma que la implementación efectiva, no solo las pruebas unitarias,
mitiga CSRF web y DNS rebinding para el servicio loopback.

### 4.4 Ollama, digest y comportamiento consultivo

- Ollama: **0.32.5**.
- Modelo: `HADES-SENTINEL-ANALYST:1.0.0`.
- Digest del modelo: comienza por `4c18df690928`.
- Tamaño: 4.920.758.673 bytes.
- Base declarada por Ollama: `dolphin3:latest`.
- Formato: GGUF, familia Llama, 8,0B, cuantización Q4_K_M.
- Parámetros observados:
  - `temperature 0`;
  - `top_p 0.9`;
  - `num_ctx 8192`;
  - `num_predict 640`;
  - `repeat_penalty 1.1`.

El Modelfile generado por la instalación resolvió al blob:

`sha256-1eee695a50800b86368b573b25b12ee49781ef397e0c38f65abf900a61b5116b`

Ese valor coincide con el digest fijado en
`Modelfile.hades-sentinel-analyst`. Por tanto, la base efectiva es
reproducible aunque Ollama también muestre el alias humano
`dolphin3:latest`.

Se realizó una inferencia corta con una instrucción hostil incrustada dentro de
la evidencia. El modelo:

- trató el texto como evidencia;
- no afirmó haber ejecutado comandos;
- no inventó CVE;
- señaló evidencia e incertidumbre;
- mantuvo el rol consultivo.

## 5. Hallazgos

### H-01 — Alto — DOM XSS en la consola del dashboard

**Evidencia**

- `agente HADES.html:1496-1508`: `pushLswLine(message)` interpola `short`
  dentro de `line.innerHTML`.
- `agente HADES.html:1774-1775`: `logToConsole(message)` concatena el mensaje
  directamente a `consoleLog.innerHTML`.
- `hades_server.py:395-397`: `add_log` almacena mensajes sin codificación.
- `hades_server.py:805-814`: la salida del subproceso se incorpora línea por
  línea al buffer.
- `/api/logs` entrega ese buffer al navegador
  (`hades_server.py:662-668`).

**Impacto**

Un mensaje que contenga markup activo puede ejecutarse en el origen local del
dashboard. Desde ese origen, el script tendría acceso a las APIs de escaneo y
detención. Aunque los flujos actuales producen mayormente mensajes internos,
el contrato del buffer acepta texto arbitrario y la salida de procesos; el
sumidero debe considerarse inseguro.

**Corrección recomendada**

- Renderizar todo texto con `textContent`.
- Crear los elementos `<span>` con `createElement`.
- Si se necesita formato, usar una lista cerrada de tokens visuales; no aceptar
  HTML desde logs.
- Añadir una prueba con payload `<img src=x onerror=...>` que verifique que
  queda visible como texto y nunca crea un nodo.

### H-02 — Alto — `DETENER_HADES.bat` puede matar procesos ajenos

**Evidencia**

- `DETENER_HADES.bat:29-30`: obtiene el propietario de cualquier listener en
  8080 y ejecuta `taskkill /f /t /pid`.
- `DETENER_HADES.bat:32-34`: enumera globalmente procesos por nombre y aplica
  `Stop-Process -Force`.
- La cabecera afirma “cleanup scopado”, pero el paso 3 no está acotado al árbol
  de procesos creado por HADES.

**Impacto**

Puede interrumpir capturas, análisis TLS o escaneos iniciados por el usuario o
por otra aplicación. Si HADES no está activo y otro servicio ocupa 8080, el
script también termina ese servicio.

**Corrección recomendada**

- Verificar `/api/status` y una marca de identidad HADES antes de actuar.
- Persistir de forma segura el PID del servidor y su tiempo de creación.
- Terminar únicamente ese PID y sus descendientes.
- Eliminar el barrido global por nombre.
- Si la identidad no coincide, abortar con mensaje y código distinto de cero.

### H-03 — Medio — Uso de `shell=True`

Se observó `shell=True` en métricas PowerShell de `hades_server.py` y en
envoltorios de herramientas. Los objetivos expuestos por API pasan por
validadores estrictos en `hades_validation.py`; no se confirmó una inyección.
Aun así, mantener comandos como listas de argumentos y `shell=False` reduce la
superficie y evita que una ampliación futura del input reabra el riesgo.

### H-04 — Medio — Dependencias no reproducibles

`requirements.txt` usa únicamente pisos mínimos:

- `python-docx>=1.2.0`
- `psutil>=7.2.2`

Instalaciones futuras pueden resolver versiones distintas. Conviene mantener
el archivo de intención y generar además un lock con hashes para el entorno
probado.

### H-05 — Bajo — Fuentes externas en un dashboard local

`agente HADES.html:8-10` consulta Google Fonts. El producto sigue funcionando
con fuentes fallback si no hay red, pero:

- no es completamente offline;
- expone una solicitud externa al abrir una interfaz de seguridad local;
- añade latencia y dependencia de disponibilidad.

Se recomienda alojar las fuentes dentro del repositorio o usar la pila local.

### H-06 — Operativo — Nikto ausente

`python hades_local.py status` informó:

- instalados: Nmap, OpenSSL, Tshark, curl y Ollama;
- ausente: Nikto.

La aplicación degrada sin derribarse, pero la cobertura web queda reducida.

### H-07 — Operativo — Disco por encima de 80%

`/api/sysinfo` informó 83,5% de uso. No causó fallos, pero los informes,
capturas y modelos locales consumen bastante espacio. Debe establecerse un
umbral y una política de retención antes de campañas largas.

### H-08 — Entrega — árbol Git no apto para un commit automático seguro

La rama está un commit por delante del remoto y contiene numerosos archivos
modificados, eliminados y sin seguimiento, varios ajenos al único informe de
esta auditoría. Además, el entorno permite leer `.git` pero no escribirlo; el
intento anterior falló con `.git/index.lock: Permission denied`.

No se creó commit ni se hizo push. Antes de integrar, hay que separar el
alcance, revisar las eliminaciones (`auth.html`, `hades_auth.py`) y ejecutar el
commit desde un contexto con permiso de escritura sobre `.git`.

## 6. Aspectos positivos

- El LLM se mantiene consultivo y separado de la evidencia determinista.
- La salida técnica se persiste antes de esperar al análisis IA.
- El modelo base quedó fijado por digest real.
- `runtime_state` está presente y se representa con texto seguro.
- Las guardas de `Host` y `Origin` funcionan en vivo.
- El body POST exige JSON, tamaño máximo y esquema exacto.
- El servidor enlaza a loopback y no expone CORS abierto.
- La instancia temporal fue cerrada y el modelo se descargó de memoria.

## 7. Prioridad de remediación

1. Sustituir los dos usos inseguros de `innerHTML` para logs.
2. Acotar `DETENER_HADES.bat` al PID/árbol verificado de HADES.
3. Añadir pruebas de regresión para XSS y para ocupación ajena del puerto 8080.
4. Eliminar o encapsular `shell=True`.
5. Generar lock reproducible de Python y localizar las fuentes.
6. Instalar/verificar Nikto si forma parte de la cobertura comprometida.
7. Liberar espacio o configurar retención de informes.
8. Repetir suite, pruebas HTTP y smoke test de Ollama después de los cambios.

## 8. Dictamen

**Funcionalidad nuclear: aprobada.**  
**Seguridad y operación de producción: no aprobadas.**

El sistema puede continuar en desarrollo y pruebas locales controladas. No
debe declararse listo para producción hasta corregir H-01 y H-02 y ejecutar
las regresiones correspondientes.
