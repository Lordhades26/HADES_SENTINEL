# Diseño: digest fijo y estado del runtime en el dashboard

## Objetivo

Hacer inmutable la construcción local de `HADES-SENTINEL-ANALYST:1.0.0` en la
workstation actual y mostrar el diagnóstico real del runtime de Ollama en el
panel existente del dashboard, sin ampliar la autoridad consultiva del LLM.

## Alcance aprobado

1. Sustituir `FROM dolphin3:latest` por la ruta inmutable a la capa de pesos
   local verificada de `dolphin3`.
2. Mantener `/api/ollama` como contrato del backend: ya expone
   `runtime_state` y `runtime_detail`.
3. Representar ambos campos en el encabezado del panel de IA, con texto y color
   comprensibles para cada estado conocido.
4. Conservar un fallback seguro para respuestas incompletas o estados futuros.
5. Añadir pruebas de regresión del Modelfile, el contrato del backend y la
   presentación del dashboard.
6. Crear un commit local sólo con archivos vinculados a este cambio. No hacer
   `push`.

La referencia del blob es deliberadamente **workstation-only**: este repositorio
se ejecuta desde el perfil `%USERPROFILE%` y Ollama no expande variables de
entorno dentro de `FROM`. Otro usuario o equipo deberá materializar el mismo
blob y regenerar esta ruta después de verificar su SHA-256.

## Fuente del digest

El manifest local:

`%USERPROFILE%\.ollama\models\manifests\registry.ollama.ai\library\dolphin3\latest`

tiene SHA-256:

`sha256:d5ab9ae8e1f22619a6be52e5694df422b7183a3883990a000188c363781ecb78`

Ese valor identifica el manifest completo, pero Ollama 0.32.5 no documenta
`FROM <modelo>@sha256:<manifest>`. Su mecanismo oficial para fijar el contenido
es la ruta al blob que muestra `ollama show --modelfile`. El manifest referencia
la capa de pesos Q4_K_M:

`sha256:1eee6953530837b2b17d61a4e6f71a5aa31c9714cfcf3cb141aa5c1972b5116b`.

La referencia exacta será:

`FROM %USERPROFILE%\.ollama\models\blobs\sha256-1eee6953530837b2b17d61a4e6f71a5aa31c9714cfcf3cb141aa5c1972b5116b`

La versión real verificada es Ollama `0.32.5`, y `ollama show
dolphin3:latest --modelfile` emite esa misma ruta.

## Arquitectura

No se añadirá otro endpoint ni estado paralelo. `hades_server.py` seguirá
inicializando y preservando `runtime_state` y `runtime_detail` dentro de
`ollama_metrics`; `/api/ollama` seguirá entregando ese snapshot.

`agente HADES.html` incorporará un mapeo explícito de estados del runtime a una
etiqueta de operador, color y clase visual. El estado se mostrará incluso cuando
`connected` sea falso, para distinguir Ollama ausente, deshabilitado, bloqueado,
con endpoint no admitido o con fallo de arranque. `runtime_detail` se presentará
como diagnóstico secundario, sin interpretar evidencia ni tomar decisiones.

## Estados y fallback

- `healthy`: runtime local disponible.
- `started`: runtime iniciado por HADES.
- `disabled`: capa consultiva deshabilitada.
- `unsupported_endpoint`: endpoint fuera del contrato loopback.
- `blocked_stale_listener`: puerto ocupado por servicio no saludable.
- `missing_binary`: binario local no verificable.
- `startup_failed`: fallo o timeout durante el arranque.
- `not_checked`: comprobación todavía no ejecutada.
- Cualquier valor futuro: etiqueta de estado no reconocido y detalle escapado
  mediante `textContent`.

Los estados de error usarán el color de alerta actual; los saludables, el verde
neón; los transitorios o deshabilitados, el color ámbar existente.

## Seguridad

- La referencia al blob identificado por SHA-256 evita que `latest` cambie
  silenciosamente.
- No se leerán ni expondrán secretos.
- El frontend usará `textContent`; no insertará `runtime_detail` como HTML.
- El diagnóstico del runtime no modificará score, severidad, CVE ni alcance.
- Ollama seguirá limitado a loopback y el LLM continuará siendo consultivo.

## Pruebas

1. El Modelfile contiene la ruta exacta al blob `sha256-1eee...b5116b` y no usa
   `dolphin3:latest`.
2. `ollama_metrics` y `/api/ollama` conservan `runtime_state` y
   `runtime_detail`.
3. El dashboard consume ambos campos y contempla todos los estados conocidos.
4. Una respuesta sin esos campos conserva un estado visual seguro.
5. La suite completa, compilación Python y `git diff --check` finalizan con
   código cero.

## Criterios de aceptación

1. En esta workstation, la construcción del modelo base queda fijada a la capa
   de pesos verificada.
2. El panel diferencia disponibilidad HTTP de diagnóstico del runtime.
3. El detalle real es visible y no admite inyección HTML.
4. No cambia la frontera consultiva del LLM.
5. Sólo los archivos del alcance aprobado entran al commit local.
6. No se realiza `push`.
