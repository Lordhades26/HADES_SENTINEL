# Mejoras posibles sin dañar HADES SENTINEL

**Fecha:** 2026-07-30  
**Criterio:** preservar el pipeline determinista y mantener la IA consultiva.

## Prioridad alta

### 1. Fijar la identidad del modelo base

El Modelfile usa `FROM dolphin3:latest`. La etiqueta `latest` puede cambiar sin
que cambie el código de HADES. Conviene registrar y comprobar el digest exacto
del modelo base durante instalación y actualizaciones.

**Beneficio:** evita deriva silenciosa de comportamiento o supply chain.  
**Condición segura:** no reemplazar el modelo automáticamente; exigir
verificación y aprobación humana.

### 2. Mostrar el estado del runtime en el dashboard

La API `/api/ollama` ya entrega `runtime_state` y `runtime_detail`. El frontend
puede traducir los estados a mensajes accionables:

- disponible;
- deshabilitado por configuración;
- Ollama no instalado;
- listener local no saludable;
- fallo de arranque.

**Beneficio:** reduce diagnósticos a ciegas.  
**Condición segura:** interfaz sólo informativa, sin botones para matar procesos
o elevar privilegios.

### 3. Cierre cooperativo del proceso propio

El runtime conserva la referencia `Popen` únicamente cuando HADES inicia
Ollama. Puede añadirse una rutina de cierre que actúe sólo sobre esa referencia,
primero con `terminate()`, timeout y, como último recurso, `kill()` sobre el
mismo PID.

**Beneficio:** evita procesos propios huérfanos.  
**Condición segura:** nunca buscar procesos por nombre, puerto o PID externo.

## Prioridad media

### 4. Revalidación con TTL en modo CLI

`HadesEngine` cachea el primer resultado del runtime. Es seguro, pero si Ollama
se recupera durante una auditoría larga, la IA seguirá omitida hasta crear otro
motor. Un TTL local de 60–120 segundos permitiría reintentar sin tormentas.

**Condición segura:** máximo un intento por TTL y nunca bloquear el escaneo.

### 5. Métricas locales de disponibilidad

Registrar sólo contadores y estados:

- `healthy`;
- `started`;
- `blocked_stale_listener`;
- `startup_failed`.

No registrar prompts, evidencia, variables, rutas completas ni respuestas del
modelo.

**Beneficio:** permite saber si la recuperación aporta valor sin filtrar datos.

### 6. Prueba de contrato del frontend

Añadir una prueba que confirme que estados desconocidos se muestran como
“IA no disponible” y nunca como “sistema seguro” o “sin riesgos”.

**Beneficio:** evita que un fallo de telemetría se interprete como ausencia de
hallazgos.

### 7. Eliminar `shell=True` de lanzadores heredados

`hades_local.py` conserva un helper histórico `run_cmd()` que ejecuta comandos
con `shell=True`. El nuevo runtime no lo usa, pero conviene inventariar sus
callers y migrarlos gradualmente a listas de argumentos con `shell=False`.

**Beneficio:** reduce superficie de inyección en herramientas externas.  
**Condición segura:** migrar comando por comando con pruebas de compatibilidad;
no hacer un reemplazo mecánico que rompa quoting o pipelines existentes.

## Prioridad baja

### 8. Comando diagnóstico de sólo lectura

Un comando `python hades_ollama_runtime.py --status` podría imprimir un JSON
redactado con estado, versión y recomendación. No debería iniciar ni detener
servicios en ese modo.

### 9. Presupuesto adaptativo consultivo

Mantener `temperature=0`, pero ajustar `num_predict` según tamaño de evidencia
dentro de límites duros. Esto sólo reduce tiempo de inferencia; no puede cambiar
scores, severidad ni decisiones.

## Mejoras descartadas por riesgo

- matar automáticamente cualquier PID que escuche en `11434`;
- ejecutar el dashboard o Ollama como administrador;
- abrir reglas inbound de firewall;
- aceptar endpoints remotos configurables desde el navegador;
- permitir que el LLM cambie hallazgos o riesgo;
- descargar o actualizar modelos sin aprobación.
