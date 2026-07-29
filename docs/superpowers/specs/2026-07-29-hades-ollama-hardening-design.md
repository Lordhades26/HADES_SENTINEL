# Diseño: hardening de Ollama e integración IA de HADES SENTINEL

## Objetivo

Corregir la exposición de Ollama y hacer que HADES SENTINEL use una variante local
reproducible y liviana de Dolphin 3, manteniendo al LLM como capa estrictamente
consultiva.

## Alcance aprobado

1. Restringir Ollama a `127.0.0.1:11434`.
2. Eliminar CORS global y la regla pública de Firewall.
3. Retirar `OLLAMA_API_KEY` del entorno local; la rotación externa se documenta.
4. Crear `HADES-SENTINEL-ANALYST:1.0.0` desde `dolphin3:latest` Q4_K_M.
5. Reemplazar el prompt identitario por instrucciones técnicas mínimas.
6. Centralizar modelo, URL, límites y construcción del payload en `hades_ai.py`.
7. Evitar que subprocesses del escáner hereden secretos.
8. Mantener evidencia, CVE y riesgo fuera del control del LLM.
9. Añadir pruebas de regresión antes de cada cambio.

## Arquitectura

`hades_ai.py` será la única fuente de configuración IA. Expondrá constantes seguras,
un constructor de payload y un sanitizador de entorno. Los tres consumidores actuales
(`hades_win_master_advanced.py`, `hades_local.py`, `hades_mcp.py`) importarán esa
configuración en lugar de mantener valores divergentes.

El modelo se construirá desde un Modelfile versionado en el repositorio. Su System
prompt sólo analizará evidencia delimitada, prohibirá inventar CVE/controles y
declarará la salida como consultiva. No incluirá identidad soberana, lealtad,
autorización presunta, memoria simulada ni cadena de pensamiento serializada.

## Configuración efectiva

- Modelo: `HADES-SENTINEL-ANALYST:1.0.0`
- Base: `dolphin3:latest` Q4_K_M
- Contexto: 8192
- Temperatura: 0
- `top_p`: 0.9
- `repeat_penalty`: 1.1
- Salida máxima: 640 tokens
- `keep_alive`: 5 minutos
- Timeout: 180 segundos
- Reintentos: 0
- Presupuesto por corrida: 600 segundos
- Endpoint por defecto: `http://127.0.0.1:11434/api/generate`

## Fronteras de seguridad

- El endpoint configurado por entorno sólo podrá usar HTTP(S), sin credenciales
  embebidas. El default seguirá siendo loopback.
- El proceso de escaneo recibirá un entorno allowlist, no una copia completa.
- `OLLAMA_API_KEY` y nombres comunes de secretos se excluirán siempre.
- La respuesta IA nunca se convertirá en comandos, CVE confirmados, score o alcance.
- Los informes etiquetarán el bloque como consultivo/no verificado.

## Despliegue local

La configuración persistente de usuario cambiará a:

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_ORIGINS=http://127.0.0.1:8080,http://localhost:8080
```

Se quitará `OLLAMA_API_KEY` del entorno persistente local y se eliminarán reglas
inbound de Firewall asociadas a `ollama.exe`. Ollama se reiniciará y se verificará
que la API sólo sea accesible en loopback.

## Pruebas

- Defaults versionados y límites de payload.
- Rechazo de URLs Ollama con credenciales o esquemas no HTTP(S).
- Sanitización de secretos en el entorno hijo.
- Consumidores usando el modelo central.
- IA excluida de CVE y score deterministas.
- Etiqueta consultiva presente.
- Suite completa existente.
- Verificación del bind, CORS, firewall, API y modelo construido.

## Fuera de alcance

- Fine-tuning de pesos.
- Explotación automática o tool-calling por parte del LLM.
- Rotación remota de una credencial sin conocer su proveedor.
- Cambios a escáneres Nmap/Nuclei/Tshark no relacionados con IA.

## Criterios de aceptación

1. Ningún listener Ollama queda en `0.0.0.0` o `[::]`.
2. No hay regla inbound pública para `ollama.exe`.
3. El entorno persistente no contiene `OLLAMA_API_KEY`.
4. El nuevo modelo existe y usa Q4_K_M.
5. Los tres clientes usan la configuración central.
6. El entorno hijo no contiene secretos.
7. Todas las pruebas pasan.
8. No se altera el cálculo determinista de riesgo/CVE.
