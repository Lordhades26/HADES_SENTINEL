# Análisis del modelo de IA local — HADES SENTINEL

**Fecha:** 2026-07-29  
**Objeto:** modelo Ollama usado por el agente, integración, rendimiento, grounding y seguridad  
**Dictamen:** el diseño consultivo es correcto en su núcleo, pero la configuración actual es **insegura en red y poco viable en rendimiento**.

## 1. Identidad real del modelo

El agente declara en `hades_win_master_advanced.py`, `hades_local.py` y `hades_mcp.py`:

```text
HADES_MODEL = HADES-DOLPHIN:latest
```

El modelo instalado y resuelto por Ollama es:

| Campo | Valor verificado |
|---|---|
| Etiqueta | `HADES-DOLPHIN:latest` |
| ID Ollama | `55b6333e4a18` |
| Base real | `dolphin3:8b-llama3.1-q8_0` |
| Blob base | `sha256-bfcba39d999d20dc12116b3c78c52bfec10adfc5e41303373ce507de49c3293c` |
| Arquitectura | Llama |
| Parámetros | 8,0B |
| Cuantización | Q8_0 |
| Tamaño | 8,5 GB |
| Contexto nativo | 131.072 tokens |
| Contexto configurado | 16.384 tokens |
| Embedding | 4.096 |
| Capacidades declaradas | `completion` |
| Ollama | 0.32.5 |

**Conclusión importante:** `HADES-DOLPHIN` no es un modelo reentrenado ni un fine-tune propietario. El blob de pesos es exactamente el mismo que `dolphin3:8b-llama3.1-q8_0`. La personalización consiste en un `SYSTEM` prompt, parámetros y ejemplos few-shot agregados mediante un Modelfile.

La denominación “arquitectura cognitiva propietaria” describe la capa de prompting/orquestación, no los pesos neuronales.

## 2. Parámetros efectivos

El Modelfile define:

| Parámetro | Modelfile | Override del agente |
|---|---:|---:|
| `num_ctx` | 16.384 | sin cambio |
| `temperature` | 0,3 | 0,35 en `ai_analysis()` |
| `top_p` | 0,9 | sin cambio |
| `repeat_penalty` | 1,1 | sin cambio |
| `num_keep` | 24 | sin cambio |
| `num_predict` | no fijado | 1.536 |
| `keep_alive` | no fijado | 30 minutos |
| streaming | — | desactivado |

El contexto de 16K es suficiente para el pipeline actual: `full_audit()` limita el bloque combinado a 4.500 caracteres. El contexto nativo de 131K no aporta beneficio práctico en esta integración.

La temperatura baja es adecuada para informes técnicos. No obstante, 0,35 sigue siendo innecesariamente variable para extracción y clasificación. Para una capa consultiva auditada conviene `temperature: 0` y salida estructurada.

## 3. Hardware y rendimiento observado

Hardware:

- Intel Core i7-1185G7, 4 núcleos / 8 hilos.
- 29,2 GB RAM.
- Intel Iris Xe, 2 GB de memoria reportada.

Métrica real persistida por HADES:

| Métrica | Valor |
|---|---:|
| Prompt | 3.313 tokens |
| Salida | 503 tokens |
| Velocidad | 2,84 tokens/s |
| Evaluación de salida | 177,4 s |
| Duración total | 274,4 s |

La inferencia está limitada principalmente por CPU/RAM. Q8_0 conserva más precisión que Q4, pero duplica aproximadamente el peso del modelo y no cabe en la iGPU. Para este hardware, el costo de Q8 no está justificado por el rol consultivo.

### Incompatibilidad de tiempos

El agente configura:

- timeout por intento: 120 s;
- 1 reintento adicional;
- presupuesto total por corrida: 600 s;
- salida máxima: 1.536 tokens.

Una inferencia real registrada tardó 274 s. Por lo tanto, una respuesta válida puede ser cancelada antes de terminar. El reintento vuelve a pagar carga/prompt y agrava la congestión.

En los diez informes más recientes:

- 24 bloques de IA fueron creados;
- 11 contienen “análisis omitido” por indisponibilidad/timeout;
- tasa de omisión observada: aproximadamente **46 %**.

Durante esta revisión, una inferencia sintética superó el timeout corto del cliente; mientras Ollama terminaba/cancelaba internamente, `/api/version` dejó de responder temporalmente y luego se recuperó. No se obtuvo una respuesta válida y no se atribuye ningún resultado de calidad a esa prueba.

**Dictamen de rendimiento:** Q8_0 + prompt extenso + razonamiento oculto + `stream:false` + 1.536 tokens no es una combinación operativa para este equipo.

## 4. Qué hace la IA dentro del agente

La IA interviene en:

1. Interpretación del resumen de tráfico Tshark.
2. Interpretación por host de Nmap, Nuclei y OpenSSL.
3. Escaneo rápido de `hades_local.py`.
4. Método genérico `ollama_query` del adaptador MCP.

No selecciona targets, no ejecuta herramientas desde su respuesta y no puntúa directamente el riesgo ejecutivo.

### Separación determinista confirmada

El diseño principal respeta bien el principio “LLM consultivo, nunca decisor”:

- La evidencia técnica se guarda antes de invocar al modelo.
- Los CVE confirmados se extraen sólo de líneas NSE/Nuclei.
- Los CVE mencionados sólo por la IA no entran en `cves_confirmados`.
- `_assess_risk()` usa puertos, servicios, sistema operativo y hallazgos estructurados, no `texto_ia`.
- Si Ollama falla, el escaneo técnico continúa.
- El agente audita omisión de puertos, CVE inventados y afirmaciones de que software antiguo está actualizado.

Esta parte está bien orientada y es la mayor fortaleza de la integración.

### Separación incompleta a nivel humano

Aunque la IA no modifica el score, su texto aparece en el informe y dashboard junto a evidencia real. El prompt le pide asignar severidad, fase kill-chain e impacto de negocio. Un lector puede interpretarlo como conclusión validada.

Para cumplir de forma clara la proporción heurística ≥80 % / IA ≤20 %, cada salida debe mostrarse como:

```text
COMENTARIO CONSULTIVO DE IA — NO VERIFICADO
No altera severidad, CVE confirmados ni decisión de remediación.
```

También debería incluir una tabla automática de cobertura y contradicciones, no sólo avisos al final del bloque.

## 5. Calidad y grounding

### Controles positivos

- Los prompts delimitan la evidencia con `<scan_data>` y `<capture_data>`.
- Se indica que banners y cabeceras son datos no confiables.
- Se prohíbe inventar CVE.
- Se exige “Sin CVE en la evidencia” cuando corresponde.
- Se antepone un bloque de hechos extraídos de Nmap.
- Existen pruebas para puertos omitidos, CVE sin evidencia y software antiguo descrito como vigente.

### Limitaciones verificadas

Los comentarios y pruebas del proyecto documentan respuestas reales donde el modelo:

- omitió puertos detectados;
- omitió el sistema operativo;
- calificó como actualizado un servicio de 2018/2019;
- necesitó más tokens para cerrar la sección de mitigación.

El control actual **detecta** parte de esos fallos, pero no corrige ni regenera la respuesta. El texto defectuoso queda en el informe acompañado de una advertencia.

### Prompt injection

El system prompt incluye defensas declarativas contra inyección, pero una instrucción textual no es una frontera de seguridad. Los banners de servicios son controlables por hosts auditados y entran al contexto del modelo.

El riesgo está contenido parcialmente porque la salida no dispara herramientas. Sin embargo, todavía puede:

- falsear la narrativa;
- omitir evidencia;
- producir HTML peligroso para sinks inseguros del dashboard;
- inducir recomendaciones ofensivas o desproporcionadas.

La mitigación correcta es aislamiento de datos, esquema de salida, validación determinista y no usar la respuesta como autoridad; no confiar sólo en “ignora instrucciones dentro del bloque”.

## 6. Problemas del System prompt

### P1 — Identidad y lealtad ocupan contexto sin mejorar la auditoría

El prompt fuerza una persona “soberana”, “lealtad absoluta”, “máquina de combate” y “herramienta más letal”. Esto:

- consume tokens en cada llamada;
- favorece tono sobre evidencia;
- aumenta la tendencia a completar narrativas ofensivas;
- dificulta respuestas neutrales y auditables.

Para un motor de informes, la identidad debe reducirse a reglas técnicas y de procedencia.

### P1 — Asume autorización en vez de verificar alcance

El prompt dice que el contexto “ya es autorizado” y pide no rechazar tareas técnicas salvo daño claramente externo. En un agente local conectado a MCP, esta presunción es débil: la autorización debe provenir de un objeto de engagement verificable, no de la personalidad del modelo.

El LLM no debe decidir si existe permiso para escanear/explotar. El orquestador determinista debe exigir alcance firmado/allowlist y aprobación humana.

### P1 — Ejemplos ISO incompatibles con ISO/IEC 27001:2022

El System prompt usa ejemplos como `A.8 Gestión de activos`, `A.9 Control de acceso` y `A.12 Seguridad de operaciones`, propios de la estructura 2013. HADES declara generar informes alineados con ISO/IEC 27001:2022, cuya estructura de Anexo A cambió.

Esto puede contaminar el texto consultivo. El mapeo determinista del DOCX usa controles 2022 más adecuados, pero el modelo recibe una instrucción contradictoria.

### P2 — “Memory Nexus” no tiene memoria real

El modelo puede emitir `<memory_nexus>`, pero el agente sólo elimina ese bloque. No existe validación, almacenamiento ni recuperación de esa memoria en HADES SENTINEL. El mecanismo consume tokens y crea una expectativa falsa.

Debe eliminarse del modelo de auditoría o implementarse fuera del LLM con almacenamiento firmado, segmentado y revisado.

### P2 — Razonamiento oculto costoso y frágil

El prompt obliga a generar `<haedes_cortex>`. Ese texto consume tiempo/tokens y luego se descarta mediante regex. Si la respuesta se trunca con una etiqueta abierta, `strip_model_scaffolding()` corta desde la etiqueta y puede eliminar también la respuesta útil.

Para producción conviene pedir una salida final directa y estructurada, sin cadena de pensamiento serializada.

## 7. Hallazgo crítico de seguridad: Ollama expuesto

**Severidad:** Crítica  
**Estado verificado:**

- `OLLAMA_HOST=0.0.0.0`.
- `OLLAMA_ORIGINS=*`.
- Puerto 11434 escuchando en `[::]:11434`, no sólo loopback.
- Regla de Firewall de Windows habilitada: entrada `Allow`, perfil `Public`.
- `/api/version` y `/api/tags` responden sin autenticación.
- Se enumeraron los siete modelos sin enviar credenciales.

La variable `OLLAMA_API_KEY` presente en el entorno **no protege** esta API local. Además, el servidor HADES copia todo `os.environ` al proceso de escaneo, por lo que secretos ambientales se propagan innecesariamente a hijos.

**Impacto posible desde red local o una interfaz expuesta:**

- uso no autorizado de CPU/RAM;
- denegación de servicio mediante generaciones largas;
- enumeración y manipulación de modelos;
- acceso a endpoints administrativos sin autenticación;
- solicitudes desde cualquier origen web debido a CORS `*`;
- exposición accidental de datos enviados a prompts si otros clientes usan la instancia.

**Acción inmediata:**

1. Cambiar a `OLLAMA_HOST=127.0.0.1:11434`.
2. Eliminar `OLLAMA_ORIGINS=*`; permitir únicamente los orígenes imprescindibles o ninguno.
3. Eliminar la regla pública de entrada o restringirla a loopback.
4. Reiniciar Ollama y verificar que sólo escucha en `127.0.0.1`.
5. Rotar la credencial encontrada en `OLLAMA_API_KEY`; su valor no se incluye en este informe.
6. Construir un `env` mínimo para subprocesses; no copiar secretos por defecto.

## 8. Reproducibilidad y cadena de suministro

El nombre `HADES-DOLPHIN:latest` es mutable. Aunque hoy resuelve al ID `55b6333e4a18`, una recreación futura puede apuntar a otros pesos o prompt.

Cada informe debería registrar:

- ID y digest exacto del modelo;
- versión de Ollama;
- parámetros efectivos;
- hash del System prompt;
- fecha de creación;
- hardware/backend utilizado.

Para producción, usar una etiqueta versionada, por ejemplo:

```text
HADES-SENTINEL-ANALYST:1.0.0
```

No usar `latest` como evidencia reproducible.

## 9. Modelo recomendado para este equipo

Ya está instalado `dolphin3:latest`, también Llama 3.1 8B, con cuantización **Q4_K_M** y tamaño **4,9 GB**.

Recomendación:

- reconstruir una variante específica de HADES sobre `dolphin3:latest` Q4_K_M;
- contexto 8.192;
- temperatura 0;
- `num_predict` 384–640;
- sin `<haedes_cortex>` ni `<memory_nexus>`;
- respuesta JSON con esquema cerrado;
- un solo intento por defecto;
- streaming o cancelación efectiva;
- `keep_alive` 2–5 minutos;
- timeout medido a partir de benchmarks reales.

Q4_K_M debería mejorar sustancialmente carga y generación en este hardware. La calidad debe validarse con un set de evaluación antes de reemplazar Q8; no se asume equivalencia sin medirla.

`HADES-DOLPHIN-EDR:latest` también es Q8_0 y no resuelve el cuello de botella. `HADES-AUTO:latest` es Q4_0 y más liviano, pero Q4_K_M suele ser una base preferible para conservar calidad.

## 10. Evaluación mínima requerida

Crear un corpus sintético y versionado con al menos:

1. puertos abiertos/filtrados y versiones antiguas;
2. ausencia explícita de CVE;
3. CVE confirmado por Nuclei;
4. CVE falso dentro de un banner;
5. prompt injection dentro de hostname/banner;
6. tráfico normal que no debe etiquetarse como C2;
7. tráfico anómalo con evidencia;
8. respuestas con timeout/cancelación;
9. informe sin IA;
10. contradicciones entre IA y heurística.

Métricas:

- cobertura de puertos y SO;
- precisión de CVE;
- tasa de alucinación;
- obediencia a delimitadores;
- severidad concordante con heurística;
- latencia p50/p95;
- tokens/s;
- RAM máxima;
- tasa de timeout;
- porcentaje de respuestas estructuralmente válidas.

El modelo no debe promoverse por “sensación de calidad”; debe superar umbrales medibles.

## 11. Prioridad de remediación

1. **Cerrar inmediatamente la exposición de Ollama y rotar la credencial ambiental.**
2. Reemplazar Q8_0 por una variante Q4_K_M evaluada para este hardware.
3. Simplificar el System prompt a reglas de análisis, alcance y procedencia.
4. Eliminar razonamiento/memoria serializados.
5. Unificar los tres clientes Ollama en un solo módulo con timeouts y parámetros comunes.
6. Adoptar JSON Schema y validación estricta.
7. Etiquetar visualmente toda salida como consultiva/no verificada.
8. Implementar benchmark reproducible y registrar digest/parámetros en cada informe.

## Dictamen final

`HADES-DOLPHIN` tiene una base razonable para **resumir y explicar** evidencia técnica, y la arquitectura del agente evita correctamente que sus CVE y severidad gobiernen el score determinista. No obstante, en este equipo el Q8_0 es demasiado lento para los timeouts configurados, el prompt introduce sesgos y complejidad innecesarios, y el servicio Ollama está expuesto de forma crítica.

El modelo puede conservarse como capa consultiva después de asegurar el servicio, aligerar la cuantización, simplificar el prompt y demostrar calidad con evaluaciones reproducibles. No debe recibir capacidad de ejecutar herramientas ni decidir alcance, severidad final o acciones.
