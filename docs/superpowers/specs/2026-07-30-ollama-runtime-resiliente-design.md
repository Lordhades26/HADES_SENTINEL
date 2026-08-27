# Diseño: runtime resiliente de Ollama para HADES SENTINEL

**Fecha:** 2026-07-30  
**Estado:** aprobado conceptualmente; pendiente de validación del documento  
**Alcance:** disponibilidad y diagnóstico del servicio local de Ollama.

## Objetivo

HADES debe detectar si Ollama está sano, iniciar una instancia local únicamente
cuando el puerto esté libre y continuar de forma determinista cuando el servicio
no pueda recuperarse. La recuperación no debe terminar procesos preexistentes,
solicitar elevación, modificar reglas de firewall ni convertir a la IA en
decisora.

## Restricciones de seguridad

- La lógica de escaneo, evidencia, severidad y riesgo conserva autoridad
  exclusiva.
- El runtime sólo acepta el endpoint loopback
  `http://127.0.0.1:11434`.
- Nunca se heredan `OLLAMA_API_KEY`, `OPENAI_API_KEY` ni variables no incluidas
  en una allowlist.
- Nunca se usa `shell=True`, interpolación de comandos ni búsqueda ambigua por
  nombre para iniciar el binario.
- Nunca se mata un PID existente, aunque se llame `ollama`.
- Nunca se solicita UAC ni se ejecuta con privilegios elevados.
- Si el puerto está ocupado pero la API no responde, el estado es
  `blocked_stale_listener`: HADES informa y continúa sin IA.
- El agente sólo administra el proceso de Ollama que él mismo creó y cuya
  referencia `Popen` conserva en memoria.

## Arquitectura

Se añadirá `hades_ollama_runtime.py`, módulo pequeño y sin dependencias externas.
Será el único responsable de:

1. validar que la URL configurada corresponde al loopback permitido;
2. consultar `/api/version` con timeout corto;
3. comprobar si `127.0.0.1:11434` está ocupado;
4. resolver el binario desde rutas locales explícitas y verificables;
5. iniciar `ollama serve` oculto con entorno mínimo;
6. esperar por condición hasta que la API responda o venza el presupuesto;
7. devolver un resultado estructurado sin lanzar excepciones al pipeline.

No se añadirá reinicio automático periódico. El arranque se intentará una sola
vez durante el inicio del dashboard o del modo CLI. Esto evita tormentas de
procesos y condiciones de carrera.

## Contrato público

```python
@dataclass(frozen=True)
class OllamaRuntimeStatus:
    state: str
    detail: str
    pid: int | None = None
    version: str | None = None


def ensure_ollama_available(
    *,
    endpoint="http://127.0.0.1:11434",
    timeout_seconds=8.0,
    source_env=None,
) -> OllamaRuntimeStatus:
    ...
```

Estados permitidos:

- `healthy`: la API ya respondía;
- `started`: HADES inició Ollama y la API quedó operativa;
- `missing_binary`: no existe un binario local verificable;
- `blocked_stale_listener`: el puerto está ocupado y la API no responde;
- `startup_failed`: el proceso propio salió o el timeout venció;
- `disabled`: `HADES_SKIP_AI=1`;
- `unsupported_endpoint`: la configuración no es loopback local.

`detail` será breve y no contendrá rutas sensibles, variables de entorno,
salidas completas de procesos ni excepciones crudas.

## Resolución del binario

En Windows se comprobarán, en orden:

1. `%LOCALAPPDATA%\Programs\Ollama\ollama.exe`;
2. una ruta devuelta por `shutil.which("ollama")`, sólo si `Path.resolve()`
   apunta a un archivo existente llamado `ollama.exe`.

No se buscará recursivamente el disco. No se ejecutarán alias, archivos `.bat`,
`.cmd` ni rutas provistas por el frontend.

## Entorno del proceso

El proceso se iniciará con una extensión controlada de `safe_subprocess_env()`:

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_ORIGINS=http://127.0.0.1:8080,http://localhost:8080
```

El entorno no incluirá claves API. En Windows se usará
`CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`; en otros sistemas no se aplicarán
flags exclusivos de Windows.

## Integración

- `hades_server.py` ejecutará el chequeo una vez antes de iniciar los hilos de
  monitoreo y expondrá el resultado dentro de `/api/ollama`.
- `hades_local.py` ejecutará el chequeo antes de la primera inferencia, nunca
  antes del escaneo determinista.
- Los consumidores actuales mantendrán sus timeouts y circuit breaker. Si el
  runtime no devuelve `healthy` o `started`, omitirán IA sin alterar el código
  de salida de la auditoría.
- El dashboard mostrará un diagnóstico accionable, pero no incorporará un botón
  capaz de matar o reiniciar servicios privilegiados.

## Manejo del proceso propio

El módulo conservará únicamente la referencia al proceso que creó. Podrá
cerrarlo de forma cooperativa durante el cierre normal del dashboard, con
timeout y terminación limitada a ese PID propio. No descargará ni detendrá una
instancia de Ollama que ya existía antes de HADES.

Para minimizar cambios de comportamiento, la primera versión no detendrá
automáticamente el proceso propio al cerrar una auditoría: sólo lo hará al
cerrarse el servidor que lo creó. El cierre del agente CLI dejará que Ollama
aplique su ciclo de vida normal.

## Pruebas

Las pruebas serán unitarias y no iniciarán procesos reales:

- API sana: no llama a `Popen`;
- `HADES_SKIP_AI=1`: devuelve `disabled`;
- puerto libre y binario válido: inicia con lista de argumentos y entorno
  saneado;
- puerto ocupado sin API: devuelve `blocked_stale_listener` y nunca mata;
- binario ausente: devuelve `missing_binary`;
- endpoint remoto, wildcard o con credenciales: devuelve
  `unsupported_endpoint`;
- proceso que sale temprano: devuelve `startup_failed`;
- espera basada en condición: termina al responder la API, no depende de un
  `sleep` fijo;
- ningún resultado expone secretos;
- regresión completa: `python tests\run_all.py`.

## Observabilidad

El dashboard distinguirá:

- IA disponible;
- IA omitida por configuración;
- Ollama no instalado;
- puerto ocupado por servicio no saludable;
- fallo de arranque del proceso propio.

Los logs incluirán estado y acción recomendada, pero nunca valores de entorno,
prompts, evidencia de red o stack traces del runtime.

## Criterios de aceptación

- Un Ollama sano no se reinicia ni se duplica.
- Un listener colgado no es terminado automáticamente.
- Un puerto libre permite iniciar el binario local exacto sin ventana.
- HADES completa el escaneo cuando Ollama está ausente o bloqueado.
- La IA continúa siendo consultiva y no altera evidencia ni riesgo.
- Todas las pruebas existentes y nuevas pasan.
- `git diff --check` no reporta errores.

## Fuera de alcance

- Reparar procesos elevados ya atascados.
- Administrar Windows Firewall.
- Instalar o actualizar Ollama.
- Descargar, eliminar o reemplazar modelos.
- Añadir endpoints remotos de inferencia.
- Exponer controles destructivos en el dashboard.
