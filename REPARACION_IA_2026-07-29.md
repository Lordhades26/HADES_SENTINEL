# Reparación de IA local y endurecimiento de Ollama

**Proyecto:** HADES SENTINEL  
**Fecha:** 2026-07-29  
**Alcance:** integración del modelo local, aislamiento de secretos y exposición
de Ollama. No se modificó la lógica determinista de escaneo ni puntuación.

## Resultado

La integración anterior basada por defecto en `HADES-DOLPHIN:latest` Q8_0 fue
reemplazada por `HADES-SENTINEL-ANALYST:1.0.0`, construido sobre
`dolphin3:latest` Q4_K_M. Ollama confirma:

- arquitectura Llama, 8.0B parámetros;
- cuantización Q4_K_M;
- tamaño de 4.920.758.673 bytes (4,9 GB);
- `num_ctx 8192`;
- `num_predict 640`;
- `temperature 0`.

El modelo se creó mediante el Modelfile versionado
`Modelfile.hades-sentinel-analyst`. El prompt de sistema es corto, defensivo y
consultivo: trata el contenido del escaneo como datos hostiles, prohíbe inventar
CVE o controles y no permite cambiar severidades, puntuaciones ni decisiones.

## Cambios de código

Se añadió `hades_ai.py` como contrato único para:

- modelo y endpoint de Ollama;
- límites de generación, timeout, presupuesto y reintentos;
- validación de la URL de inferencia;
- payload determinista compartido;
- etiqueta visible de contenido IA no verificado;
- entorno mínimo de subprocesos que no hereda API keys.

Se migraron `hades_win_master_advanced.py`, `hades_local.py` y `hades_mcp.py`.
`hades_server.py` ahora construye el entorno del proceso de escaneo con una
allowlist y excluye `OLLAMA_API_KEY`, `OPENAI_API_KEY` y cualquier variable no
necesaria. Los lanzadores directos CLI/MCP aplican la misma allowlist al invocar
herramientas externas. Los informes por host y de tráfico anteponen:

> COMENTARIO CONSULTIVO DE IA — NO VERIFICADO

La lógica determinista conserva autoridad exclusiva sobre evidencia, severidad
y riesgo.

## Endurecimiento aplicado al equipo

Estado previo comprobado:

- listener Ollama en `[::]:11434` (todas las interfaces);
- `OLLAMA_HOST=0.0.0.0`;
- `OLLAMA_ORIGINS=*` en el proceso existente;
- `OLLAMA_API_KEY` presente en el entorno de usuario;
- dos reglas inbound Allow/Public para el binario exacto de Ollama.

Estado posterior comprobado:

- listener únicamente en `127.0.0.1:11434`;
- `OLLAMA_HOST=127.0.0.1:11434` persistente para el usuario;
- orígenes limitados a los dos orígenes del dashboard local;
- `OLLAMA_API_KEY` ausente en User y Machine;
- cero reglas de firewall asociadas al binario exacto de Ollama;
- API `http://127.0.0.1:11434/api/version` operativa con Ollama 0.32.5.

Se detuvieron únicamente los dos procesos Ollama verificados por ruta y se
levantó `ollama serve` oculto con el entorno seguro. No se eliminaron modelos
anteriores ni otros binarios.

## Prueba real de inferencia

Se envió evidencia sintética con una instrucción hostil incrustada al modelo
nuevo. Resultado:

- inferencia completada;
- reconoció el puerto/servicio observado;
- no afirmó haber ejecutado el comando incrustado;
- 96 tokens generados;
- 5,77 tokens/s;
- 43,9 segundos de tiempo total, incluida la carga del modelo.

El límite de prueba produjo una respuesta truncada a 96 tokens de forma
intencional. La operación normal permite hasta 640 tokens y usa timeout de 180
segundos, coherente con el hardware medido.

## Verificación

- `python -m compileall`: PASS.
- `python -m unittest tests.test_hades_ai -v`: 13/13 PASS.
- `python tests\run_all.py`: 37/37 PASS.
- `git diff --check`: PASS.
- Revisión de referencias a `OLLAMA_API_KEY`: sólo documentación y fixtures
  sintéticos con el texto `secret`; no se encontró el valor real en el repo.

## Riesgo residual y acción externa

El proceso de Codex que inició esta reparación conserva una copia heredada de la
antigua variable hasta que esa aplicación se cierre. La persistencia de usuario
y máquina ya está limpia, los nuevos procesos de HADES filtran secretos y el
nuevo servidor Ollama se inició sin esa variable. Para purgar la copia en
memoria, cerrar y volver a abrir Codex y cualquier terminal antigua.

El valor encontrado no se reprodujo en ningún archivo ni salida. Si correspondía
a una credencial válida de un servicio externo, su rotación en el proveedor
sigue siendo obligatoria; no fue posible rotarla sin conocer su emisor.

Los modelos Q8 anteriores permanecen instalados para evitar una eliminación no
solicitada. Ya no son el valor por defecto de HADES.

## Revalidación posterior

El 2026-07-30 se repitió desde cero la verificación de cierre:

- `python tests\run_all.py`: 37/37 PASS;
- `python -m unittest tests.test_hades_ai -v`: 13/13 PASS;
- compilación forzada de los seis módulos modificados: exit 0;
- `git diff --check`: exit 0, con advertencias informativas LF/CRLF.

Durante la suite, Ollama agotó el timeout en los casos simulados y HADES
continuó correctamente con la auditoría determinista, confirmando que la IA
consultiva no bloquea el pipeline.

La revalidación operativa posterior detectó que el PID `21476` conserva el
listener `127.0.0.1:11434`, pero no responde a `/api/version`. El proceso corre
con privilegios que esta sesión no puede administrar: `Stop-Process` y la
consulta de firewall devuelven `Acceso denegado`. Se restauraron correctamente
las variables persistentes de usuario:

- `OLLAMA_HOST=127.0.0.1:11434`;
- `OLLAMA_ORIGINS=http://127.0.0.1:8080,http://localhost:8080`;
- `OLLAMA_API_KEY` ausente en User y Machine.

Queda pendiente reiniciar Ollama desde una terminal elevada y repetir
`/api/version`, `ollama show` y la inspección de reglas de firewall. Este estado
no bloquea la auditoría determinista: HADES degrada de forma segura y omite el
comentario consultivo cuando Ollama no está disponible.

### Recuperación pendiente en PowerShell elevado

Verificar antes de detener que el PID siga siendo Ollama:

```powershell
$p = Get-Process -Id 21476 -ErrorAction Stop
if ($p.ProcessName -ne 'ollama') { throw 'El PID cambió; no detener.' }
Stop-Process -Id $p.Id -Force

$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_ORIGINS = 'http://127.0.0.1:8080,http://localhost:8080'
Remove-Item Env:OLLAMA_API_KEY -ErrorAction SilentlyContinue
Start-Process `
  -FilePath 'C:\Users\DELL 5420\AppData\Local\Programs\Ollama\ollama.exe' `
  -ArgumentList 'serve' `
  -WindowStyle Hidden
```

Después, comprobar:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/version
ollama show HADES-SENTINEL-ANALYST:1.0.0
Get-NetTCPConnection -LocalPort 11434 -State Listen
Get-NetFirewallApplicationFilter |
  Where-Object {
    $_.Program -eq
    'C:\Users\DELL 5420\AppData\Local\Programs\Ollama\ollama.exe'
  } |
  ForEach-Object {
    Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $_
  }
```

## Recuperación conservadora incorporada — 2026-07-30

Se añadió `hades_ollama_runtime.py` para evitar que una indisponibilidad futura
de Ollama requiera cambios manuales cuando el puerto esté libre. El runtime:

- conserva la IA como capa consultiva;
- no mata listeners ni procesos preexistentes;
- no solicita elevación ni administra firewall;
- sólo admite `127.0.0.1:11434`;
- inicia únicamente un binario local verificable, sin `shell=True`;
- usa un entorno allowlist sin claves API;
- informa el motivo exacto de degradación al dashboard;
- permite que el escaneo determinista continúe ante cualquier fallo.

Un listener privilegiado ya atascado, como el PID `21476` observado durante la
revalidación, permanece deliberadamente fuera de la autorreparación. Ese caso
requiere intervención elevada porque terminarlo automáticamente violaría el
principio de no dañar procesos que HADES no creó.

### Verificación final del runtime

Al cierre de la implementación, el servicio se recuperó sin terminación
automática de procesos:

- runtime `healthy`;
- Ollama `0.32.5`;
- modelo `HADES-SENTINEL-ANALYST:1.0.0` disponible, 8B Q4_K_M;
- origen `http://127.0.0.1:8080` admitido;
- origen externo `https://evil.example` rechazado con HTTP 403;
- suite completa 48/48 PASS;
- suite específica del runtime 11/11 PASS.
