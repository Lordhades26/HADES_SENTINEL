# 📜 Manual de Usuario: HADES Surveillance Agent v2.2
### Ecosistema de Auditoría de Red y Análisis de Tráfico Local con Inteligencia Artificial

Bienvenido a **HADES Surveillance Agent v2.2**, una suite avanzada y completamente local para la supervisión de red, análisis de tráfico en tiempo real y detección de vulnerabilidades. HADES está diseñado bajo un modelo de privacidad absoluto (zero-trust): todas las operaciones, capturas de paquetes y análisis de inteligencia artificial se ejecutan **100% en tu máquina local**, sin enviar datos a la nube ni requerir conexiones a internet externas.

---

## 1. ⚙️ Arquitectura y Flujo de Operación
HADES ejecuta un flujo de vigilancia autónomo y colaborativo, dividido en **5 fases consecutivas** con control interactivo de alcance:

```
[FASE 1: ARP Sweep] ────> Detecta hosts activos en la LAN
         │
[FASE 2: Live Tshark] ──> Captura tráfico de red local (30s)
         │
[FASE 3: Update] ───────> Actualiza templates del escáner Nuclei
         │
  [MENÚ DE CONTROL] <───> Interactivo: Pentester elige foco del ataque
         │
         ├───> [Opción ID] ──> FASE 4: Auditoría profunda de host único
         │                     FASE 5: Reporte específico de host
         │
         └───> [Opción 'A'] ─> FASE 4: Auditoría profunda masiva de red
                               FASE 5: Reporte Consolidador Maestro.md
```

1. **Fase 1: Descubrimiento ARP (Nmap):** Realiza un barrido ultra rápido en la subred local para identificar qué dispositivos están conectados y encendidos.
2. **Fase 2: Captura de Tráfico en Tiempo Real (Tshark):** Captura e inspecciona el tráfico durante 30 segundos en la interfaz de red activa. Extrae flujos, puertos de destino, protocolos utilizados e IPs externas con las que se comunican tus dispositivos.
3. **Fase 3: Actualización de Vulnerabilidades (Nuclei):** Descarga de forma silenciosa y local las últimas firmas de vulnerabilidades conocidas.
4. **Menú Táctico Interactivo (Control del Pentester):** Tras detectar los hosts activos y realizar la captura, el agente presenta una lista interactiva numerada en la consola para elegir si deseas auditar una IP específica o analizar toda la subred.
5. **Fase 4: Auditoría por Host (HADES Engine):** 
   * **Nmap profundo:** Analiza puertos abiertos y versiones de servicios en la IP o IPs seleccionadas.
   * **Nuclei Web Scan:** Busca vulnerabilidades en puertos HTTP/HTTPS expuestos.
   * **SSL/TLS Audit:** Comprueba la robustez de los certificados TLS.
6. **Fase 5: Reporte Consolidador e IA:** La IA local (Ollama) analiza los datos de puertos y flujos de tráfico detectados para generar las recomendaciones y el `INFORME_MAESTRO.md` estructurado.

---

## 2. 🎛️ Requisitos e Instalación en Windows

Para que HADES ejecute todas las herramientas en Windows de manera nativa, asegúrate de tener instalados los siguientes componentes en sus rutas predeterminadas:

| Herramienta | Función en HADES | Ruta por Defecto en Windows |
| :--- | :--- | :--- |
| **Python 3.10+** | Intérprete para correr los scripts de HADES. | Encontrado automáticamente en el PATH |
| **Nmap** | Escaneo de red y detección de puertos. | `C:\Program Files (x86)\Nmap\nmap.exe` |
| **Wireshark (Tshark)** | Captura silenciosa de tráfico en la tarjeta de red. | `C:\Program Files\Wireshark\tshark.exe` |
| **OpenSSL** | Auditoría y diagnóstico de cifrados TLS/SSL. | `C:\Program Files\OpenSSL-Win64\bin\openssl.exe` |
| **Nuclei** | Motor de búsqueda de vulnerabilidades web. | `%USERPROFILE%\Documents\HADES\nuclei\nuclei.exe` |
| **Ollama (IA)** | Red Neuronal Local para análisis automatizado. | Escucha en: `http://127.0.0.1:11434` |

> [!NOTE]
> Si has instalado alguna herramienta en una ruta no estándar, puedes ajustar la variable `WIN_PATHS` directamente en el archivo [hades_win_master_advanced.py](file:///c:/Users/DELL%205420/Desktop/HADES%20ECOSYSTEM/ediciones%20hades%20free/hades_win_master_advanced.py).

### Configuración del Modelo de Inteligencia Artificial (Ollama)
HADES utiliza por defecto el modelo local `HADES-AUTO:latest` (o un fallback similar como `llama3` o `qwen2.5`). 
Para levantar el servidor de IA local:
1. Abre una terminal de PowerShell o CMD y ejecuta:
   ```powershell
   ollama serve
   ```
2. En otra terminal, descarga el modelo con:
   ```powershell
   ollama pull llama3
   ```

---

## 3. 🚀 Modo de Uso y Ejecución

### Opción A: Lanzamiento Automático con Doble Clic (Recomendado)
1. Conecta tu pendrive o sitúate en la carpeta del proyecto.
2. Haz doble clic sobre el archivo **[LANZAR_HADES.bat](file:///c:/Users/DELL%205420/Desktop/HADES%20ECOSYSTEM/ediciones%20hades%20free/LANZAR_HADES.bat)**.
3. Se abrirá una consola interactiva con el banner de HADES que:
   * Detectará automáticamente la versión de Python instalada.
   * **Autodetectará tu red local** actual resolviendo tu IP de red.
   * Iniciará el flujo de descubrimiento y captura de 30 segundos.
   * **Presentará el Menú de Control interactivo** en la ventana para que elijas tu objetivo.
   * Al finalizar la auditoría elegida, **abrirá automáticamente la carpeta de informes** en tu explorador.

### Opción B: Ejecución por Terminal de Comandos (Personalizada)
Si prefieres controlar el alcance o los tiempos de captura, abre PowerShell/CMD en este directorio y ejecuta:

```powershell
# Sintaxis: python hades_surveillance_advanced.py [RANGO_RED/auto] [TIEMPO_CAPTURA_SEGUNDOS]

# 1. Ejecutar con autodetección de red y 30 segundos de captura:
python hades_surveillance_advanced.py auto 30

# 2. Especificar una red específica y 60 segundos de captura:
python hades_surveillance_advanced.py 192.168.10.0/24 60

# 3. Escaneo rápido de un host único usando el máster local:
python hades_win_master_advanced.py nmap 192.168.1.1
```

### Opción C: Detención de Emergencia de Procesos (Fuerza Bruta)
Si necesitas cancelar inmediatamente las auditorías, las capturas de Tshark demoran demasiado o deseas suspender todas las actividades de seguridad de forma instantánea sin dejar procesos huérfanos en segundo plano:
1. Haz doble clic sobre el archivo **[DETENER_HADES.bat](file:///c:/Users/DELL%205420/Desktop/HADES%20ECOSYSTEM/ediciones%20hades%20free/DETENER_HADES.bat)**.
2. El script forzará el cierre inmediato y limpio de todos los binarios activos en segundo plano (`nmap.exe`, `tshark.exe`, `nuclei.exe`, `openssl.exe`, `python.exe`, `pythonw.exe`).

### Opción D: Centro de Control Web Táctico (Dashboard Inteligente)
HADES ahora incluye un panel de control interactivo de nivel profesional, ciberpunk y moderno en formato web 100% nativo y autohospedado localmente de forma segura.
* **Seguridad Incorporada:** Posee autenticación dinámica a través de un Token de Sesión de un solo uso generado en tiempo real por el backend. Esto mitiga cualquier vector de ataque de Falsificación de Petición en Sitios Cruzados (CSRF) y asegura que ningún agente externo en tu red pueda invocar APIs del sistema.
* **Inicio Autónomo:** Al abrir la interfaz, el agente inicia automáticamente un escaneo LAN de reconocimiento sin necesidad de interacciones previas.
* **Logs en Tiempo Real:** Visualiza directamente en pantalla la salida interactiva del terminal del agente, estado del host actual y volumetría de protocolos.

**Para Iniciarlo:**
Abre una terminal PowerShell/CMD y ejecuta:
```powershell
python hades_server.py
```
El servidor levantará en el puerto local `8080` y abrirá automáticamente tu navegador web por defecto de forma segura inyectando el token de sesión dinámico.



### 🖥️ Interacción con el Menú en Consola
Cuando el escaneo ARP y la captura finalicen, la pantalla se pausará mostrando un panel como este:
```text
-----------------------------------------------------------------
  HADES SURVEILLANCE — DISPOSITIVOS ACTIVOS DETECTADOS
-----------------------------------------------------------------
  [1] IP: 192.168.1.1
  [2] IP: 192.168.1.83
  [3] IP: 192.168.1.150
  [A] Escanear TODOS los hosts de la red de forma automatica
  [Q] Salir de HADES
-----------------------------------------------------------------
Selecciona una opcion (ID de host, 'A' para todos, 'Q' para salir):
```
* Introduce el **número** del host (ej: `2`) para realizar auditorías profundas únicamente sobre ese equipo.
* Introduce **`A`** para realizar la auditoría a todos de forma automatizada.
* Introduce **`Q`** para salir de forma segura sin generar ruido de escaneo activo en la subred.

---

## 4. 📂 Estructura de Reportes Generados
Cada vez que HADES finaliza una vigilancia, crea una carpeta bajo `informes/` con el nombre `informe_YYYYMMDD_HHMM/` que contiene:

* **`INFORME_MAESTRO.md` (Markdown Principal):** Archivo maestro consolidado. Incluye tablas de hosts activos, resúmenes legibles de protocolos, análisis técnico estructurado por IA sobre los riesgos de tráfico, e informes detallados host por host.
* **`trafico_red.txt` (Tráfico RAW y Resumen):** Registro textual estructurado que agrupa flujos locales, puertos externos consultados y volumetría de protocolos detectada por Tshark.
* **`host_XXX_XXX_XXX_XXX.txt` (Detalle por Host):** Reporte técnico individualizado de puertos, banners de servicios, auditorías SSL y vulnerabilidades de esa IP específica.

---

## 5. 🛠️ Solución de Problemas Comunes

* **[ERROR] No se encuentra tshark.exe o nmap.exe:**
  * Verifica si tienes instalado Wireshark (que incluye Tshark) y Nmap. 
  * Asegúrate de marcar la casilla "Install Npcap" durante la instalación de Wireshark.
* **El reporte de IA sale vacío o indica error de conexión:**
  * Asegúrate de que Ollama está activo ejecutando `ollama serve` y que has descargado un modelo (`ollama pull llama3`).
  * Si utilizas un modelo distinto de `HADES-AUTO:latest`, puedes configurarlo en la línea 125 de `hades_win_master_advanced.py`.
* **No se detecta ningún host en la red local:**
  * Esto sucede si tu adaptador de red bloquea los paquetes de descubrimiento ARP. Prueba indicando el rango de red de forma manual: `python hades_surveillance_advanced.py 192.168.1.0/24`.

---

## ⚖️ Descargo de Responsabilidad y Uso Ético
HADES-LOCAL es una herramienta orientada exclusivamente a la auditoría, defensa y diagnóstico preventivo de redes propias o bajo autorización explícita. El escaneo de redes ajenas o el análisis no autorizado de tráfico de terceros puede constituir una violación a las normativas de telecomunicaciones y leyes de delitos informáticos vigentes. **Utilízalo siempre bajo tu propia responsabilidad.**
