# Reversing — LookLAN Network Monitor → paridad de detección en HADES SENTINEL

**Objetivo:** identificar las técnicas de descubrimiento de activos que usa
LookLAN Network Monitor para replicarlas en HADES con nuestras propias
herramientas (Nmap, etc.). **Metodología:** análisis **estático** del binario
(`look-lan-network-monitor.exe`, 2.167.447 bytes). No se ejecutó el binario, no
se eludieron protecciones ni se copió código: las técnicas de descubrimiento de
red son estándar (ICMP, ARP, SNMP, NetBIOS…) y no son propietarias.

## 1. Estructura del binario
- PE válido. Secciones muy pequeñas (`.text` ~16 KB, `.rsrc` ~38 KB; total ~66 KB)
  frente a 2,16 MB de archivo → **overlay enorme**: es un **instalador/self-extractor**;
  el programa real va comprimido en el overlay.
- El *stub* del instalador solo importa `KERNEL32/USER32/GDI32/COMCTL32` (no es el
  programa final). Por eso la tabla de imports del PE no revela las APIs de red.

## 2. Técnicas confirmadas por análisis estático (strings del payload)
| Evidencia en el binario | Técnica de descubrimiento |
|---|---|
| `WS2_32.DLL` (Winsock) | **ICMP echo (ping sweep)** vía raw sockets, sondas **TCP/UDP**, `gethostby*` |
| `TTL` (campo) | Lee el **TTL** de las respuestas ICMP → inferencia de SO / nº de saltos |
| `SNMPAPI.DLL`, `MGMTAPI.DLL`, `SnmpMgrOpen`, `SnmpUtil` | **SNMP manager**: consulta OIDs (`sysDescr`, `sysName`, interfaces) a switches, routers, APs e impresoras |

## 3. Técnicas propias del producto (no visibles por estar comprimido el payload, pero características de LookLAN)
- **ARP** → dirección **MAC** y **fabricante (OUI/vendor)** de cada host de la LAN.
- **NetBIOS** (UDP/137) → **nombre de equipo** y **grupo de trabajo/dominio**.
- Resolución de **hostname** (DNS/reverse).
- Sondeo de **puertos/servicios** comunes.

## 4. Mapeo a HADES SENTINEL — qué ya cubre y qué falta

| Técnica de LookLAN | Estado en HADES | Dónde |
|---|---|---|
| ICMP ping sweep | ✅ Cubierto | perfil de descubrimiento `-PE -PP` |
| Sondas TCP/UDP para hosts que filtran ICMP | ✅ **Mejor que LookLAN** | `-PS`/`-PA`/`-PU` (LookLAN es sobre todo ICMP+SNMP) |
| Inferencia de SO por TTL | ✅ Superado | Fase 4 usa `-O` (osscan), más completo que TTL |
| Cruza el router (L3) a rangos enrutados | ✅ Cubierto (esta mejora) | descubrimiento adaptativo on-link/L3 |
| Resolución de hostname | ✅ Parcial | reverse DNS en fase profunda (`-n` en descubrimiento por velocidad) |
| **ARP → MAC + fabricante** | ✅ Cubierto | `hechos_desde_nmap` (MAC/vendor on-link) + MAC vía NetBIOS en `asset_profile` |
| **SNMP (sysDescr/sysName)** | ✅ **Cubierto** | `asset_profile()` → `--script snmp-info,snmp-sysdescr` |
| **NetBIOS (nombre/workgroup)** | ✅ **Cubierto** | `asset_profile()` → `--script nbstat` |

## 5. Paridad IMPLEMENTADA (2026-08-27)
La brecha se cerró con Nmap, sin dependencias nuevas. En `hades_win_master_advanced.py`:

- **`asset_profile(ip)`** — perfila cada host vivo:
  `nmap -sU -n -p161,137 --script snmp-info,snmp-sysdescr,nbstat --host-timeout 60s`
  (techo de subproceso `HADES_ASSET_PROFILE_TIMEOUT`, 120 s por defecto).
- **`hechos_desde_perfil(salida)`** — estructura la identidad: `snmp_sysdescr`,
  `snmp_sysname`, `snmp_activo`, `netbios_nombre`, `netbios_usuario`,
  `netbios_mac`, `netbios_vendor`.
- **`bloque_perfil(perfil)`** — render legible para informe y prompt de IA.
- **Integrado en `full_audit`** como paso **1b**: la sección
  `[IDENTIDAD DEL ACTIVO (SNMP/NetBIOS)]` se añade al informe y la identidad entra
  como *hecho verificado* en el prompt de la IA (saber que un activo es un switch
  gestionable o una impresora cambia el impacto de negocio evaluado).
  Un fallo del perfilado **nunca aborta** la auditoría (se registra y se continúa).
- Comunidad SNMP configurable y **saneada** (`HADES_SNMP_COMMUNITIES`, solo
  alfanumérico) para que no pueda inyectar argumentos en la línea de comandos.

**Validado:** 13 tests nuevos (`tests/test_asset_profile.py`), suite total **74/74 OK**;
prueba real contra un router (10,2 s) y parsers verificados con salidas de switch
Cisco, impresora HP y PC Windows.

Gotchas encontrados y resueltos:
- Nmap rinde las claves con prefijos variables (`|   sysDescr:`, `|_  sysDescr:` y
  `|_snmp-sysdescr:`): el parser normaliza la línea y acepta las tres formas.
- En **UDP**, `open|filtered` significa **sin respuesta**, no puerto abierto:
  tratarlo como SNMP expuesto generaba un falso positivo en cada host que no
  contesta. Se exige `open` confirmado.

### Pendiente opcional
- **Hostname en el descubrimiento**: reverse DNS (`-R`) en un pase ligero sobre los
  hosts vivos, para mostrar nombres DNS como hace LookLAN.
- Exponer la identidad del activo también en el **mapa 3D** y en el **DOCX ISO 27001**.

> Nota de alcance: para un objetivo **enrutado** como `10.77.0.0/16`, ARP y NetBIOS
> **no cruzan el router** (son de capa 2 / broadcast local); ahí las técnicas
> válidas son ICMP/TCP/UDP (ya implementadas) y **SNMP** (recomendación 1). ARP y
> NetBIOS aplican cuando el objetivo está en la propia subred (on-link).

## 6. Anomalía corregida en esta sesión
El modo Custom con `10.77.0.0/16` "no hacía nada" porque el descubrimiento usaba
timing fijo (`--min-rate 200`, techo 600 s): 65.536 IPs no terminaban en 10 min y
`execute` cortaba Nmap devolviendo una lista incompleta. **Corregido** con escalado
dinámico del `--min-rate` y del techo del subproceso según el tamaño del objetivo
(`_scaled_routed_discovery`). Un `/16` pasa a `--min-rate 1092`, techo 900 s.
