#!/usr/bin/env python3
"""
HADES — Generador de Informe Ejecutivo ISO/IEC 27001 (DOCX)
===========================================================
Convierte el `INFORME_MAESTRO.md` consolidado de una auditoría HADES en UN ÚNICO
documento .docx ejecutivo con estructura alineada a ISO/IEC 27001:2022.

Diseño propio LISTO PARA TU MARCA: edita el bloque ``BRANDING`` (logo, colores,
nombre de empresa, autor). Si defines ``logo_path`` y el archivo existe, se inserta
automáticamente en portada y cabecera; si no, se omite sin romper nada.

El scoring de riesgo es DETERMINISTA (heurístico, no decidido por la IA). El texto
de la IA se incluye sólo como análisis consultivo.

Uso CLI:
    python hades_report_docx.py <ruta\\INFORME_MAESTRO.md> [salida.docx]
    python hades_report_docx.py informes\\informe_XXXX\\INFORME_MAESTRO.md
"""
import os
import re
import sys
from datetime import datetime

try:
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
except ImportError:
    sys.stderr.write("[ERROR] Falta 'python-docx'. Instala con: pip install python-docx\n")
    raise

# Reconfigurar UTF-8 en Windows (logs con '→'/emojis)
if sys.platform.startswith("win") or os.name == "nt":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════════════
#  MARCA — EDITA ESTO LUEGO CON TU IDENTIDAD CORPORATIVA
# ════════════════════════════════════════════════════════════════════════════
_BRAND_DIR = os.path.dirname(os.path.abspath(__file__))
BRANDING = {
    "company_name":    "HADES SENTINEL — CIBERAGENTES",
    "logo_path":       os.path.join(_BRAND_DIR, "assets", "logo_hades_sentinel_doc.png"),
    "report_title":    "Informe de Auditoría de Seguridad de Red",
    "standard":        "ISO/IEC 27001:2022",
    "author":          "Equipo de Ciberseguridad · CIBERAGENTES",
    "confidentiality": "CONFIDENCIAL",
    # Paleta corporativa derivada del logo (azul eléctrico + rojo cyber + acero):
    "primary":   (0x12, 0x22, 0x33),   # acero/azul muy oscuro (escudo)
    "secondary": (0x18, 0x9C, 0xD4),   # azul eléctrico (ojos/circuitos)
    "accent":    (0xCE, 0x3A, 0x16),   # rojo cyber (glow derecho / riesgos)
    "light":     (0xD7, 0xE6, 0xF2),   # fondo de cabeceras de tabla
}

# Niveles de riesgo (determinista) y sus colores
RISK_COLORS = {
    "CRÍTICO":     "C00000",
    "ALTO":        "E36C09",
    "MEDIO":       "BF9000",
    "BAJO":        "548235",
    "INFORMATIVO": "808080",
}
RISK_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]


def _rgb(t):
    return RGBColor(t[0], t[1], t[2])


# ════════════════════════════════════════════════════════════════════════════
#  PARSEO DEL INFORME_MAESTRO.md
# ════════════════════════════════════════════════════════════════════════════
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
PORT_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+(open|filtered|open\|filtered)\s+([^\s]+)(?:\s+(.*))?$",
                     re.IGNORECASE)


def _meta_value(md, label):
    m = re.search(rf"\|\s*{re.escape(label)}\s*\|\s*(.+?)\s*\|", md)
    return m.group(1).strip() if m else ""


def parse_master_report(md):
    """Extrae estructura del INFORME_MAESTRO.md → dict con metadata, tráfico y hosts."""
    data = {
        "subnet": _meta_value(md, "Red objetivo").strip("`"),
        "date":   _meta_value(md, "Fecha"),
        "devices": _meta_value(md, "Dispositivos activos"),
        "ips_raw": _meta_value(md, "IPs"),
        "tools": {},
        "traffic_summary": "",
        "traffic_ai": "",
        "hosts": [],
    }

    # Tabla de herramientas (pre-flight), si existe
    for name in ("Nmap", "Tshark", "Nuclei", "OpenSSL", "Ollama"):
        m = re.search(rf"\|\s*{name}\s*\|\s*(.+?)\s*\|", md)
        if m:
            data["tools"][name] = "✅" in m.group(1) or "Disponible" in m.group(1)

    # Resumen de tráfico (Fase 2)
    mt = re.search(r"## Fase 2.*?```(.*?)```", md, re.DOTALL)
    if mt:
        data["traffic_summary"] = mt.group(1).strip()
    ma = re.search(r"### Análisis IA del Tráfico\s*(.*?)\n---", md, re.DOTALL)
    if ma:
        data["traffic_ai"] = ma.group(1).strip()

    # Bloques por host: delimitados por "OBJETIVO: <ip>"
    blocks = re.split(r"={5,}\s*\nOBJETIVO:\s*", md)
    for blk in blocks[1:]:
        ip_m = re.match(r"([0-9.]+)", blk.strip())
        if not ip_m:
            continue
        ip = ip_m.group(1)
        host = _parse_host_block(ip, blk)
        data["hosts"].append(host)

    return data


def _parse_host_block(ip, blk):
    host = {
        "ip": ip, "status": "desconocido", "mac": "", "vendor": "",
        "os": "", "ports": [], "cves": [], "nuclei": [], "ai": "", "risk": "INFORMATIVO",
        "latency": "", "traceroute": [], "device_type": "Desconocido",
    }

    # Sección NMAP
    nmap_m = re.search(r"\[NMAP\](.*?)(?:\[NUCLEI\]|\[SSL/TLS\]|\[ANÁLISIS IA HADES\]|$)", blk, re.DOTALL)
    nmap_txt = nmap_m.group(1) if nmap_m else blk

    # Estado del host
    if re.search(r"Host seems down|0 hosts up", nmap_txt):
        host["status"] = "caído / sin respuesta"
    elif re.search(r"All \d+ scanned ports.*are closed", nmap_txt):
        host["status"] = "activo (todos los puertos cerrados)"
    elif re.search(r"All \d+ scanned ports.*are filtered", nmap_txt):
        host["status"] = "activo (todos los puertos filtrados)"
    elif re.search(r"Host is up", nmap_txt):
        host["status"] = "activo"

    # MAC + fabricante
    mac_m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?", nmap_txt)
    if mac_m:
        host["mac"] = mac_m.group(1)
        host["vendor"] = (mac_m.group(2) or "").strip()

    # Sistema operativo (varias formas que produce Nmap)
    for pat in (r"OS details:\s*(.+)", r"Aggressive OS guesses:\s*(.+)",
                r"Running(?: \(JUST GUESSING\))?:\s*(.+)",
                r"Too many fingerprints.*"):
        os_m = re.search(pat, nmap_txt)
        if os_m:
            host["os"] = (os_m.group(1).strip() if os_m.groups() else os_m.group(0).strip())[:200]
            break

    # Puertos abiertos
    for line in nmap_txt.splitlines():
        pm = PORT_RE.match(line)
        if pm:
            port, proto, state, service, version = pm.groups()
            if "open" in state.lower():
                host["ports"].append({
                    "port": port, "proto": proto.lower(),
                    "service": service, "version": (version or "").strip(),
                })

    # CVEs (de scripts NSE de Nmap o de cualquier parte del bloque)
    host["cves"] = sorted(set(c.upper() for c in CVE_RE.findall(blk)))

    # Hallazgos Nuclei
    nu_m = re.search(r"\[NUCLEI\](.*?)(?:\[SSL/TLS\]|\[ANÁLISIS IA HADES\]|$)", blk, re.DOTALL)
    if nu_m:
        for line in nu_m.group(1).splitlines():
            line = line.strip()
            sev = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.IGNORECASE)
            if sev:
                host["nuclei"].append(line)

    # Análisis IA
    ai_m = re.search(r"\[ANÁLISIS IA HADES\](.*)", blk, re.DOTALL)
    if ai_m:
        host["ai"] = ai_m.group(1).split("\n---")[0].strip()

    # Latencia: "Host is up (0.0032s latency)."
    lat_m = re.search(r"Host is up \(([\d.]+)s latency\)", nmap_txt)
    if lat_m:
        host["latency"] = f"{float(lat_m.group(1)) * 1000:.1f} ms"

    # Traceroute: sección "TRACEROUTE" → lista de saltos {hop, rtt, ip}
    tr_m = re.search(r"TRACEROUTE.*?\n(.*?)(?:\n\s*\n|\nOS and Service|\nNmap done|$)", nmap_txt, re.DOTALL)
    if tr_m:
        for line in tr_m.group(1).splitlines():
            hop = re.match(r"\s*(\d+)\s+(\.\.\.|[\d.]+\s*ms)\s+([0-9.]+)", line)
            if hop:
                host["traceroute"].append({"hop": hop.group(1), "rtt": hop.group(2).strip(), "ip": hop.group(3)})

    host["device_type"] = _infer_device_type(host)
    host["risk"] = _assess_risk(host)
    return host


# ── Inferencia de tipo de dispositivo (heurística determinista) ───────────────
ROUTER_VENDORS = ("askey", "tp-link", "tplink", "cisco", "huawei", "mikrotik", "ubiquiti",
                  "netgear", "d-link", "dlink", "zte", "arris", "technicolor", "avm", "fritz",
                  "aruba", "ruckus", "zyxel", "sagemcom")
PRINTER_HINTS = ("canon", "hewlett", "epson", "brother", "lexmark", "kyocera", "xerox", "ricoh")
IOT_VENDORS = ("espressif", "tuya", "sonoff", "shelly", "amazon technologies", "nest", "ring",
               "wyze", "raspberry", "particle", "texas instruments")
NAS_VENDORS = ("synology", "qnap", "western digital", "seagate", "buffalo")
MOBILE_VENDORS = ("apple", "samsung", "oneplus", "motorola", "oppo", "vivo", "realme")


def _infer_device_type(host):
    ports = {p["port"] for p in host["ports"]}
    svcs = " ".join(p["service"].lower() for p in host["ports"])
    vendor = (host.get("vendor") or "").lower()
    os_l = (host.get("os") or "").lower()
    ip = host["ip"]

    if ip.endswith(".1") or any(v in vendor for v in ROUTER_VENDORS):
        return "Router / Gateway"
    if (ports & {"631", "9100", "515"}) or any(h in vendor for h in PRINTER_HINTS) \
            or "printer" in svcs or "cups" in svcs or "ipp" in svcs:
        return "Impresora"
    if any(v in vendor for v in NAS_VENDORS):
        return "NAS / Almacenamiento"
    if "windows" in os_l or (ports & {"445", "139", "135"}):
        return "Equipo Windows"
    if ("linux" in os_l or "unix" in os_l) and (ports & {"22", "80", "443", "3306", "5432", "8080"}):
        return "Servidor (Linux/Unix)"
    if any(v in vendor for v in IOT_VENDORS) or "camera" in os_l or "webcam" in os_l or "android" in os_l:
        return "IoT / Embebido"
    if any(v in vendor for v in MOBILE_VENDORS) and not ports:
        return "Dispositivo móvil"
    if host["status"].startswith("caído"):
        return "Inactivo"
    if not ports and host["status"].startswith("activo"):
        return "Host sin servicios expuestos"
    return "Desconocido"


# Servicios/puertos de alto riesgo si están expuestos
RISKY_PORTS = {"21", "23", "135", "139", "445", "3389", "5900", "1433", "3306", "5432"}
RISKY_SERVICES = {"telnet", "ftp", "microsoft-ds", "netbios-ssn", "msrpc", "ms-wbt-server",
                  "rdp", "vnc", "ms-sql-s", "mysql"}
OUTDATED_OS_RE = re.compile(r"2\.6\b|vista|2008|windows xp|android 2|server 2003", re.IGNORECASE)
CRITICAL_NUCLEI_RE = re.compile(r"\[(CRITICAL|HIGH)\]", re.IGNORECASE)


def _assess_risk(host):
    """Nivel de riesgo DETERMINISTA basado en evidencia (no en la IA)."""
    if host["status"].startswith("caído"):
        return "INFORMATIVO"

    score = 0
    score += 3 * len(host["cves"])
    score += 2 * sum(1 for n in host["nuclei"] if CRITICAL_NUCLEI_RE.search(n))
    score += 1 * len(host["nuclei"])
    for p in host["ports"]:
        if p["port"] in RISKY_PORTS or p["service"].lower() in RISKY_SERVICES:
            score += 2
        else:
            score += 1
    if OUTDATED_OS_RE.search(host.get("os", "")):
        score += 2

    if host["cves"] or any(CRITICAL_NUCLEI_RE.search(n) for n in host["nuclei"]):
        # Hay CVEs/hallazgos altos confirmados
        return "CRÍTICO" if score >= 8 else "ALTO"
    if score >= 7:
        return "ALTO"
    if score >= 4:
        return "MEDIO"
    if score >= 1:
        return "BAJO"
    return "INFORMATIVO"


# ════════════════════════════════════════════════════════════════════════════
#  MAPEO A CONTROLES ISO/IEC 27001:2022 (Anexo A)
# ════════════════════════════════════════════════════════════════════════════
def map_iso_controls(data):
    """Devuelve lista de (control, título, justificación) aplicables según hallazgos."""
    controls = {}
    def add(cid, title, why):
        controls.setdefault(cid, [title, set()])[1].add(why)

    any_open = any(h["ports"] for h in data["hosts"])
    any_cve = any(h["cves"] or h["nuclei"] for h in data["hosts"])
    any_cleartext = False
    any_smb = False
    any_mgmt = False
    any_outdated = False

    for h in data["hosts"]:
        for p in h["ports"]:
            s = p["service"].lower(); port = p["port"]
            if s in ("telnet", "ftp") or port in ("21", "23"):
                any_cleartext = True
            if port in ("445", "139", "135") or s in ("microsoft-ds", "netbios-ssn", "msrpc"):
                any_smb = True
            if port in ("22", "3389", "5900") or s in ("ssh", "ms-wbt-server", "rdp", "vnc"):
                any_mgmt = True
        if OUTDATED_OS_RE.search(h.get("os", "")):
            any_outdated = True

    if any_open:
        add("A.8.20", "Seguridad de las redes", "Servicios de red expuestos detectados en hosts de la LAN.")
        add("A.8.21", "Seguridad de los servicios de red", "Necesidad de asegurar y monitorizar los servicios de red activos.")
    if any_cve or any_outdated:
        add("A.8.8", "Gestión de vulnerabilidades técnicas", "Se detectaron vulnerabilidades conocidas y/o software/SO desactualizado.")
    if any_cleartext:
        add("A.8.24", "Uso de criptografía", "Protocolos en texto claro (Telnet/FTP) sin cifrado.")
        add("A.8.5", "Autenticación segura", "Servicios sin autenticación cifrada.")
    if any_smb:
        add("A.8.22", "Segregación de redes", "Servicios SMB/RPC/NetBIOS expuestos; conviene segmentar.")
        add("A.5.15", "Control de acceso", "Servicios de archivos/administración accesibles en la red.")
    if any_mgmt:
        add("A.5.15", "Control de acceso", "Servicios de administración remota (SSH/RDP/VNC) expuestos.")
    # Controles siempre recomendados tras una auditoría
    add("A.8.16", "Actividades de seguimiento (monitorización)", "Monitorización continua de la red y los activos.")
    add("A.5.7", "Inteligencia de amenazas", "Incorporar inteligencia de amenazas al proceso de gestión de riesgos.")
    add("A.8.9", "Gestión de la configuración", "Asegurar configuraciones base seguras en los activos.")

    out = []
    for cid in sorted(controls.keys()):
        title, whys = controls[cid]
        out.append((cid, title, " ".join(sorted(whys))))
    return out


# ════════════════════════════════════════════════════════════════════════════
#  CONSTRUCCIÓN DEL DOCX
# ════════════════════════════════════════════════════════════════════════════
def _shade(cell, hex_fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tcPr.append(shd)


def _set_cell_text(cell, text, bold=False, color=None, size=9, align=None, white=False):
    cell.text = ""
    p = cell.paragraphs[0]
    if align is not None:
        p.alignment = align
    run = p.add_run(str(text))
    run.bold = bold
    run.font.size = Pt(size)
    if white:
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    elif color is not None:
        run.font.color.rgb = color


def _header_row(table, headers):
    hdr = table.rows[0].cells
    for i, h in enumerate(headers):
        _set_cell_text(hdr[i], h, bold=True, size=9, white=True,
                       align=WD_ALIGN_PARAGRAPH.LEFT)
        _shade(hdr[i], "%02X%02X%02X" % BRANDING["primary"])


def _add_page_number(footer_par):
    run = footer_par.add_run()
    fldChar1 = OxmlElement("w:fldChar"); fldChar1.set(qn("w:fldCharType"), "begin")
    instrText = OxmlElement("w:instrText"); instrText.set(qn("xml:space"), "preserve"); instrText.text = "PAGE"
    fldChar2 = OxmlElement("w:fldChar"); fldChar2.set(qn("w:fldCharType"), "end")
    run._r.append(fldChar1); run._r.append(instrText); run._r.append(fldChar2)


def _heading(doc, text, level=1):
    h = doc.add_heading(text, level=level)
    for run in h.runs:
        run.font.color.rgb = _rgb(BRANDING["primary"] if level == 1 else BRANDING["secondary"])
    return h


def build_iso27001_docx(data, output_path):
    doc = Document()

    # Estilo base
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)

    # Cabecera y pie con marca
    section = doc.sections[0]
    header = section.header
    hp = header.paragraphs[0]
    hp.text = f"{BRANDING['company_name']}  ·  {BRANDING['confidentiality']}"
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for r in hp.runs:
        r.font.size = Pt(8); r.font.color.rgb = _rgb(BRANDING["secondary"])

    footer = section.footer
    fp = footer.paragraphs[0]
    fp.text = f"{BRANDING['confidentiality']} — {BRANDING['report_title']}   ·   Página "
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for r in fp.runs:
        r.font.size = Pt(8); r.font.color.rgb = _rgb(BRANDING["secondary"])
    _add_page_number(fp)

    # ───────── PORTADA ─────────
    logo = BRANDING.get("logo_path", "")
    if logo and os.path.exists(logo):
        try:
            doc.add_picture(logo, width=Inches(2.2))
            doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception:
            pass
    else:
        ph = doc.add_paragraph()
        ph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = ph.add_run("[ LOGO DE TU EMPRESA ]")
        r.italic = True; r.font.size = Pt(11); r.font.color.rgb = _rgb(BRANDING["secondary"])

    for _ in range(2):
        doc.add_paragraph()

    t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run(BRANDING["report_title"].upper())
    r.bold = True; r.font.size = Pt(26); r.font.color.rgb = _rgb(BRANDING["primary"])

    s = doc.add_paragraph(); s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = s.add_run(f"Conforme a {BRANDING['standard']}")
    r.font.size = Pt(14); r.font.color.rgb = _rgb(BRANDING["secondary"])

    doc.add_paragraph()
    line = doc.add_paragraph(); line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = line.add_run("INFORME EJECUTIVO DE CIBERSEGURIDAD")
    r.font.size = Pt(12); r.bold = True

    for _ in range(4):
        doc.add_paragraph()

    # Tabla de metadatos en portada
    meta = doc.add_table(rows=0, cols=2)
    meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    def meta_row(k, v):
        row = meta.add_row().cells
        _set_cell_text(row[0], k, bold=True, size=10, color=_rgb(BRANDING["primary"]))
        _set_cell_text(row[1], v, size=10)
    meta_row("Organización", BRANDING["company_name"])
    meta_row("Red auditada", data.get("subnet") or "N/D")
    meta_row("Fecha de auditoría", data.get("date") or datetime.now().strftime("%d/%m/%Y %H:%M"))
    meta_row("Dispositivos detectados", data.get("devices") or str(len(data["hosts"])))
    meta_row("Elaborado por", BRANDING["author"])
    meta_row("Clasificación", BRANDING["confidentiality"])
    meta_row("Estándar de referencia", BRANDING["standard"])

    doc.add_page_break()

    # ───────── 1. RESUMEN EJECUTIVO ─────────
    _heading(doc, "1. Resumen Ejecutivo", 1)

    hosts = data["hosts"]
    up = [h for h in hosts if not h["status"].startswith("caído")]
    total_ports = sum(len(h["ports"]) for h in hosts)
    total_cves = sorted({c for h in hosts for c in h["cves"]})
    risk_count = {lvl: sum(1 for h in hosts if h["risk"] == lvl) for lvl in RISK_ORDER}

    doc.add_paragraph(
        f"Se realizó una auditoría de seguridad sobre la red {data.get('subnet') or 'objetivo'}, "
        f"identificando {len(hosts)} dispositivo(s), de los cuales {len(up)} respondieron activamente. "
        f"Se detectaron {total_ports} puerto(s)/servicio(s) abiertos y {len(total_cves)} vulnerabilidad(es) "
        f"con identificador CVE asociado. El presente informe consolida todos los hallazgos en un único "
        f"documento ejecutivo, evaluando el riesgo de forma determinista y mapeándolo a los controles del "
        f"Anexo A de {BRANDING['standard']}."
    )

    _heading(doc, "Distribución de riesgo", 2)
    rt = doc.add_table(rows=1, cols=2)
    rt.style = "Table Grid"
    _header_row(rt, ["Nivel de riesgo", "Nº de activos"])
    for lvl in RISK_ORDER:
        row = rt.add_row().cells
        _set_cell_text(row[0], lvl, bold=True, white=True)
        _shade(row[0], RISK_COLORS[lvl])
        _set_cell_text(row[1], risk_count[lvl], align=WD_ALIGN_PARAGRAPH.CENTER)

    # ───────── 2. ALCANCE Y OBJETIVOS ─────────
    _heading(doc, "2. Alcance y Objetivos", 1)
    doc.add_paragraph(
        "El alcance de esta auditoría comprende el descubrimiento y la evaluación de seguridad de los "
        f"activos accesibles en la red local {data.get('subnet') or 'objetivo'}. Los objetivos son: "
        "(a) inventariar los dispositivos activos; (b) identificar servicios y puertos expuestos; "
        "(c) detectar vulnerabilidades técnicas conocidas; (d) analizar el tráfico de red en busca de "
        "actividad anómala; y (e) emitir recomendaciones priorizadas conforme a ISO/IEC 27001."
    )

    # ───────── 3. METODOLOGÍA ─────────
    _heading(doc, "3. Metodología", 1)
    doc.add_paragraph(
        "La auditoría se ejecutó con el agente HADES, que orquesta herramientas estándar de la industria "
        "en un pipeline robusto y reproducible:"
    )
    mt = doc.add_table(rows=1, cols=2); mt.style = "Table Grid"
    _header_row(mt, ["Herramienta", "Función en la auditoría"])
    for tool, desc in [
        ("Nmap", "Descubrimiento de hosts (ARP) y escaneo de puertos, servicios y sistema operativo."),
        ("Nuclei", "Detección de vulnerabilidades web mediante plantillas (CVE, exposiciones, malas configuraciones)."),
        ("Tshark", "Captura y análisis pasivo de tráfico de red."),
        ("OpenSSL", "Auditoría de configuración TLS/SSL de servicios cifrados."),
        ("Ollama (IA local)", "Análisis consultivo de los hallazgos (no decisorio)."),
    ]:
        row = mt.add_row().cells
        _set_cell_text(row[0], tool, bold=True, color=_rgb(BRANDING["primary"]))
        _set_cell_text(row[1], desc)

    # ───────── 4. RESUMEN DE HALLAZGOS ─────────
    _heading(doc, "4. Resumen de Hallazgos por Activo", 1)
    ht = doc.add_table(rows=1, cols=6); ht.style = "Table Grid"
    _header_row(ht, ["Host (IP)", "Estado", "Sistema operativo", "Puertos abiertos", "CVE", "Riesgo"])
    for h in sorted(hosts, key=lambda x: RISK_ORDER.index(x["risk"])):
        row = ht.add_row().cells
        _set_cell_text(row[0], h["ip"], bold=True, size=9)
        _set_cell_text(row[1], h["status"], size=8)
        _set_cell_text(row[2], (h["os"] or "N/D")[:60], size=8)
        ports_str = ", ".join(f"{p['port']}/{p['proto']}" for p in h["ports"]) or "—"
        _set_cell_text(row[3], ports_str, size=8)
        _set_cell_text(row[4], str(len(h["cves"])) if h["cves"] else "—", size=9,
                       align=WD_ALIGN_PARAGRAPH.CENTER)
        _set_cell_text(row[5], h["risk"], bold=True, white=True, size=9,
                       align=WD_ALIGN_PARAGRAPH.CENTER)
        _shade(row[5], RISK_COLORS[h["risk"]])

    # ───────── 5. DETALLE POR ACTIVO ─────────
    _heading(doc, "5. Detalle Técnico por Activo", 1)
    for idx, h in enumerate(sorted(hosts, key=lambda x: RISK_ORDER.index(x["risk"])), 1):
        _heading(doc, f"5.{idx}  Host {h['ip']}  —  Riesgo {h['risk']}", 2)
        info = doc.add_table(rows=0, cols=2); info.style = "Table Grid"
        def irow(k, v):
            c = info.add_row().cells
            _set_cell_text(c[0], k, bold=True, size=9, color=_rgb(BRANDING["primary"]))
            _set_cell_text(c[1], v if v else "N/D", size=9)
        irow("Estado", h["status"])
        irow("Sistema operativo", h["os"])
        irow("Dirección MAC", f"{h['mac']} ({h['vendor']})" if h["mac"] else "N/D")
        irow("Vulnerabilidades (CVE)", ", ".join(h["cves"]) if h["cves"] else "Ninguna identificada por CVE")
        if h["nuclei"]:
            irow("Hallazgos Nuclei", "\n".join(h["nuclei"]))

        if h["ports"]:
            pt = doc.add_table(rows=1, cols=4); pt.style = "Table Grid"
            _header_row(pt, ["Puerto", "Protocolo", "Servicio", "Versión"])
            for p in h["ports"]:
                row = pt.add_row().cells
                _set_cell_text(row[0], p["port"], size=9)
                _set_cell_text(row[1], p["proto"], size=9)
                _set_cell_text(row[2], p["service"], size=9)
                _set_cell_text(row[3], p["version"] or "—", size=8)

        if h["ai"]:
            ap = doc.add_paragraph()
            r = ap.add_run("Análisis consultivo (IA local):")
            r.bold = True; r.font.color.rgb = _rgb(BRANDING["secondary"])
            # Limpieza ligera de markdown del texto IA
            clean = re.sub(r"\*\*(.+?)\*\*", r"\1", h["ai"])
            doc.add_paragraph(clean[:3000])
        doc.add_paragraph()

    # ───────── 6. MAPEO A CONTROLES ISO 27001 ─────────
    _heading(doc, f"6. Mapeo a Controles del Anexo A de {BRANDING['standard']}", 1)
    doc.add_paragraph(
        "Los hallazgos se relacionan con los siguientes controles del Anexo A, que constituyen la base "
        "para el plan de tratamiento de riesgos:"
    )
    ct = doc.add_table(rows=1, cols=3); ct.style = "Table Grid"
    _header_row(ct, ["Control", "Título", "Justificación"])
    for cid, title, why in map_iso_controls(data):
        row = ct.add_row().cells
        _set_cell_text(row[0], cid, bold=True, size=9, color=_rgb(BRANDING["primary"]))
        _set_cell_text(row[1], title, size=9)
        _set_cell_text(row[2], why, size=8)

    # ───────── 7. RECOMENDACIONES ─────────
    _heading(doc, "7. Recomendaciones Priorizadas", 1)
    recs = _build_recommendations(data)
    for i, rec in enumerate(recs, 1):
        p = doc.add_paragraph(style="List Number")
        p.add_run(rec)

    # ───────── 8. CONCLUSIÓN ─────────
    _heading(doc, "8. Conclusión", 1)
    crit = risk_count["CRÍTICO"] + risk_count["ALTO"]
    doc.add_paragraph(
        f"La auditoría identificó {crit} activo(s) con riesgo Alto o Crítico que requieren atención "
        "prioritaria. La implementación de las recomendaciones y los controles del Anexo A indicados "
        "reducirá significativamente la superficie de exposición de la red. Se recomienda repetir esta "
        "auditoría de forma periódica como parte del ciclo de mejora continua del SGSI."
    )

    # ───────── APÉNDICE: TRÁFICO ─────────
    if data.get("traffic_summary") or data.get("traffic_ai"):
        doc.add_page_break()
        _heading(doc, "Apéndice A — Análisis de Tráfico de Red", 1)
        if data.get("traffic_summary"):
            doc.add_paragraph(data["traffic_summary"])
        if data.get("traffic_ai"):
            r = doc.add_paragraph().add_run("Interpretación (IA local):")
            r.bold = True; r.font.color.rgb = _rgb(BRANDING["secondary"])
            doc.add_paragraph(re.sub(r"\*\*(.+?)\*\*", r"\1", data["traffic_ai"])[:3000])

    doc.save(output_path)
    return output_path


def _build_recommendations(data):
    recs = []
    cleartext = smb = mgmt = outdated = cves = False
    for h in data["hosts"]:
        for p in h["ports"]:
            s = p["service"].lower(); port = p["port"]
            if s in ("telnet", "ftp") or port in ("21", "23"): cleartext = True
            if port in ("445", "139", "135"): smb = True
            if port in ("22", "3389", "5900"): mgmt = True
        if OUTDATED_OS_RE.search(h.get("os", "")): outdated = True
        if h["cves"] or h["nuclei"]: cves = True

    if cves:
        recs.append("Remediar las vulnerabilidades con CVE identificadas aplicando parches y actualizaciones "
                    "del proveedor (control A.8.8 — Gestión de vulnerabilidades técnicas).")
    if outdated:
        recs.append("Actualizar o reemplazar los sistemas operativos y servicios obsoletos detectados, que "
                    "ya no reciben soporte de seguridad.")
    if cleartext:
        recs.append("Deshabilitar servicios en texto claro (Telnet/FTP) y sustituirlos por equivalentes "
                    "cifrados (SSH/SFTP/FTPS) — controles A.8.24 y A.8.5.")
    if smb:
        recs.append("Restringir y segmentar el acceso a servicios SMB/RPC/NetBIOS (445/139/135); limitarlos "
                    "a redes de gestión y aplicar firewall por host — control A.8.22.")
    if mgmt:
        recs.append("Proteger los servicios de administración remota (SSH/RDP/VNC) con autenticación fuerte, "
                    "MFA y listas de control de acceso — control A.5.15.")
    recs.append("Implementar monitorización continua del tráfico y los eventos de seguridad de la red "
                "(control A.8.16).")
    recs.append("Mantener un inventario actualizado de activos y una línea base de configuración segura "
                "(controles A.5.9 y A.8.9).")
    recs.append("Repetir esta auditoría periódicamente e integrarla en el ciclo de mejora continua del SGSI.")
    return recs


# ════════════════════════════════════════════════════════════════════════════
#  API DE ALTO NIVEL / CLI
# ════════════════════════════════════════════════════════════════════════════
def generate_from_master(master_md_path, output_path=None):
    """Genera el DOCX a partir de un INFORME_MAESTRO.md. Devuelve la ruta del .docx."""
    with open(master_md_path, "r", encoding="utf-8") as f:
        md = f.read()
    data = parse_master_report(md)
    if output_path is None:
        base = os.path.dirname(os.path.abspath(master_md_path))
        output_path = os.path.join(base, "INFORME_EJECUTIVO_ISO27001.docx")
    build_iso27001_docx(data, output_path)
    return output_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python hades_report_docx.py <ruta\\INFORME_MAESTRO.md> [salida.docx]")
        sys.exit(1)
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    if not os.path.exists(src):
        print(f"[ERROR] No existe: {src}")
        sys.exit(1)
    path = generate_from_master(src, out)
    print(f"[OK] Informe ejecutivo ISO 27001 generado: {path}")
