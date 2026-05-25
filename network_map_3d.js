/* ============================================================================
 *  HADES — Mapa de Red 3D (Three.js / WebGL vía 3d-force-graph)
 *  Consume datos REALES del escaneo desde /api/graph y los visualiza como un
 *  grafo force-directed 3D estilo SOC: router central, hosts radiales coloreados
 *  por criticidad, partículas de flujo (paquetes) y panel lateral SOC al hacer
 *  clic. Mantiene la misma interfaz pública que el mapa anterior:
 *    init(), parseLogLine(msg), clear(), setActivityState(text,color), resetView()
 * ========================================================================== */
class HadesGraph3D {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.graph = null;
        this.currentKey = "";          // huella del conjunto de hosts (para no relayoutear de más)
        this.hostsById = {};           // ip -> datos del host (para el panel SOC)
        this.pollTimer = null;
        this.routerId = "GATEWAY";
        // Indicadores de estado (overlays existentes en el HTML)
        this.statusDotEl = document.getElementById("graphStatusDot");
        this.statusTextEl = document.getElementById("graphStatusText");
        this.hostsCountEl = document.getElementById("graphHostsCount");
        this.subnetEl = document.getElementById("graphSubnetVal");
    }

    // Color de nodo según semántica SOC (verde/amarillo/rojo/blanco/azul)
    static color(node) {
        if (node.isExternal) return "#ff00aa";                // magenta = IP externa (Internet)
        if (node.isRouter) return "#18d0ff";                 // azul = infraestructura crítica
        if (node.risk === "ALTO" || node.risk === "CRÍTICO") return "#ff0033"; // rojo = amenaza
        if (node.risk === "MEDIO") return "#ffd400";          // amarillo = sospechoso
        if (node.status && node.status.indexOf("caído") === 0) return "#dddddd"; // blanco = inactivo/desconocido
        if (node.device_type === "Desconocido") return "#dddddd";
        return "#39ff14";                                     // verde = estable/normal
    }

    // Ícono de red según el tipo de dispositivo (estilo topología/Cisco)
    static iconFor(node) {
        if (node.isExternal) return "☁️";
        const t = (node.device_type || "").toLowerCase();
        if (node.isRouter || t.includes("router") || t.includes("gateway")) return "🌐";
        if (t.includes("impresora") || t.includes("printer")) return "🖨️";
        if (t.includes("windows")) return "🖥️";
        if (t.includes("servidor") || t.includes("server") || t.includes("nas") || t.includes("almacen")) return "🗄️";
        if (t.includes("iot") || t.includes("embebido")) return "📟";
        if (t.includes("móvil") || t.includes("movil") || t.includes("mobile")) return "📱";
        if (t.includes("inactivo")) return "⛔";
        return "💻";  // host genérico / descubierto
    }

    _roundRect(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + w, y, x + w, y + h, r);
        ctx.arcTo(x + w, y + h, x, y + h, r);
        ctx.arcTo(x, y + h, x, y, r);
        ctx.arcTo(x, y, x + w, y, r);
        ctx.closePath();
    }

    // Construye un sprite con el ícono del dispositivo y un borde según criticidad.
    // Si THREE no está o algo falla, devuelve undefined → ForceGraph3D usa su esfera.
    _iconSprite(node) {
        try {
            if (typeof THREE === "undefined" || !THREE.Sprite) return undefined;
            const emoji = HadesGraph3D.iconFor(node);
            const color = HadesGraph3D.color(node);
            const S = 128;
            const cv = document.createElement("canvas");
            cv.width = cv.height = S;
            const ctx = cv.getContext("2d");
            ctx.fillStyle = "rgba(4,8,12,0.92)";
            this._roundRect(ctx, 8, 8, S - 16, S - 16, 18); ctx.fill();
            ctx.lineWidth = 8; ctx.strokeStyle = color;
            ctx.shadowColor = color; ctx.shadowBlur = 12;
            this._roundRect(ctx, 8, 8, S - 16, S - 16, 18); ctx.stroke();
            ctx.shadowBlur = 0;
            ctx.font = "62px 'Segoe UI Emoji','Apple Color Emoji','Noto Color Emoji',sans-serif";
            ctx.textAlign = "center"; ctx.textBaseline = "middle";
            ctx.fillText(emoji, S / 2, S / 2 + 4);
            const tex = new THREE.CanvasTexture(cv);
            tex.anisotropy = 4;
            const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
            const scale = node.isRouter ? 17 : (node.isExternal ? 9 : 12);
            sprite.scale.set(scale, scale, 1);
            return sprite;
        } catch (e) {
            return undefined;
        }
    }

    _retryLib() {
        // El motor 3D se carga como módulo ES (hades-graph-bundle.js) que define
        // window.ForceGraph3D de forma asíncrona. Esperamos a que esté disponible
        // (sondeo cada 200ms, hasta ~8s) en vez de fallar.
        this._libAttempts = (this._libAttempts || 0) + 1;
        if (this._libAttempts > 40) {
            this.container.innerHTML = '<div style="padding:16px;color:#ff6a00;font-family:monospace;font-size:12px">' +
                '[Mapa 3D] No se pudo cargar el motor 3D (vendor/hades-graph-bundle.js). Recarga la página (F5).</div>';
            return;
        }
        this.container.innerHTML = '<div style="padding:16px;color:#18d0ff;font-family:monospace;font-size:12px">' +
            '[Mapa 3D] Cargando motor 3D…</div>';
        setTimeout(() => this.init(), 200);
    }

    init() {
        if (!this.container) { console.warn("[HadesGraph3D] contenedor no encontrado"); return; }
        if (typeof ForceGraph3D === "undefined") {
            this._retryLib();   // reintentar carga de la librería en vez de fallar
            return;
        }

        try {
        this.graph = new ForceGraph3D(this.container)
            .backgroundColor("#04060a")
            .showNavInfo(false)
            .nodeId("id")
            .nodeLabel(n => {
                const dom = (this._hostnames && this._hostnames[n.ip]) || "";
                return `<div style="font-family:monospace;font-size:12px;background:rgba(0,0,0,.85);` +
                    `padding:4px 8px;border:1px solid #18d0ff;border-radius:4px;color:#e0ffe8">` +
                    `<b>${n.ip || n.id}</b><br>${n.device_type || ""}` +
                    (dom ? `<br>🌐 ${dom}` : "") +
                    (n.risk && !n.isExternal ? `<br>Riesgo: ${n.risk}` : "") + `</div>`;
            })
            .nodeColor(HadesGraph3D.color)
            .nodeVal(n => n.isRouter ? 26 : (n.isExternal ? 4 : (5 + (n.ports ? n.ports.length : 0) * 3)))
            .nodeOpacity(0.92)
            .nodeResolution(14)
            .nodeThreeObject(n => this._iconSprite(n))
            .nodeThreeObjectExtend(false)
            .linkColor(l => l.kind === "traffic" ? "rgba(255,60,190,0.8)" : "rgba(0,225,255,0.8)")
            .linkWidth(l => l.kind === "traffic" ? 1.2 : 2.0)
            .linkOpacity(0.75)
            .linkDirectionalParticles(l => (l.particles || 3))
            .linkDirectionalParticleSpeed(l => l.kind === "traffic" ? 0.02 : 0.012)
            .linkDirectionalParticleWidth(l => l.kind === "traffic" ? 2.5 : 4)
            .linkDirectionalParticleColor(l => l.kind === "traffic" ? "#ff80d0" : "#5dff8f")
            .linkDirectionalParticleResolution(6)
            .cooldownTime(8000)
            .onNodeClick(n => this.openPanel(n))
            .onBackgroundClick(() => this.closePanel());
        } catch (err) {
            this.container.innerHTML = '<div style="padding:16px;color:#ff6a00;font-family:monospace;font-size:12px">' +
                '[Mapa 3D] Error al inicializar ForceGraph3D: ' + (err && err.message ? err.message : err) + '</div>';
            console.error("[HadesGraph3D] init error:", err);
            return;
        }

        // Tamaño inicial y resize
        this._resize();
        window.addEventListener("resize", () => this._resize());

        // Botones existentes
        const rb = document.getElementById("btnResetGraph");
        const cb = document.getElementById("btnClearGraph");
        if (rb) rb.addEventListener("click", () => this.resetView());
        if (cb) cb.addEventListener("click", () => this.clear());

        // Crear panel lateral SOC y barra de mini-dashboards
        this._buildPanel();
        this._buildStatsBar();

        // Primera carga + polling de datos reales
        this.refresh();
        this.pollTimer = setInterval(() => this.refresh(), 4000);
        this.setActivityState("EN ESPERA", "#18d0ff");
    }

    _resize() {
        if (this.graph && this.container) {
            this.graph.width(this.container.clientWidth).height(this.container.clientHeight);
        }
    }

    // ── Carga de datos reales desde /api/graph ──────────────────────────────
    async refresh() {
        try {
            // Preferir el token inyectado por el servidor (siempre correcto) y, si no,
            // el de la URL. Evita 403 si la pestaña tiene una URL con token antiguo.
            const token = (typeof REAL_SURVEILLANCE_TOKEN !== "undefined" && REAL_SURVEILLANCE_TOKEN)
                || new URLSearchParams(window.location.search).get("token") || "";
            const res = await fetch(`/api/graph?token=${token}`);
            if (!res.ok) return;
            const data = await res.json();
            this._apply(data);
        } catch (e) { /* el polling reintenta */ }
    }

    _apply(data) {
        if (!data || data.status !== "ok") return;
        const hosts = data.hosts || [];
        const externals = data.externals || [];
        const connections = data.connections || [];
        this.routerId = data.router_ip || "GATEWAY";
        this._hostnames = data.hostnames || {};   // PTR (dominio) de IPs externas; se resuelve en vivo

        // Indexar hosts (LAN) para el panel de detalles
        this.hostsById = {};
        hosts.forEach(h => { this.hostsById[h.ip] = h; });

        // Refrescar EN VIVO el panel del activo seleccionado (datos nuevos o PTR resuelto)
        if (this.selectedHost) {
            if (this.hostsById[this.selectedHost.ip]) this.selectedHost = this.hostsById[this.selectedHost.ip];
            this._renderHostDetail();
        }

        // Overlays + mini-stats
        if (this.hostsCountEl) this.hostsCountEl.textContent = hosts.length;
        if (this.subnetEl && data.subnet) this.subnetEl.textContent = data.subnet;
        this._updateStats(data.stats || {});

        // Huella: incluye hosts, externos y nº de conexiones (para redibujar en vivo
        // a medida que el escaneo detecta nuevos elementos).
        const key = hosts.map(h => h.ip + ":" + h.risk + ":" + (h.ports ? h.ports.length : 0)).sort().join("|")
            + "#E" + externals.slice().sort().join(",") + "#C" + connections.length;
        if (key === this.currentKey) return;
        this.currentKey = key;

        const nodes = [];
        const links = [];
        const seen = new Set();

        // Router central
        if (!hosts.some(h => h.ip === this.routerId)) {
            nodes.push({ id: "GATEWAY", ip: data.subnet || "Gateway", isRouter: true,
                         device_type: "Router / Gateway", risk: "INFORMATIVO", ports: [] });
            this.routerId = "GATEWAY";
            seen.add("GATEWAY");
        }
        // Hosts internos de la LAN
        hosts.forEach(h => {
            const isR = h.ip === this.routerId;
            nodes.push(Object.assign({ id: h.ip, isRouter: isR }, h));
            seen.add(h.ip);
            if (!isR) {
                const ports = h.ports ? h.ports.length : 0;
                links.push({ source: this.routerId, target: h.ip, kind: "lan",
                             particles: Math.min(6, 2 + ports) });
            }
        });
        // Nodos externos (Internet): TODAS las IPs externas + destinos de conexiones
        const extSet = new Set(externals);
        connections.forEach(cn => extSet.add(cn.dst));
        extSet.forEach(ip => {
            if (!seen.has(ip)) {
                nodes.push({ id: ip, ip: ip, isExternal: true,
                             device_type: "Internet (externo)", risk: "INFORMATIVO", ports: [] });
                seen.add(ip);
            }
        });
        // Enlaces de tráfico (host LAN → destino), con partículas según volumen
        const connectedDst = new Set(connections.map(cn => cn.dst));
        connections.forEach(cn => {
            if (seen.has(cn.src) && seen.has(cn.dst)) {
                links.push({ source: cn.src, target: cn.dst, kind: "traffic",
                             proto: cn.proto, port: cn.port,
                             particles: Math.min(8, Math.ceil(cn.count / 3)) });
            }
        });
        // Anclar TODA IP externa que no tenga tráfico directo a un host: se enlaza al
        // router (el tráfico a Internet sale por el gateway). Evita nodos flotantes
        // sueltos que se salían de vista → así se ven TODAS las externas.
        extSet.forEach(ip => {
            if (seen.has(ip) && !connectedDst.has(ip)) {
                links.push({ source: this.routerId, target: ip, kind: "traffic", particles: 2 });
            }
        });

        this.graph.graphData({ nodes, links });
        setTimeout(() => { try { this.graph.zoomToFit(500, 50); } catch (e) {} }, 600);
    }

    // ── Panel de Detalles del Activo (inline, con pestañas) ─────────────────
    _buildPanel() {
        this.selectedHost = null;
        this.activeTab = "general";
        document.querySelectorAll("#hostTabs .host-tab").forEach(btn => {
            btn.addEventListener("click", () => {
                this.activeTab = btn.getAttribute("data-tab");
                document.querySelectorAll("#hostTabs .host-tab").forEach(b => b.classList.toggle("active", b === btn));
                this._renderHostDetail();
            });
        });
    }

    openPanel(node) {
        this.selectedHost = this.hostsById[node.ip] || node;
        const ipEl = document.getElementById("hostDetailIp");
        if (ipEl) ipEl.textContent = this.selectedHost.ip || "";
        this._renderHostDetail();
    }

    closePanel() { /* el panel inline permanece visible; no se cierra */ }

    _renderHostDetail() {
        const body = document.getElementById("hostDetailBody");
        if (!body) return;
        const h = this.selectedHost;
        if (!h) {
            body.innerHTML = '<div style="color:var(--text-secondary);font-family:var(--font-mono);padding:28px 10px;text-align:center">' +
                '⬡ Selecciona un host en el Mapa de Red para ver aquí todos sus datos.</div>';
            return;
        }
        const esc = s => String(s == null ? "" : s).replace(/[<>&]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
        const row = (k, v) => `<div class="host-detail-row"><span class="k">${k}</span>` +
            `<span class="v">${v != null && v !== "" ? esc(v) : "N/D"}</span></div>`;
        const tab = this.activeTab || "general";
        let html = "";

        if (tab === "general") {
            const riskColor = { "CRÍTICO": "#ff0033", "ALTO": "#ff6a00", "MEDIO": "#ffd400", "BAJO": "#39ff14", "INFORMATIVO": "#9aa0a6" }[h.risk] || "#9aa0a6";
            const isLocal = h.ip && /^(10\.|192\.168\.|172\.)/.test(h.ip);
            html = `<div style="margin-bottom:8px"><span style="display:inline-block;padding:2px 10px;border-radius:4px;` +
                `background:${riskColor};color:#000;font-weight:bold;font-family:var(--font-mono)">RIESGO: ${esc(h.risk || "N/D")}</span></div>`
                + row("Dirección IP", h.ip)
                + row("Tipo de dispositivo", h.device_type)
                + row("Estado", h.status)
                + row("Sistema operativo", h.os)
                + row("Dirección MAC", h.mac)
                + row("Fabricante (MAC)", h.vendor)
                + row("Latencia", h.latency)
                + row("Puertos abiertos", h.ports ? h.ports.length : 0)
                + row("Geolocalización", h.isExternal ? "IP externa (Internet)" : (isLocal ? "Red local (N/A)" : "N/D"))
                + (h.isExternal ? row("Dominio (DNS inverso)",
                       (this._hostnames && this._hostnames[h.ip]) ? this._hostnames[h.ip] : "(sin PTR / resolviendo…)") : "");
        } else if (tab === "ports") {
            html = (h.ports && h.ports.length)
                ? '<table class="host-detail-table"><tr><th>Puerto</th><th>Servicio</th><th>Versión</th></tr>'
                    + h.ports.map(p => `<tr><td>${esc(p.port)}/${esc(p.proto)}</td><td>${esc(p.service || "?")}</td>` +
                        `<td style="color:var(--text-secondary)">${esc((p.version || "").slice(0, 50))}</td></tr>`).join("") + '</table>'
                : '<div style="color:var(--text-secondary)">Sin puertos abiertos detectados.</div>';
        } else if (tab === "vulns") {
            const cves = (h.cves && h.cves.length) ? h.cves.map(esc).join(", ") : "Ninguna identificada por CVE";
            const nuclei = (h.nuclei && h.nuclei.length) ? h.nuclei.map(esc).join("<br>") : "Sin hallazgos web (Nuclei)";
            html = `<div style="color:var(--neon-accent);margin-bottom:3px">Vulnerabilidades (CVE)</div><div>${cves}</div>` +
                `<div style="color:var(--neon-accent);margin:10px 0 3px">Hallazgos web (Nuclei)</div><div>${nuclei}</div>`;
        } else if (tab === "trace") {
            html = (h.traceroute && h.traceroute.length)
                ? '<table class="host-detail-table"><tr><th>Salto</th><th>IP</th><th>RTT</th></tr>'
                    + h.traceroute.map(x => `<tr><td>${esc(x.hop)}</td><td>${esc(x.ip)}</td><td>${esc(x.rtt)}</td></tr>`).join("") + '</table>'
                : '<div style="color:var(--text-secondary)">Sin datos de traceroute (en la LAN suele ser 1 salto directo).</div>';
        } else if (tab === "ia") {
            const ai = h.ai ? esc(h.ai.replace(/\*\*(.+?)\*\*/g, "$1")) : "";
            html = ai ? `<div style="white-space:pre-wrap;color:#a8d0b8;font-size:0.78rem">${ai}</div>`
                : '<div style="color:var(--text-secondary)">Sin análisis IA para este activo.</div>';
        }
        body.innerHTML = html;
    }

    // ── Mini-dashboards (métricas reales) ───────────────────────────────────
    _buildStatsBar() {
        if (document.getElementById("graphStatsBar")) return;
        const bar = document.createElement("div");
        bar.id = "graphStatsBar";
        bar.style.cssText = "position:absolute;top:8px;left:8px;display:flex;gap:6px;flex-wrap:wrap;" +
            "z-index:5;pointer-events:none;font-family:monospace;font-size:0.66rem";
        const cell = (id, label) => `<div style="background:rgba(0,0,0,.82);border:1px solid rgba(24,208,255,.3);` +
            `border-radius:4px;padding:3px 7px;color:#7fb0c0">${label}: ` +
            `<span id="${id}" style="color:#18d0ff;font-weight:bold">0</span></div>`;
        bar.innerHTML = cell("stActivos", "Activos") + cell("stExternos", "Externos") +
            cell("stPuertos", "Puertos") + cell("stAlto", "Alto/Crít") + cell("stRiesgo", "Riesgo máx");
        // insertar dentro del contenedor del grafo (posición relativa)
        const wrap = this.container.parentElement;
        if (wrap) wrap.appendChild(bar);
    }

    _updateStats(stats) {
        const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
        if (!stats || !stats.riesgo) return;
        set("stActivos", stats.activos || 0);
        set("stExternos", stats.externos || 0);
        set("stPuertos", stats.puertos_abiertos || 0);
        set("stAlto", (stats.riesgo["ALTO"] || 0) + (stats.riesgo["CRÍTICO"] || 0));
        const order = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"];
        const max = order.find(k => stats.riesgo[k] > 0) || "—";
        const el = document.getElementById("stRiesgo");
        if (el) {
            el.textContent = max;
            el.style.color = { "CRÍTICO": "#ff0033", "ALTO": "#ff6a00", "MEDIO": "#ffd400",
                               "BAJO": "#39ff14", "INFORMATIVO": "#b0b0b0", "—": "#b0b0b0" }[max];
        }
    }

    // ── Interfaz pública (compatibilidad con el dashboard) ──────────────────
    parseLogLine(msg) {
        const m = (msg || "").toLowerCase();
        if (m.includes("fase 1") || m.includes("descubrimiento")) { this.setActivityState("DESCUBRIENDO", "#18d0ff"); this.refresh(); }
        else if (m.includes("fase 2") || m.includes("captura") || m.includes("tshark") || m.includes("tráfico")) { this.setActivityState("CAPTURANDO", "#18d0ff"); this.refresh(); }
        else if (m.includes("fase 4") || m.includes("auditoria") || m.includes("auditoría")) this.setActivityState("ANALIZANDO", "#ffd400");
        else if (m.includes("host") && m.includes("auditado")) this.refresh();
        else if (m.includes("vuln") || m.includes("critical") || m.includes("cve-")) this.setActivityState("⚠ VULN", "#ff0033");
        else if (m.includes("agente finalizado") || (m.includes("vigilancia") && m.includes("completada"))) { this.setActivityState("COMPLETADO", "#39ff14"); this.refresh(); }
        else if (m.includes("escaneo iniciado") || m.includes("lanzando")) this.setActivityState("ESCANEANDO", "#18d0ff");
    }

    setActivityState(text, color) {
        if (this.statusTextEl) { this.statusTextEl.textContent = text; this.statusTextEl.style.color = color; }
        if (this.statusDotEl) { this.statusDotEl.style.background = color; this.statusDotEl.style.boxShadow = `0 0 8px ${color}`; }
    }

    clear() {
        this.currentKey = "";
        this.hostsById = {};
        if (this.graph) this.graph.graphData({ nodes: [], links: [] });
        if (this.hostsCountEl) this.hostsCountEl.textContent = "0";
        this.setActivityState("LIMPIO", "#18d0ff");
    }

    resetView() {
        if (this.graph) { try { this.graph.zoomToFit(600, 60); } catch (e) {} }
    }
}

window.HadesGraph3D = HadesGraph3D;
