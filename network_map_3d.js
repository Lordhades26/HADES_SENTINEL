/* ============================================================================
 *  HADES — Mapa de Red 3D (Three.js / WebGL vía 3d-force-graph)
 *  Consume datos REALES del escaneo desde /api/graph y los visualiza como un
 *  grafo 3D estilo SOC con un modelo de tráfico realista:
 *
 *   • Topología estable: los nodos conservan su posición entre actualizaciones
 *     (no se reconstruye el grafo); router fijo al centro, LAN en un anillo,
 *     Internet en una capa exterior. Enlaces dúplex (carril de ida y de vuelta).
 *   • Paquetes enrutados por saltos: host → gateway → Internet y la respuesta de
 *     vuelta, con latencia distinta en LAN y WAN.
 *   • Emisión estocástica (Poisson + ráfagas) proporcional al volumen capturado,
 *     con color y tamaño según el protocolo.
 *   • Nodos vivos: latido al recibir tráfico, aparición con fundido, alerta
 *     pulsante en activos de riesgo alto; barrido de sondeo en el descubrimiento
 *     y sondas sobre el host que se está auditando.
 *   • Cámara en órbita lenta mientras el usuario no interactúa.
 *
 *  Interfaz pública (sin cambios): init(), parseLogLine(msg), clear(),
 *  setActivityState(text,color), resetView()
 * ========================================================================== */

// Estilo de paquete por protocolo (color, tamaño relativo, nombre para la leyenda).
const HADES_PROTO_STYLES = [
    { re: /^(TLS|SSL|HTTPS|QUIC)/i, ports: ["443", "8443", "993", "995", "465"], color: "#18d0ff", size: 2.4, label: "TLS / HTTPS" },
    { re: /^HTTP/i, ports: ["80", "8080", "8000"], color: "#ff9f1a", size: 2.3, label: "HTTP" },
    { re: /^(DNS|MDNS|LLMNR|NBNS)/i, ports: ["53", "5353", "5355", "137"], color: "#ffe14d", size: 1.5, label: "DNS / nombres" },
    { re: /^(SSH|RDP|SMB|TELNET|FTP|VNC)/i, ports: ["22", "3389", "445", "139", "23", "21", "5900"], color: "#ff3355", size: 2.2, label: "Acceso remoto / SMB" },
    { re: /^(ICMP|PING)/i, ports: [], color: "#ffffff", size: 1.4, label: "ICMP / sondeo" },
    { re: /^(DHCP|SSDP|IGMP|ARP|NTP)/i, ports: ["67", "68", "1900", "123"], color: "#b04dff", size: 1.4, label: "Servicios de red" },
];
const HADES_PROTO_DEFAULT = { color: "#ff5cd6", size: 1.9, label: "Otro TCP/UDP" };
const HADES_PROBE = { color: "#ffd400", size: 1.6 };     // sondas del auditor
const HADES_KEEPALIVE = { color: "#8fb8c8", size: 1.4 }; // ARP / keepalive de fondo
// Estela del paquete: [retardo ms, tamaño relativo] de los destellos que lo siguen.
const HADES_TRAIL = [[40, 0.6], [80, 0.32]];

// Velocidades (fracción del enlace por cuadro): la WAN es más lenta que la LAN.
const HADES_SPEED_LAN = 0.03;
const HADES_SPEED_WAN = 0.016;

class HadesGraph3D {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.graph = null;
        this.currentKey = "";          // huella de la topología (para no relayoutear de más)
        this.hostsById = {};           // ip -> datos del host (para el panel SOC)
        this.pollTimer = null;
        this.routerId = "GATEWAY";
        this._nodes = new Map();       // id -> objeto nodo (se reutiliza: conserva posición)
        this._links = new Map();       // "a->b" -> objeto enlace
        this._flows = [];              // conexiones observadas por Tshark
        this._frameMs = 16.7;          // duración media de cuadro (para cronometrar saltos)
        this._inFlight = 0;            // paquetes en vuelo (tope de rendimiento)
        this._lastInteraction = 0;
        this._sweepIdx = 0;
        this._mode = "idle";           // idle | discovery | audit
        this._auditTarget = null;
        this._fitted = false;
        this._texCache = {};
        // Indicadores de estado (overlays existentes en el HTML)
        this.statusDotEl = document.getElementById("graphStatusDot");
        this.statusTextEl = document.getElementById("graphStatusText");
        this.hostsCountEl = document.getElementById("graphHostsCount");
        this.subnetEl = document.getElementById("graphSubnetVal");
    }

    // Color de nodo según semántica SOC (verde/amarillo/rojo/blanco/azul)
    static color(node) {
        if (node.isExternal || node.isCloud) return "#ff00aa"; // magenta = Internet
        if (node.isRouter) return "#18d0ff";                 // azul = infraestructura crítica
        if (node.risk === "ALTO" || node.risk === "CRÍTICO") return "#ff0033"; // rojo = amenaza
        if (node.risk === "MEDIO") return "#ffd400";          // amarillo = sospechoso
        if (node.risk === "NO EVALUADO") return "#b04dff";    // violeta = prueba no concluyente
        if (node.status && node.status.indexOf("caído") === 0) return "#dddddd"; // blanco = inactivo
        if (node.device_type === "Desconocido") return "#dddddd";
        return "#39ff14";                                     // verde = estable/normal
    }

    // Ícono de red según el tipo de dispositivo (estilo topología/Cisco)
    static iconFor(node) {
        if (node.isCloud) return "☁️";
        if (node.isExternal) return "🌍";
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

    static protoStyle(proto, port) {
        const p = String(proto || "");
        const pt = String(port || "");
        for (const s of HADES_PROTO_STYLES) {
            if (s.re.test(p)) return s;
        }
        // Protocolo genérico (TCP/UDP): deducir por puerto conocido.
        for (const s of HADES_PROTO_STYLES) {
            if (s.ports.includes(pt)) return s;
        }
        return HADES_PROTO_DEFAULT;
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

    // Textura de brillo radial (núcleo blanco → color → transparente), cacheada.
    _glowTexture(color) {
        if (this._texCache[color]) return this._texCache[color];
        const S = 64;
        const cv = document.createElement("canvas");
        cv.width = cv.height = S;
        const ctx = cv.getContext("2d");
        const g = ctx.createRadialGradient(S / 2, S / 2, 0, S / 2, S / 2, S / 2);
        g.addColorStop(0, "rgba(255,255,255,1)");
        g.addColorStop(0.22, color);
        g.addColorStop(0.55, color + "55");
        g.addColorStop(1, "rgba(0,0,0,0)");
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, S, S);
        const tex = new THREE.CanvasTexture(cv);
        this._texCache[color] = tex;
        return tex;
    }

    // Objeto 3D de un paquete: destello aditivo del color de su protocolo.
    _packetObject(link) {
        try {
            if (typeof THREE === "undefined") return undefined;
            const st = link.__pkt || HADES_PROTO_DEFAULT;
            const mat = new THREE.SpriteMaterial({
                map: this._glowTexture(st.color), transparent: true,
                depthWrite: false, blending: THREE.AdditiveBlending,
            });
            const sp = new THREE.Sprite(mat);
            const s = st.size * 1.9;
            sp.scale.set(s, s, 1);
            return sp;
        } catch (e) {
            return undefined;
        }
    }

    // Texto del rótulo: [línea principal, línea secundaria opcional].
    _etiqueta(node) {
        if (node.isCloud) return ["INTERNET", ""];
        if (node.isRouter) return ["GATEWAY", node.id !== "GATEWAY" ? node.ip : (node.ip || "")];
        if (node.isExternal) return [node.ip || node.id, ""];
        const tipo = (node.device_type || "").replace(/\s*\(.*\)$/, "").slice(0, 22);
        return [node.ip || node.id, tipo];
    }

    // Nodo = grupo con ícono del dispositivo + halo de actividad.
    // Se cachea en el propio nodo y sólo se rehace si cambia ícono o color.
    _nodeObject(node) {
        try {
            if (typeof THREE === "undefined" || !THREE.Sprite) return undefined;
            const emoji = HadesGraph3D.iconFor(node);
            const color = HadesGraph3D.color(node);
            const etiqueta = this._etiqueta(node);
            const key = emoji + color + etiqueta.join("|");
            if (node.__obj && node.__objKey === key) return node.__obj;

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
            const icon = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
            const base = node.isRouter ? 18 : (node.isCloud ? 17 : (node.isExternal ? 11 : 15));
            icon.scale.set(base, base, 1);

            const halo = new THREE.Sprite(new THREE.SpriteMaterial({
                map: this._glowTexture(color), transparent: true, depthWrite: false,
                blending: THREE.AdditiveBlending, opacity: 0.25,
            }));
            halo.scale.set(base * 2.2, base * 2.2, 1);

            // Rótulo legible bajo el ícono (IP / función), sin tener que pasar el mouse.
            const lc = document.createElement("canvas");
            lc.width = 512; lc.height = 128;
            const lx = lc.getContext("2d");
            lx.textAlign = "center"; lx.textBaseline = "middle";
            lx.font = "bold 44px Consolas, 'Courier New', monospace";
            lx.lineWidth = 8; lx.strokeStyle = "rgba(0,0,0,0.85)";
            lx.strokeText(etiqueta[0], 256, 40); lx.fillStyle = "#e8fff2"; lx.fillText(etiqueta[0], 256, 40);
            if (etiqueta[1]) {
                lx.font = "34px Consolas, 'Courier New', monospace";
                lx.strokeText(etiqueta[1], 256, 96); lx.fillStyle = color; lx.fillText(etiqueta[1], 256, 96);
            }
            const ltex = new THREE.CanvasTexture(lc);
            const label = new THREE.Sprite(new THREE.SpriteMaterial({ map: ltex, transparent: true, depthWrite: false }));
            const lw = node.isExternal ? 34 : 46;
            label.scale.set(lw, lw / 4, 1);
            label.position.set(0, -(base * 0.5 + lw / 8 + 1), 0);

            const group = new THREE.Group();
            group.add(halo);
            group.add(icon);
            group.add(label);
            node.__obj = group;
            node.__objKey = key;
            node.__icon = icon;
            node.__halo = halo;
            node.__base = base;
            if (node.__born == null) node.__born = performance.now();
            return group;
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
                // La etiqueta se pinta como HTML: el PTR lo controla el dueño de la IP
                // remota, así que TODO dato se escapa antes de interpolarlo.
                const e = s => String(s == null ? "" : s).replace(/[<>&"']/g,
                    c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" }[c]));
                const dom = (this._hostnames && this._hostnames[n.ip]) || "";
                return `<div style="font-family:monospace;font-size:12px;background:rgba(0,0,0,.85);` +
                    `padding:4px 8px;border:1px solid #18d0ff;border-radius:4px;color:#e0ffe8">` +
                    `<b>${e(n.ip || n.id)}</b><br>${e(n.device_type)}` +
                    (dom ? `<br>🌐 ${e(dom)}` : "") +
                    (n.risk && !n.isExternal ? `<br>Riesgo: ${e(n.risk)}` : "") + `</div>`;
            })
            .nodeColor(HadesGraph3D.color)
            .nodeVal(n => n.isRouter ? 26 : (n.isExternal ? 4 : (5 + (n.ports ? n.ports.length : 0) * 3)))
            .nodeOpacity(0.92)
            .nodeResolution(14)
            .nodeThreeObject(n => this._nodeObject(n))
            .nodeThreeObjectExtend(false)
            // Enlaces dúplex finos y translúcidos: el protagonismo es de los paquetes.
            // El enlace de retorno (x → gateway) va superpuesto y transparente: sólo
            // transporta los paquetes de respuesta por la misma línea.
            .linkColor(l => l.__reverse ? "rgba(0,0,0,0)" : (l.kind === "wan" ? "rgba(255,92,214,0.75)" : "rgba(24,208,255,0.9)"))
            .linkWidth(l => l.__reverse ? 0 : (l.kind === "wan" ? 1.1 : 1.8))
            .linkOpacity(0.8)
            .linkCurvature(0)                       // una sola línea recta por conexión
            .linkDirectionalParticles(0)            // sin partículas fijas: todo es emitido
            .linkDirectionalParticleSpeed(l => l.kind === "wan" ? HADES_SPEED_WAN : HADES_SPEED_LAN)
            .linkDirectionalParticleThreeObject(l => this._packetObject(l))
            .d3AlphaDecay(0.03)
            .d3VelocityDecay(0.38)
            .warmupTicks(30)
            .cooldownTime(6000)
            .onNodeClick(n => this.openPanel(n))
            // Diagrama ordenado: los nodos no se arrastran (cada uno tiene su lugar).
            .enableNodeDrag(false)
            .onBackgroundClick(() => this.closePanel());
        } catch (err) {
            this.container.innerHTML = '<div style="padding:16px;color:#ff6a00;font-family:monospace;font-size:12px">' +
                '[Mapa 3D] Error al inicializar ForceGraph3D: ' + (err && err.message ? err.message : err) + '</div>';
            console.error("[HadesGraph3D] init error:", err);
            return;
        }

        this._setupForces();

        // Tamaño inicial y resize
        this._resize();
        window.addEventListener("resize", () => this._resize());

        // La órbita automática se pausa mientras el usuario manipula el mapa.
        const touch = () => { this._lastInteraction = performance.now(); };
        ["pointerdown", "wheel", "touchstart"].forEach(ev =>
            this.container.addEventListener(ev, touch, { passive: true }));

        // Botones existentes
        const rb = document.getElementById("btnResetGraph");
        const cb = document.getElementById("btnClearGraph");
        if (rb) rb.addEventListener("click", () => this.resetView());
        if (cb) cb.addEventListener("click", () => this.clear());

        // Crear panel lateral SOC, barra de mini-dashboards y leyenda de protocolos
        this._buildPanel();
        this._buildStatsBar();
        this._buildLegend();

        // Bucles de animación: cuadros (pulsos, cámara) y emisor de paquetes.
        this._lastFrame = performance.now();
        this._lastInteraction = performance.now();
        const frame = (t) => { this._onFrame(t); this._raf = requestAnimationFrame(frame); };
        this._raf = requestAnimationFrame(frame);
        this._trafficTimer = setInterval(() => this._trafficTick(0.1), 100);

        // Primera carga + polling de datos reales
        this.refresh();
        this.pollTimer = setInterval(() => this.refresh(), 4000);
        this.setActivityState("EN ESPERA", "#18d0ff");
    }

    // Sin física: el diagrama por capas usa posiciones fijas (ver _layout).
    // Una simulación de fuerzas dispersaba los nodos en forma de «erizo».
    _setupForces() {
        try {
            ["charge", "center"].forEach(f => this.graph.d3Force(f, null));
            // La fuerza de enlaces se conserva con intensidad 0: es la que resuelve
            // los ids origen/destino a nodos (sin ella no se dibujan líneas ni paquetes).
            const link = this.graph.d3Force("link");
            if (link && link.strength) link.strength(0);
        } catch (e) {
            console.warn("[HadesGraph3D] no se pudieron desactivar las fuerzas:", e);
        }
    }

    _resize() {
        if (this.graph && this.container) {
            this.graph.width(this.container.clientWidth).height(this.container.clientHeight);
        }
    }

    // ── Carga de datos reales desde /api/graph ──────────────────────────────
    async refresh() {
        try {
            // GET de sólo lectura: el backend lo autoriza por mismo origen.
            const res = await fetch(`/api/graph`);
            if (!res.ok) return;
            const data = await res.json();
            this._apply(data);
        } catch (e) { /* el polling reintenta */ }
    }

    // Obtiene (o crea) el nodo con id dado conservando su posición previa.
    _upsertNode(id, props, anchorId) {
        let n = this._nodes.get(id);
        if (!n) {
            n = { id };
            // Nace junto a su ancla (gateway u origen) para que entre «desde» la red.
            const a = this._nodes.get(anchorId);
            const j = () => (Math.random() - 0.5) * 12;
            if (a && a.x != null) { n.x = a.x + j(); n.y = a.y + j(); n.z = a.z + j(); }
            n.__born = performance.now();
            this._nodes.set(id, n);
        }
        // Actualiza datos sin tocar x/y/z/vx/vy/vz ni la caché del objeto 3D.
        Object.keys(n).forEach(k => {
            if (!k.startsWith("__") && !["id", "x", "y", "z", "vx", "vy", "vz", "fx", "fy", "fz", "index"].includes(k)
                && !(k in props)) delete n[k];
        });
        Object.assign(n, props);
        return n;
    }

    _linkKey(a, b) { return a + "->" + b; }

    _upsertLink(a, b, kind, reverse) {
        const key = this._linkKey(a, b);
        let l = this._links.get(key);
        if (!l) {
            l = { source: a, target: b, kind };
            this._links.set(key, l);
        }
        l.kind = kind;
        // Carril de retorno: invisible, comparte la línea de ida.
        l.__reverse = !!reverse;
        return l;
    }

    _apply(data) {
        if (!data || data.status !== "ok") return;
        const hosts = data.hosts || [];
        const externals = data.externals || [];
        const connections = data.connections || [];
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

        // Los flujos se actualizan siempre (no requieren relayout).
        this._flows = connections.map(cn => Object.assign({}, cn, {
            style: HadesGraph3D.protoStyle(cn.proto, cn.port),
        }));

        // Huella de la topología: sólo se re-entrega el grafo si cambian nodos/enlaces.
        const key = hosts.map(h => h.ip + ":" + h.risk + ":" + (h.ports ? h.ports.length : 0)).sort().join("|")
            + "#E" + externals.slice().sort().join(",")
            + "#C" + connections.map(c => c.src + ">" + c.dst).sort().join(",");
        if (key === this.currentKey) return;
        this.currentKey = key;

        const wantNodes = new Set();
        const wantLinks = new Set();

        // Router central (fijo en el origen)
        let routerId = data.router_ip && hosts.some(h => h.ip === data.router_ip) ? data.router_ip : "GATEWAY";
        if (routerId === "GATEWAY") {
            this._upsertNode("GATEWAY", { ip: data.subnet || "Gateway", isRouter: true,
                device_type: "Router / Gateway", risk: "INFORMATIVO", ports: [] });
            wantNodes.add("GATEWAY");
        }
        this.routerId = routerId;

        // Enlace visible (a → b) + carril de retorno transparente (b → a) por la misma línea.
        const conectar = (a, b, kind) => {
            wantLinks.add(this._linkKey(a, b));
            wantLinks.add(this._linkKey(b, a));
            this._upsertLink(a, b, kind, false);
            this._upsertLink(b, a, kind, true);
        };

        // Capa inferior: hosts de la LAN, colgando del gateway.
        const lan = [];
        hosts.forEach(h => {
            const isR = h.ip === routerId;
            this._upsertNode(h.ip, Object.assign({ isRouter: isR }, h), routerId);
            wantNodes.add(h.ip);
            if (!isR) { lan.push(h.ip); conectar(routerId, h.ip, "lan"); }
        });

        // Capa superior: Internet. Una sola troncal gateway → nube, y las IP
        // externas cuelgan de la nube (no del gateway): nada de «erizo».
        const extSet = new Set(externals);
        connections.forEach(cn => {
            if (!this.hostsById[cn.dst]) extSet.add(cn.dst);
            if (!this.hostsById[cn.src] && cn.src !== routerId) extSet.add(cn.src);
        });
        const ext = [...extSet].filter(ip => !wantNodes.has(ip));
        this._cloudId = "INTERNET";
        if (ext.length) {
            this._upsertNode(this._cloudId, { ip: "Internet", isCloud: true, device_type: "Internet (nube)",
                risk: "INFORMATIVO", ports: [] }, routerId);
            wantNodes.add(this._cloudId);
            conectar(routerId, this._cloudId, "wan");
            ext.forEach(ip => {
                this._upsertNode(ip, { ip, isExternal: true, device_type: "Internet (externo)",
                    risk: "INFORMATIVO", ports: [] }, this._cloudId);
                wantNodes.add(ip);
                conectar(this._cloudId, ip, "wan");
            });
        }

        // Quitar lo que ya no existe
        [...this._nodes.keys()].forEach(id => { if (!wantNodes.has(id)) this._nodes.delete(id); });
        [...this._links.keys()].forEach(k => { if (!wantLinks.has(k)) this._links.delete(k); });

        this._layout(routerId, lan, ext);

        const nodes = [...this._nodes.values()];
        // Los enlaces se entregan con ids: la librería los resuelve a los mismos objetos nodo.
        const links = [...this._links.values()].map(l => {
            l.source = typeof l.source === "object" ? l.source.id : l.source;
            l.target = typeof l.target === "object" ? l.target.id : l.target;
            return l;
        });
        this.graph.graphData({ nodes, links });

        // Encuadre sólo la primera vez o si la red creció mucho (no marea al usuario).
        const count = nodes.length;
        if (!this._fitted || count > (this._fittedCount || 0) * 1.5) {
            this._fitted = true;
            this._fittedCount = count;
            setTimeout(() => this._encuadrar(900), 1600);
        }
    }

    // Diagrama por capas con posiciones fijas (lectura inmediata para el operador):
    //   Internet (filas arriba, ordenadas por volumen de tráfico)
    //   └ nube INTERNET ─ gateway (centro) ─ hosts LAN (filas abajo, por IP)
    _layout(routerId, lan, ext) {
        const fijar = (id, x, y) => {
            const n = this._nodes.get(id);
            if (!n) return;
            n.fx = x; n.fy = y; n.fz = 0;
            if (n.x == null) { n.x = x; n.y = y; n.z = 0; }
        };
        const filas = (ids, porFila, dx, y0, dy) => {
            ids.forEach((id, i) => {
                const fila = Math.floor(i / porFila);
                const enFila = Math.min(porFila, ids.length - fila * porFila);
                const col = i % porFila;
                fijar(id, (col - (enFila - 1) / 2) * dx, y0 + fila * dy);
            });
        };
        const ipNum = ip => String(ip).split(".").reduce((a, b) => a * 256 + (parseInt(b, 10) || 0), 0);
        const volumen = {};
        this._flows.forEach(f => { volumen[f.dst] = (volumen[f.dst] || 0) + (f.count || 0); });

        fijar(routerId, 0, 0);
        fijar(this._cloudId, 0, 62);
        filas(ext.slice().sort((a, b) => (volumen[b] || 0) - (volumen[a] || 0) || ipNum(a) - ipNum(b)),
              7, 42, 122, 40);
        filas(lan.slice().sort((a, b) => ipNum(a) - ipNum(b)), 6, 58, -74, -62);
    }

    // ── Motor de tráfico ────────────────────────────────────────────────────
    _hopMs(link) {
        const speed = link.kind === "wan" ? HADES_SPEED_WAN : HADES_SPEED_LAN;
        return (1 / speed) * this._frameMs;
    }

    // Emite un paquete que recorre `path` salto a salto (cada salto es un enlace).
    _send(path, style, onArrive) {
        if (!this.graph || path.length < 2 || this._inFlight > 260) return;
        const linkAt = i => this._links.get(this._linkKey(path[i], path[i + 1]));
        if (!linkAt(0)) return;
        this._inFlight++;
        const hop = (i) => {
            const link = linkAt(i);
            if (!link || !this._links.has(this._linkKey(path[i], path[i + 1]))) { this._inFlight--; return; }
            link.__pkt = style;
            try { this.graph.emitParticle(link); } catch (e) { this._inFlight--; return; }
            // Estela tipo cometa: dos destellos menores detrás del paquete.
            HADES_TRAIL.forEach(([ms, k]) => setTimeout(() => {
                if (!this._links.has(this._linkKey(path[i], path[i + 1]))) return;
                link.__pkt = Object.assign({}, style, { size: style.size * k });
                try { this.graph.emitParticle(link); } catch (e) { /* enlace ya retirado */ }
            }, ms));
            const dst = this._nodes.get(path[i + 1]);
            setTimeout(() => {
                if (dst) this._pulse(dst, i + 1 === path.length - 1 ? 1 : 0.45);
                if (i + 2 < path.length) hop(i + 1);
                else { this._inFlight--; if (onArrive) onArrive(); }
            }, this._hopMs(link));
        };
        hop(0);
    }

    // Ruta realista: LAN ↔ gateway ↔ nube ↔ IP externa.
    _route(src, dst) {
        const R = this.routerId, C = this._cloudId;
        const esExt = id => { const n = this._nodes.get(id); return !!(n && n.isExternal); };
        if (esExt(src) && esExt(dst)) return [src, C, dst];
        const subir = id => id === R ? [R] : (id === C ? [C, R] : (esExt(id) ? [id, C, R] : [id, R]));
        const ida = subir(src);
        const vuelta = subir(dst).slice().reverse();
        return ida.concat(vuelta.slice(1));
    }

    // Petición y respuesta (la respuesta llega tras la latencia del servidor).
    _exchange(src, dst, style, burst = 1) {
        const path = this._route(src, dst);
        const external = this._nodes.get(dst) && this._nodes.get(dst).isExternal;
        const think = external ? 220 + Math.random() * 380 : 40 + Math.random() * 120;
        for (let b = 0; b < burst; b++) {
            setTimeout(() => {
                this._send(path, style, () => {
                    // Las respuestas de TLS/HTTP suelen ser más pesadas (descarga).
                    const resp = style.size >= 2.2 ? Object.assign({}, style, { size: style.size * 1.25 }) : style;
                    setTimeout(() => this._send(path.slice().reverse(), resp), think);
                });
            }, b * (55 + Math.random() * 40));
        }
    }

    _trafficTick(dt) {
        if (!this.graph || document.hidden) return;

        // 1) Flujos reales capturados por Tshark: proceso de Poisson por flujo.
        for (const f of this._flows) {
            if (!this._nodes.has(f.src) || !this._nodes.has(f.dst)) continue;
            const lambda = Math.min(3, 0.35 + Math.log2(1 + (f.count || 1)) * 0.45); // paquetes/s
            if (Math.random() < 1 - Math.exp(-lambda * dt)) {
                const heavy = f.style.size >= 2.2;
                const burst = heavy && Math.random() < 0.35 ? 2 + Math.floor(Math.random() * 3) : 1;
                this._exchange(f.src, f.dst, f.style, burst);
            }
        }

        // 2) Ruido de fondo: ARP/keepalive con hosts LAN y sesiones HTTPS leves
        //    hacia IPs externas que no tienen un flujo propio capturado.
        const conFlujo = new Set(this._flows.map(f => f.dst));
        const origenes = [...new Set(this._flows.map(f => f.src))].filter(id => this._nodes.has(id));
        for (const n of this._nodes.values()) {
            if (n.isRouter) continue;
            if (!n.isExternal) {
                if (Math.random() < 0.012) this._exchange(this.routerId, n.id, HADES_KEEPALIVE);
            } else if (!conFlujo.has(n.id) && Math.random() < 0.02) {
                const src = origenes.length ? origenes[Math.floor(Math.random() * origenes.length)] : this.routerId;
                this._exchange(src, n.id, HADES_PROTO_STYLES[0]);
            }
        }

        // 3) Actividad del escáner.
        const lan = [...this._nodes.values()].filter(n => !n.isRouter && !n.isExternal);
        if (this._mode === "discovery" && lan.length) {
            // Barrido de sondeo: un eco ICMP por host en orden, como un ping sweep.
            const n = lan[this._sweepIdx++ % lan.length];
            const st = HadesGraph3D.protoStyle("ICMP");
            this._send([this.routerId, n.id], st, () => {
                if (Math.random() < 0.85) setTimeout(() => this._send([n.id, this.routerId], st), 60);
            });
        } else if (this._mode === "audit" && this._auditTarget && this._nodes.has(this._auditTarget)) {
            // Sondas del auditor sobre el host objetivo (SYN → SYN/ACK|RST).
            if (Math.random() < 0.55) this._exchange(this.routerId, this._auditTarget, HADES_PROBE,
                1 + Math.floor(Math.random() * 3));
        }
    }

    _pulse(node, amount) {
        node.__pulse = Math.min(1.4, (node.__pulse || 0) + amount);
    }

    // ── Cuadro a cuadro: pulsos, apariciones, alertas y cámara ──────────────
    _onFrame(t) {
        const dt = t - this._lastFrame;
        this._lastFrame = t;
        if (dt > 0 && dt < 250) this._frameMs = this._frameMs * 0.95 + dt * 0.05;

        for (const n of this._nodes.values()) {
            if (!n.__icon) continue;
            const age = Math.min(1, (t - (n.__born || 0)) / 900);       // aparición 0→1
            const ease = 1 - Math.pow(1 - age, 3);
            n.__pulse = (n.__pulse || 0) * Math.pow(0.9, dt / 16.7);
            const alert = n.risk === "CRÍTICO" || n.risk === "ALTO";
            const breathe = n.isRouter ? 0.12 * (1 + Math.sin(t / 900)) :
                (alert ? 0.35 * (1 + Math.sin(t / 260)) : 0);
            const isTarget = this._mode === "audit" && n.id === this._auditTarget;
            const s = n.__base * ease * (1 + 0.16 * n.__pulse + (isTarget ? 0.12 * (1 + Math.sin(t / 140)) : 0));
            n.__icon.scale.set(s, s, 1);
            const hs = n.__base * ease * (2.0 + 1.1 * n.__pulse + breathe + (isTarget ? 0.8 : 0));
            n.__halo.scale.set(hs, hs, 1);
            n.__halo.material.opacity = Math.min(0.95, 0.18 + 0.55 * n.__pulse + breathe * 0.6 + (isTarget ? 0.35 : 0));
            n.__icon.material.opacity = ease;
        }

        // Sin órbita automática: vista frontal estable para leer el diagrama.
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
        this._pulse(node, 1);
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
            const riskColor = { "CRÍTICO": "#ff0033", "ALTO": "#ff6a00", "MEDIO": "#ffd400", "BAJO": "#39ff14", "NO EVALUADO": "#b04dff", "INFORMATIVO": "#9aa0a6" }[h.risk] || "#9aa0a6";
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

    // Leyenda: qué significa cada color de paquete.
    _buildLegend() {
        if (document.getElementById("graphProtoLegend")) return;
        const box = document.createElement("div");
        box.id = "graphProtoLegend";
        box.style.cssText = "position:absolute;bottom:8px;right:8px;z-index:5;pointer-events:none;" +
            "background:rgba(0,0,0,.72);border:1px solid rgba(24,208,255,.25);border-radius:4px;" +
            "padding:4px 8px;font-family:monospace;font-size:0.62rem;color:#9fc3cf;line-height:1.5";
        const items = HADES_PROTO_STYLES.concat([HADES_PROTO_DEFAULT,
            Object.assign({ label: "Sondas del auditor" }, HADES_PROBE)]);
        box.innerHTML = items.map(s =>
            `<div><span style="display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;` +
            `background:${s.color};box-shadow:0 0 6px ${s.color}"></span>${s.label}</div>`).join("");
        const wrap = this.container.parentElement;
        if (wrap) wrap.appendChild(box);
    }

    _updateStats(stats) {
        const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
        if (!stats || !stats.riesgo) return;
        set("stActivos", stats.activos || 0);
        set("stExternos", stats.externos || 0);
        set("stPuertos", stats.puertos_abiertos || 0);
        set("stAlto", (stats.riesgo["ALTO"] || 0) + (stats.riesgo["CRÍTICO"] || 0));
        const order = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "NO EVALUADO", "INFORMATIVO"];
        const max = order.find(k => stats.riesgo[k] > 0) || "—";
        const el = document.getElementById("stRiesgo");
        if (el) {
            el.textContent = max;
            el.style.color = { "CRÍTICO": "#ff0033", "ALTO": "#ff6a00", "MEDIO": "#ffd400",
                               "BAJO": "#39ff14", "NO EVALUADO": "#b04dff", "INFORMATIVO": "#b0b0b0", "—": "#b0b0b0" }[max];
        }
    }

    // ── Interfaz pública (compatibilidad con el dashboard) ──────────────────
    parseLogLine(msg) {
        const m = (msg || "").toLowerCase();
        const auditado = (msg || "").match(/auditor[ií]a completa\s*(?:→|->)\s*([0-9a-f.:]+)/i);
        if (auditado) {
            this._mode = "audit";
            this._auditTarget = auditado[1];
            this.setActivityState("ANALIZANDO " + auditado[1], "#ffd400");
            return;
        }
        if (m.includes("fase 1") || m.includes("descubrimiento")) { this._mode = "discovery"; this.setActivityState("DESCUBRIENDO", "#18d0ff"); this.refresh(); }
        else if (m.includes("fase 2") || m.includes("captura") || m.includes("tshark") || m.includes("tráfico")) { this._mode = "idle"; this.setActivityState("CAPTURANDO", "#18d0ff"); this.refresh(); }
        else if (m.includes("fase 4") || m.includes("auditoria") || m.includes("auditoría")) this.setActivityState("ANALIZANDO", "#ffd400");
        else if (m.includes("host") && m.includes("auditado")) { this._auditTarget = null; this.refresh(); }
        else if (m.includes("vuln") || m.includes("critical") || m.includes("cve-")) this.setActivityState("⚠ VULN", "#ff0033");
        else if (m.includes("agente finalizado") || (m.includes("vigilancia") && m.includes("completada"))) {
            this._mode = "idle"; this._auditTarget = null;
            this.setActivityState("COMPLETADO", "#39ff14"); this.refresh();
        }
        else if (m.includes("escaneo iniciado") || m.includes("lanzando")) this.setActivityState("ESCANEANDO", "#18d0ff");
    }

    setActivityState(text, color) {
        if (this.statusTextEl) { this.statusTextEl.textContent = text; this.statusTextEl.style.color = color; }
        if (this.statusDotEl) { this.statusDotEl.style.background = color; this.statusDotEl.style.boxShadow = `0 0 8px ${color}`; }
    }

    clear() {
        this.currentKey = "";
        this.hostsById = {};
        this._nodes.clear();
        this._links.clear();
        this._flows = [];
        this._mode = "idle";
        this._auditTarget = null;
        this._fitted = false;
        if (this.graph) this.graph.graphData({ nodes: [], links: [] });
        if (this.hostsCountEl) this.hostsCountEl.textContent = "0";
        this.setActivityState("LIMPIO", "#18d0ff");
    }

    // Vista FRONTAL centrada en el diagrama, a la distancia justa para que
    // quepan todas las capas (también deshace cualquier rotación del operador).
    _encuadrar(ms) {
        if (!this.graph || !this._nodes.size) return;
        try {
            const ns = [...this._nodes.values()];
            const xs = ns.map(n => n.fx != null ? n.fx : (n.x || 0));
            const ys = ns.map(n => n.fy != null ? n.fy : (n.y || 0));
            const margen = 22;   // íconos + rótulos
            const minX = Math.min(...xs) - margen, maxX = Math.max(...xs) + margen;
            const minY = Math.min(...ys) - margen - 14, maxY = Math.max(...ys) + margen + 18;  // arriba: barra de métricas
            const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
            const cam = this.graph.camera();
            const aspect = (this.container.clientWidth || 1) / (this.container.clientHeight || 1);
            const tanMedio = Math.tan((cam.fov * Math.PI / 180) / 2);
            const dist = Math.max((maxY - minY) / 2, (maxX - minX) / 2 / aspect) / tanMedio;
            this.graph.cameraPosition({ x: cx, y: cy, z: dist }, { x: cx, y: cy, z: 0 }, ms);
        } catch (e) { /* motor aún no listo */ }
    }

    resetView() {
        this._lastInteraction = performance.now();
        this._encuadrar(600);
    }
}

window.HadesGraph3D = HadesGraph3D;
