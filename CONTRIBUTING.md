# 🤝 Contributing to HADES SENTINEL

First — **thank you**. Every star, every issue, every PR pushes this project forward.

This guide is bilingual: 🇬🇧 English first, 🇪🇸 [Español](#-español) below.

---

## TL;DR

1. Fork → branch → commit → PR.
2. Be specific in issues. Be small in PRs.
3. By contributing, you agree your code is **dual-licensed MIT OR Apache-2.0**.
4. Don't commit real network data, credentials, or anything from `informes/`.

---

## Ways to contribute

| Type | How |
|------|-----|
| 🐛 **Report a bug** | [Open an issue](https://github.com/Lordhades26/HADES_SENTINEL/issues/new?template=bug_report.yml) with full repro steps + commit hash. |
| ✨ **Propose a feature** | [Open an issue](https://github.com/Lordhades26/HADES_SENTINEL/issues/new?template=feature_request.yml) — describe the **pain** before the solution. |
| 🔐 **Report a vulnerability** | See [SECURITY.md](./SECURITY.md) — **never** in a public issue. |
| 💬 **Ask a question** | Use [Discussions](https://github.com/Lordhades26/HADES_SENTINEL/discussions), not issues. |
| 📝 **Improve docs** | PRs welcome — fix typos, clarify steps, translate to a new language. |
| 🧩 **Add a feature / fix a bug** | See workflow below. |
| ⭐ **Star the repo** | Genuinely the highest-leverage thing if you find HADES useful. |

---

## Development workflow

### 1. Fork and clone

```bash
gh repo fork Lordhades26/HADES_SENTINEL --clone
cd HADES_SENTINEL
```

### 2. Branch

Use a descriptive, kebab-case branch name prefixed with the type:

```bash
git checkout -b feat/streaming-dashboard-results
git checkout -b fix/nmap-timeout-on-class-b
git checkout -b docs/spanish-quickstart
```

### 3. Install dependencies

```bash
pip install python-docx psutil
```

External binaries (must be on PATH or at the default Windows locations):

| Tool | Install |
|------|---------|
| Nmap | `winget install Insecure.Nmap` |
| Wireshark/Tshark | `winget install WiresharkFoundation.Wireshark` |
| OpenSSL | `winget install ShiningLight.OpenSSL.Light` |
| Nuclei | Download from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) → `%USERPROFILE%\Documents\HADES\nuclei\nuclei.exe` |
| Ollama | `winget install Ollama.Ollama` |

### 4. Run

```bash
LANZAR_DASHBOARD.bat
```

Make your changes. **Test on a network you own** before opening a PR.

### 5. Commit

We use **[Conventional Commits](https://www.conventionalcommits.org/)**. Format:

```
<type>(<scope>): <short summary in imperative mood>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `security`.

**Scopes** (common): `dashboard`, `server`, `engine`, `pipeline`, `report`, `auth`, `ollama`, `docs`.

**Good examples** (from this repo's history):

```
feat(auth): autenticacion biometrica WebAuthn (Windows Hello) + cierre limpio total
fix(dashboard): polling /api/graph cada 5s para refrescar el mapa en vivo
fix(ollama): deteccion robusta de host + metricas IA reales del agente
```

### 6. Pull request

- Keep PRs **small and focused**. One concern per PR.
- Fill out the [PR template](.github/PULL_REQUEST_TEMPLATE.md) completely.
- Link the issue you're closing: `Closes #42`.
- Include screenshots for any UI change (with **sensitive network data redacted**).
- Be patient — reviews happen on evenings & weekends.

---

## Code style

This is a Windows-first Python 3.10+ project. Match the surrounding style — we're not a "formatter-enforced" project (yet), but:

- **Python**: PEP 8 with 100-char line limit. No tabs.
- **HTML/JS** (`agente HADES.html`, `network_map_3d.js`): 2-space indent, no trailing whitespace.
- **Batch files**: ALL CAPS for the well-known commands (`ECHO`, `SET`, `IF EXIST`).
- **No comments that explain WHAT** — only WHY (when non-obvious).
- **Strings in user-facing output**: keep them in Spanish OR English consistently with the surrounding context.

---

## What we WON'T merge

- ❌ Cloud-dependent features. HADES is **100% local**. This is a hard architectural commitment.
- ❌ Telemetry, analytics, or "phone-home" of any kind.
- ❌ Code that requires external API keys to function.
- ❌ Code with bundled binaries (we install tools via winget / standard installers).
- ❌ Sweeping reformatting / "fix all the things" PRs. Open an issue first.
- ❌ PRs from accounts with no human history (we will check).

---

## License of contributions

By submitting a contribution you agree it is dual-licensed under **MIT OR Apache-2.0** (see [LICENSE](./LICENSE)). This matches the project's dual-license and means contributors retain the same rights as the original code.

---

## 🇪🇸 Español

### Primero: gracias

Cada estrella, issue y PR empuja el proyecto. Esta guía es **bilingüe**.

### Resumen rápido

1. Fork → branch → commit → PR.
2. Sé específico en issues. Sé pequeño en PRs.
3. Al contribuir, aceptas que tu código sea **dual-licenciado MIT OR Apache-2.0**.
4. No subas datos reales de red, credenciales o nada de la carpeta `informes/`.

### Formas de contribuir

| Tipo | Cómo |
|------|------|
| 🐛 **Reportar un bug** | [Abre un issue](https://github.com/Lordhades26/HADES_SENTINEL/issues/new?template=bug_report.yml) con pasos completos para reproducir + hash del commit. |
| ✨ **Proponer una feature** | [Abre un issue](https://github.com/Lordhades26/HADES_SENTINEL/issues/new?template=feature_request.yml) — describe el **dolor**, no solo la solución. |
| 🔐 **Reportar una vulnerabilidad** | Ver [SECURITY.md](./SECURITY.md) — **nunca** en un issue público. |
| 💬 **Hacer una pregunta** | Usa [Discussions](https://github.com/Lordhades26/HADES_SENTINEL/discussions), no issues. |
| 📝 **Mejorar la documentación** | PRs bienvenidos — corregir typos, clarificar pasos, traducir. |
| ⭐ **Dale una estrella al repo** | Honestamente, es lo más útil que puedes hacer si HADES te sirve. |

### Estilo de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/) — mira los ejemplos de `git log` para ver el estilo exacto del proyecto.

### Qué NO mergearemos

- ❌ Features que dependan de la nube. HADES es **100% local**. Compromiso arquitectónico no negociable.
- ❌ Telemetría o "phone-home" de cualquier tipo.
- ❌ Código que requiera claves de API externas.
- ❌ Binarios incluidos en el repo.
- ❌ PRs gigantes de "limpieza general". Abre un issue primero.

---

¿Dudas? Abre una [Discussion](https://github.com/Lordhades26/HADES_SENTINEL/discussions) — preferimos discutir antes de que escribas código que luego no podamos mergear.
