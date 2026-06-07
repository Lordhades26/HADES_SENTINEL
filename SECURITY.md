# 🔐 Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Older commits | ❌ — please upgrade |

HADES SENTINEL is a security tool. We take vulnerabilities in HADES itself very seriously.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of:

1. **GitHub Security Advisories** (preferred):
   👉 [Open a private advisory](https://github.com/Lordhades26/HADES_SENTINEL/security/advisories/new)

2. **Email**: `fhormazabalcano [at] gmail [dot] com` — use PGP if possible. Subject line: `[HADES-SECURITY] <short description>`.

### What to include

- Affected file(s) and commit hash
- Step-by-step reproduction
- Impact: what can an attacker do? (RCE, auth bypass, data exfil, etc.)
- Suggested fix (if any)
- Your name / handle for credit (or "anonymous" if preferred)

### What to expect

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | within 72 hours |
| Triage & severity assessment | within 7 days |
| Fix + coordinated disclosure | within 30 days for High/Critical, 90 days for Medium/Low |

---

## Out of scope

The following are **NOT** considered vulnerabilities in HADES SENTINEL itself:

- Vulnerabilities in **downstream tools** HADES orchestrates (Nmap, Nuclei, Tshark, OpenSSL, Ollama) — report those to their respective projects.
- Findings produced **by** HADES on a network you scan — that's the tool working as intended.
- Issues that require physical access to a machine already running HADES under your account.
- Self-XSS, missing security headers on `localhost:8080`, or other dashboard issues that require an attacker to already be on `127.0.0.1`.

---

## Hall of fame

Security researchers who responsibly disclose valid vulnerabilities will be credited here (with their consent).

<!-- Add credits below as: - @handle — short description — YYYY-MM-DD -->
_No disclosures yet._

---

## 🇪🇸 Versión en español

**Por favor NO abras un issue público para reportar vulnerabilidades.**

Repórtalas en privado vía:
1. [GitHub Security Advisory privada](https://github.com/Lordhades26/HADES_SENTINEL/security/advisories/new) (preferido)
2. Email: `fhormazabalcano [at] gmail [dot] com` con asunto `[HADES-SECURITY]`

Responderemos en 72 horas, triaje en 7 días, fix coordinado en 30 días (High/Critical) o 90 días (Medium/Low).
