# Screenshots used in the main README

The main `README.md` renders these 6 PNGs in a **3×2 grid** with two narrative rows:

**🖥️ Live experience (row 1)**

| Filename | What it shows |
|----------|---------------|
| `01_dashboard_live.png` | Tactical SOC dashboard — live network map + console mid-scan |
| `02_dashboard_resources.png` | Control panel — 5-phase scan flow, CPU/GPU/RAM monitors, Ollama LLM |
| `03_traffic_capture.png` | Live Tshark traffic capture output |

**📄 Deliverables (row 2)**

| Filename | What it shows |
|----------|---------------|
| `04_severity_table.png` | Findings classified by severity (Critical / High / Medium / Low) with business impact |
| `05_risk_matrix.png` | Color-coded risk matrix (probability × impact) |
| `06_iso27001_mapping.png` | ISO 27001 Annex A control mapping table |

## Quality checklist before committing

- [ ] **Redact all real network data** — IPs, MACs, hostnames, banners. Use a blur/black-box tool. **This is non-negotiable for a public repo.**
- [ ] PNG format (not JPG).
- [ ] At least 1280px wide.
- [ ] Under 500 KB each (use TinyPNG or similar to compress without losing quality).
- [ ] No personal info in the taskbar / window title.

Once the 3 files are here, the README will render correctly on GitHub.
