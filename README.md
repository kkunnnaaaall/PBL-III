# 🛡️ AI-Powered Brute-Force Incident Response Platform

A lightweight, fully local tool that turns raw SSH authentication logs into a complete **incident report**: it detects brute-force attacks, scores their severity, flags probable compromise, and generates an AI-written playbook with ready-to-review containment commands and Wazuh rules.

> **Detection and severity are deterministic Python. The local LLM (Llama 3) only writes the narrative.** The model never counts, scores, or writes commands, so it can't miscount or invent an IP address.

---

## ✨ Features

| Capability | How it works |
|---|---|
| **Brute-force detection from login logs** | Regex-parses `sshd` events (syslog and ISO timestamps, IPv4/IPv6), groups them by source IP, and computes failures, targeted accounts, time span and rate per minute. |
| **Attack classification** | Password Guessing, Password Spraying, Dictionary / Bot Attack, or Isolated Failure. |
| **Severity analysis** | Transparent 0–100 risk score mapped to Critical / High / Medium / Low / Informational, with a per-IP score breakdown. |
| **Compromise detection** | A successful login after failed attempts from the same IP is forced to **Critical** and triggers account-lockdown steps. |
| **AI playbook generation** | Llama 3 (via Ollama) writes the executive summary, attacker assessment and recommendations. Your custom guidance shapes the wording. |
| **Automatic incident report** | Incident ID, timeline, IOCs, compromise assessment, triage checklist, containment commands, Wazuh rules and remediation. Download as Markdown or JSON. |
| **Interactive dashboard** | Streamlit UI with KPI cards, charts, per-attacker drill-down and a timeline. |
| **Graceful degradation** | If Ollama is down you get a deterministic fallback narrative. If the API is down the GUI runs the engine locally. |

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  Streamlit GUI (app.py)                                        │
│  upload · settings · KPIs · charts · tabs · downloads          │
└──────────────┬─────────────────────────────────────────────────┘
               │ POST /analyze-logs                ▲ JSON result
               ▼                                   │
┌────────────────────────────────────────────────────────────────┐
│  FastAPI (main.py)  ·  validation · /health                    │
└──────────────┬─────────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────────┐
│  Analysis engine (engine.py)  ·  deterministic                 │
│  Parse → Group by IP → Classify → Score severity               │
│        → Compromise check → Commands / Wazuh rules → Report    │
└──────────────┬─────────────────────────────────────────────────┘
               │ computed summary only (no raw logs)   ▲ narrative
               ▼                                       │
┌────────────────────────────────────────────────────────────────┐
│  LLM helper (llm.py)  →  Ollama (local)  →  Llama 3            │
└────────────────────────────────────────────────────────────────┘
```

If the FastAPI backend is offline, `app.py` calls `engine.run_analysis()` directly.

## 🧰 Tech Stack

- **Language:** Python 3
- **Frontend:** Streamlit, Altair, pandas
- **Backend:** FastAPI, Uvicorn
- **Detection engine:** Python standard library (`re`, `ipaddress`, `collections`, `dataclasses`)
- **AI:** Llama 3 running locally through [Ollama](https://ollama.com)
- **SIEM output:** Wazuh rule and active-response XML (generated text, not a live integration)

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/download) (optional, needed only for the AI narrative)

### Install
```bash
git clone <your-repo-url>
cd <your-repo-folder>
pip install -r requirements.txt
ollama pull llama3
```

### Run
Open two terminals in the project folder:

```bash
# Terminal 1 - API backend
uvicorn main:app --reload

# Terminal 2 - dashboard
streamlit run app.py
```

Then open the URL Streamlit prints (usually http://localhost:8501), click **Load sample log**, and then **Analyze & generate incident report**.

> The dashboard also works without the backend or Ollama. It falls back to the local engine and a deterministic summary.

### Configuration
| Environment variable | Default | Purpose |
|---|---|---|
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama server address |
| `OLLAMA_MODEL` | `llama3` | Model used for the narrative |

Detection settings (failure threshold, privileged accounts, firewall type, AI on/off, custom guidance) are in the dashboard sidebar.

## 📊 How Severity Is Scored

Each flagged IP gets a 0–100 score from:

- **Volume** of failed attempts
- **Rate** (attempts per minute)
- **Account spread** (number of distinct usernames)
- **Privileged or default account** targeted (root, admin, ...)
- **Share of non-existent usernames**
- **Attack pattern** (spraying or dictionary/bot)
- **Internal source** address (possible compromised host)
- **+40** if a successful login followed the failures

Levels: **≥75 Critical · ≥55 High · ≥30 Medium · ≥10 Low · otherwise Informational.** A success-after-failures finding is always Critical. The full breakdown appears in the report appendix and in the dashboard.

## 🔌 API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Reports API status and whether Ollama and the model are available. |
| `POST` | `/analyze-logs` | Multipart upload with `file`, plus optional `min_failures`, `privileged_accounts`, `firewall` (`iptables`, `ufw`, `firewalld`, `all`), `critical_on_privileged`, `use_llm` and `custom_rules`. Returns the analysis, report and commands as JSON. |

```bash
curl -F "file=@auth.log" -F "firewall=ufw" -F "use_llm=false" http://127.0.0.1:8000/analyze-logs
```

## 📁 Project Structure

```
├── app.py            # Streamlit dashboard
├── main.py           # FastAPI backend
├── engine.py         # Parsing, detection, severity, report builder
├── llm.py            # Ollama client + output validation
└── requirements.txt
```

## 🔒 Security Design

- **Local and private:** logs never leave your machine.
- **Prompt-injection resistant:** the LLM receives only computed data. Raw log lines and attacker-controlled usernames are never sent to it, and usernames are sanitized.
- **Validated output:** any IP address the model mentions that was not found in the logs is replaced with `[unverified IP]`, and code blocks are stripped from its output.
- **Commands built from validated data:** firewall commands are generated in Python from parsed, validated IP addresses. Always review them before running, especially for private/internal addresses.

## ⚠️ Limitations

- Parses **`sshd`** authentication logs only. Other sources (PAM, Windows, web or VPN logins) need new parsers in `engine.py`.
- Wazuh output is generated rule text. There is no live Wazuh integration, so validate rules with `wazuh-logtest` before deploying.
- Syslog timestamps carry no year, so the current year is assumed.
- The AI narrative has not been benchmarked. Treat it as a draft for analyst review.

## 🗺️ Roadmap

- [ ] Support for additional log sources (web, VPN, Windows RDP)
- [ ] Incident history storage (e.g. SQLite)
- [ ] PDF report export
- [ ] Live Wazuh API integration
- [ ] Optional IP reputation enrichment

## 📚 Research Motivation

Existing work treats brute-force detection, mitigation and playbook generation separately. This project combines **log-based detection, severity analysis, AI-customized playbook generation and automatic incident-report generation in one simple system.**
