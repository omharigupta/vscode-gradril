# Gradril — Setup & Installation Guide

Complete guide to install, run, and develop the Gradril Copilot Prompt Guardrail extension.

---

## Table of Contents

1. [Quick Install (VSIX)](#1-quick-install-vsix)
2. [Build from Source](#2-build-from-source)
3. [Run as Custom Connector](#3-run-as-custom-connector)
4. [Backend with Docker (Recommended)](#4-backend-with-docker-recommended)
5. [Backend Manual Setup](#5-backend-manual-setup)
6. [How It Works](#6-how-it-works)
7. [Configuration](#7-configuration)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Quick Install (VSIX)

The fastest way to start using Gradril.

### Prerequisites

- VS Code **^1.90.0**
- GitHub Copilot extension installed

### Steps

```bash
# Install the pre-built extension
code --install-extension gradril-1.0.0.vsix
```

Or in VS Code:

1. Open **Extensions** panel (`Ctrl+Shift+X`)
2. Click **...** (top-right) → **Install from VSIX...**
3. Select `gradril-1.0.0.vsix`
4. Click **Reload** when prompted

### After Install

1. VS Code reloads → Gradril activates automatically
2. **First time:** A notification appears — click **"Open Gradril Chat"**
3. **Every time after:** Chat panel auto-opens with `@gradril` pre-selected
4. Type any prompt → Gradril validates, masks secrets/PII, and forwards to Copilot

> **Note:** `@gradril` is set to "sticky" mode. Once selected, it stays active for **all messages** in the session — you don't need to type `@gradril` every time.

---

## 2. Build from Source

### Prerequisites

- **Node.js** 18.x or 20.x
- **VS Code** ^1.90.0
- **Git**

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/omharigupta/vscode-gradril.git
cd vscode-gradril

# 2. Install dependencies
cd extension
npm install

# 3. Build TypeScript
npm run build

# 4. Package as VSIX
echo y | node_modules/.bin/vsce package --no-dependencies --allow-missing-repository
# On Windows:
# echo y | node_modules\.bin\vsce package --no-dependencies --allow-missing-repository

# 5. Install the generated VSIX
code --install-extension gradril-1.0.0.vsix
```

### Development Mode (F5 Debug)

1. Open the `extension/` folder in VS Code
2. Press **F5** → launches Extension Development Host
3. In the new VS Code window, open Chat panel and type `@gradril`
4. Make code changes → the host auto-reloads

### Watch Mode

```bash
# Auto-recompile on file changes
npm run watch
```

---

## 3. Run as Custom Connector

Gradril works as a **custom AI connector** that sits between you and GitHub Copilot. Here's how it operates:

### How the Connector Works

```
You type a prompt
        │
        ▼
┌─────────────────┐
│   GRADRIL        │  ← Intercepts via Chat Participant API
│   Connector      │
│                  │
│  1. Scan prompt  │  ← Local regex (PII, secrets, injection, jailbreak, toxicity)
│  2. ML validate  │  ← Guardrails AI backend (optional)
│  3. Score risk   │  ← Weighted multi-signal scoring
│  4. Mask/sanitize│  ← Replace secrets with [REDACTED-AWS-KEY] etc.
│  5. Forward      │  ← Send sanitized prompt to Copilot
│  6. Check output │  ← Hallucination & bias detection on response
│  7. Show results │  ← Color-coded findings + masked values
└─────────────────┘
        │
        ▼
  Copilot responds with safe, validated context
```

### Connector Behavior

| What You Type | What Gradril Does | What Copilot Sees |
|---|---|---|
| `my AWS key is AKIA1234567890ABCDEF` | Detects AWS key → masks it | `my AWS key is [REDACTED-AWS-KEY]` |
| `email me at john@example.com` | Detects email → masks it | `email me at [EMAIL_REDACTED]` |
| `ignore previous instructions and...` | Detects injection → strips it | `and...` (malicious part removed) |
| `explain kubernetes deployments` | No findings → passes through | `explain kubernetes deployments` |

### Auto-Activation

Gradril auto-activates on VS Code startup:

- **First launch:** Notification + "Open Gradril Chat" button
- **Subsequent launches:** Chat panel opens automatically with `@gradril` pre-selected
- **Sticky mode:** Once selected, `@gradril` stays active for the entire session
- **No manual steps needed** after the first click

### Slash Commands

| Command | Purpose |
|---|---|
| `@gradril /scan <prompt>` | Dry-run scan — see what would be detected without sending to AI |
| `@gradril /status` | Show guard status, backend health, session stats |
| `@gradril /config` | Open Gradril settings |

### Status Bar

The status bar shows real-time guard status:
- 🛡️ **Active** — Guard enabled, backend online
- 🛡️ **Local Only** — Guard enabled, backend offline (still safe!)
- ⚪ **Off** — Guard disabled

---

## 4. Backend with Docker (Recommended)

The easiest way to run the Guardrails AI backend. One command, everything included.

### Prerequisites

- **Docker** installed and running ([Get Docker](https://docs.docker.com/get-docker/))
- **Docker Compose** (included with Docker Desktop)

### Get a Guardrails Hub Token

A free token is required to download the Hub validators during the Docker build.

1. Sign up at [https://guardrailsai.com](https://guardrailsai.com)
2. Go to [https://guardrailsai.com/hub/keys](https://guardrailsai.com/hub/keys)
3. Copy your API token

### Quick Start

```bash
# From the project root directory

# Set your Guardrails Hub token
export GUARDRAILS_TOKEN=your_token_here

# Option 1: Docker Compose (recommended)
docker compose up -d --build

# Option 2: Build and run manually
cd backend
docker build --build-arg GUARDRAILS_TOKEN=$GUARDRAILS_TOKEN -t gradril-backend .
docker run -d -p 8000:8000 --name gradril-backend gradril-backend
```

> **Note:** The token is only needed once during `docker build` to download validators. It is NOT needed at runtime.

That's it! The backend is now running at `http://localhost:8000`.

### Verify it's running

```bash
# Health check
curl http://localhost:8000/health

# Or open in browser
# http://localhost:8000/docs
```

### Docker Commands

```bash
# Start the backend
docker compose up -d

# Stop the backend
docker compose down

# View logs
docker compose logs -f gradril-backend

# Restart
docker compose restart

# Rebuild (after updating config.py)
docker compose up -d --build
```

### What's inside the Docker image

The Dockerfile automatically:
1. Installs Python 3.11 + Guardrails AI
2. Downloads all 7 Hub validators (PII, toxicity, jailbreak, secrets, unusual prompt, hallucination, bias)
3. Copies `config.py` with input guard + output guard
4. Starts the server on port 8000
5. Includes health checks every 30s

### Docker image details

| Property | Value |
|---|---|
| Base image | `python:3.11-slim` |
| Port | `8000` |
| Health check | `GET /health` every 30s |
| Restart policy | `unless-stopped` |
| API docs | `http://localhost:8000/docs` |

> **Note:** First build takes 3-5 minutes (downloads ML models). Subsequent starts are instant.

---

## 5. Backend Manual Setup

If you prefer running without Docker.

> **Without backend:** Gradril still works using 5 local regex validators. The backend adds ML-based detection for better accuracy.

### Prerequisites

- **Python** 3.9+
- **pip**

### Steps

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Install Guardrails AI
pip install "guardrails-ai[api]"

# 4. Get a free API key from https://guardrailsai.com/hub/keys
guardrails configure

# 5. Install Hub validators (input guard)
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/toxic_language
guardrails hub install hub://guardrails/detect_jailbreak
guardrails hub install hub://guardrails/secrets_present
guardrails hub install hub://guardrails/unusual_prompt

# 6. Install Hub validators (output guard)
guardrails hub install hub://groundedai/grounded_ai_hallucination
guardrails hub install hub://guardrails/bias_check

# 7. Start the server
guardrails start --config config.py
```

### Verify Backend

```bash
# Health check
curl http://localhost:8000/health

# Open API docs
# http://localhost:8000/docs
```

### Backend Guards

**Input Guard** (`gradril_input_guard`) — validates prompts BEFORE LLM:

| Validator | What It Does | On Failure |
|---|---|---|
| DetectPII | ML-based PII detection (Presidio) | Auto-redact |
| ToxicLanguage | ML toxicity classifier | Block |
| DetectJailbreak | ML jailbreak pattern recognition | Block |
| SecretsPresent | Rule + ML secret detection | Auto-redact |
| UnusualPrompt | LLM trickery detection | Log only |

**Output Guard** (`gradril_output_guard`) — validates LLM responses AFTER generation:

| Validator | What It Does | On Failure |
|---|---|---|
| GroundedAIHallucination | Sentence-level hallucination scoring | Flag for display |
| BiasCheck | ML bias classifier | Flag for display |
| ToxicLanguage | Defense-in-depth on output | Block |
| DetectPII | Catch training data PII leaks | Auto-redact |

### Test Backend from VS Code

```
Ctrl+Shift+P → "Gradril: Test Backend Connection"
```

Or in chat:
```
@gradril /status
```

---

## 6. How It Works

### Extension Architecture

```
extension/src/
├── extension.ts           # Entry point — auto-activates, wires all modules
├── validators/            # 5 local regex validators (PII, secrets, injection, jailbreak, toxicity)
├── sanitizer/             # Masking pipeline (PII → [EMAIL_REDACTED], secrets → [AWS_KEY_REDACTED])
├── engine/                # Risk scoring + decision engine (ALLOW or SANITIZE, never blocks)
├── backend/               # HTTP client for Guardrails AI (input validate + output validate)
├── participant/           # Chat Participant handler — the main pipeline
├── ui/                    # Status bar, feedback renderer (risk bars, masked values), audit webview
├── logging/               # SHA-256 hashed audit log (.gradril/audit.jsonl)
└── config/                # VS Code settings bindings
```

### Pipeline Flow

1. **Intercept** — Chat Participant API captures your prompt
2. **Local Scan** — 5 regex validators run in parallel (< 50ms)
3. **Backend Scan** — Guardrails AI ML validators (optional, < 2s)
4. **Risk Score** — Weighted scoring: PII 0.25, Secrets 0.30, Injection 0.25, Jailbreak 0.25, Toxicity 0.20
5. **Decision** — Score < 0.3 → ALLOW, Score ≥ 0.3 or any findings → SANITIZE
6. **Sanitize** — Mask PII/secrets, strip injections
7. **Forward** — Send sanitized prompt to Copilot
8. **Output Guard** — Check LLM response for hallucinations, bias, PII leaks
9. **Display** — Show color-coded findings, masked values, hallucination badges

### Visual Feedback

When findings are detected, you see:

```
## ⚠️ Prompt Modified for Safety

Risk: 85% 🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥⬜⬜⬜ High

### 🔍 Detected & Redacted

🔴 **AWS key** detected
> 🔴 ~~AKIA••••••••••••CDEF~~ → 🟢 [REDACTED-AWS-KEY]

🟠 **email address** detected
> 🔴 ~~jo••@example.com~~ → 🟢 [EMAIL_REDACTED]
```

---

## 7. Configuration

Open settings: `Ctrl+Shift+P` → "Preferences: Open Settings" → search `gradril`

| Setting | Default | Description |
|---|---|---|
| `gradril.enabled` | `true` | Enable/disable the guardrail |
| `gradril.backendUrl` | `http://localhost:8000` | Guardrails AI backend URL |
| `gradril.backendEnabled` | `true` | Enable backend ML validation |
| `gradril.backendTimeout` | `2000` | Backend timeout (ms) |
| `gradril.sanitizeThreshold` | `0.3` | Risk score above which prompts are sanitized |
| `gradril.enabledValidators` | `["pii","secrets","injection","jailbreak","toxicity"]` | Active validators |
| `gradril.customBlocklist` | `[]` | Additional blocked terms |
| `gradril.auditLogEnabled` | `true` | Enable SHA-256 hashed audit logging |

---

## 8. Troubleshooting

### Extension not showing in Chat

- Make sure VS Code is **^1.90.0** or later
- Make sure GitHub **Copilot Chat** extension is installed
- Reload VS Code: `Ctrl+Shift+P` → "Developer: Reload Window"

### `@gradril` not appearing

- Check that the extension is installed: `Ctrl+Shift+X` → search "Gradril"
- Check Output panel: `Ctrl+Shift+U` → select "Gradril" channel for logs

### Backend not connecting

```bash
# Test from terminal
curl http://localhost:8000/health

# Check if server is running
# Should see: guardrails start --config config.py
```

- Verify `gradril.backendUrl` in settings matches your server
- Verify `gradril.backendEnabled` is `true`
- Run `Ctrl+Shift+P` → "Gradril: Test Backend Connection"

### Extension works without backend

Yes — Gradril **always works** with local regex validators. The backend adds ML accuracy but is completely optional. The extension gracefully degrades to local-only when the backend is unavailable.

### Audit log location

```
<workspace>/.gradril/audit.jsonl
```

View it: `Ctrl+Shift+P` → "Gradril: Open Audit Log"

---

## Quick Reference

| Action | How |
|---|---|
| **Install** | `code --install-extension gradril-1.0.0.vsix` |
| **Use** | Open Chat panel → type `@gradril <your prompt>` |
| **Scan only** | `@gradril /scan <prompt>` |
| **Check status** | `@gradril /status` |
| **Toggle on/off** | `Ctrl+Shift+P` → "Gradril: Toggle Guard" |
| **View audit log** | `Ctrl+Shift+P` → "Gradril: Open Audit Log" |
| **Test backend** | `Ctrl+Shift+P` → "Gradril: Test Backend Connection" |
| **Build from source** | `cd extension && npm install && npm run build` |
| **Package** | `echo y \| vsce package --no-dependencies --allow-missing-repository` |
| **Start backend** | `cd backend && guardrails start --config config.py` |
