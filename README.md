# Gradril — Copilot Prompt Guardrail

[![CI](https://github.com/gradril/gradril/actions/workflows/ci.yml/badge.svg)](https://github.com/gradril/gradril/actions/workflows/ci.yml)
[![VS Code](https://img.shields.io/badge/VS%20Code-^1.90.0-blue)](https://code.visualstudio.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Gradril** is a VS Code extension that intercepts and validates prompts before they reach GitHub Copilot, preventing credential leaks, PII exposure, prompt injection, jailbreak attempts, and toxic content. It also analyzes LLM output for hallucinations, bias, and data leakage using a self-hosted Guardrails AI backend.

## Features

### Input Guard (Pre-LLM)

- **PII Detection** — SSN, email, phone, credit card, IP, passport, date of birth
- **Secret Scanning** — AWS keys, GitHub/GitLab tokens, JWTs, connection strings, private keys, Stripe/Slack/Azure/npm tokens, passwords
- **Prompt Injection Detection** — Instruction override, role hijack, system prompt extraction, delimiter injection, restriction removal
- **Jailbreak Detection** — DAN, developer mode, hypothetical framing, roleplay escalation, base64 evasion, unicode obfuscation
- **Toxicity Filtering** — Violence, harassment, self-harm, illegal activity, explicit content, custom blocklist

### Output Guard (Post-LLM)

- **Hallucination Detection** — Sentence-level analysis with ML-based grounding scores via GroundedAI
- **Bias Detection** — ML classifier flags biased LLM responses
- **Output Toxicity** — Defense-in-depth toxicity check on generated responses
- **Output PII Leakage** — Catches PII from LLM training data

### Smart Processing

- **Sanitization** — PII/secrets masked with typed placeholders, injection phrases stripped while preserving intent
- **Risk-Based Decisions** — Weighted multi-signal scoring with two outcomes: ALLOW or SANITIZE (never blocks)
- **Graceful Degradation** — Falls back to local-only validation when backend is unavailable

### Rich Visual Feedback

- **Risk Bar** — Color-coded visual risk indicator (🟥🟥🟥🟥🟥⬜⬜⬜⬜⬜ 50%)
- **Grouped Findings** — Organized by category (🔑 Secrets, 👤 PII, 💉 Injection, 🔓 Jailbreak, ☠️ Toxicity)
- **Severity Indicators** — Per-finding icons (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW)
- **Masked Detected Values** — Shows what was found without exposing full secrets (e.g., `AKIA••••CDEF`, `jo••@example.com`, `123-••-••••`)
- **Before→After Redactions** — Color-coded display: 🔴 ~~`masked`~~ → 🟢 `[REDACTED]`
- **Hallucination Badges** — Sentence-level: ✅ Grounded, ⚠️ Uncertain, 🔴 Hallucinated with confidence bars

### Infrastructure

- **Backend ML Validation** — Self-hosted Guardrails AI (open source, Apache 2.0), zero external API calls
- **Audit Logging** — SHA-256 hashed entries (never raw text) in `.gradril/audit.jsonl`
- **Status Bar** — Real-time guard status indicator (enabled/disabled, backend online/offline)
- **Zero Runtime Deps** — Extension uses only Node.js built-in modules

## Architecture

```
User @gradril prompt
        │
        ▼
┌─────────────────┐
│  Local Validators│ ← PII, Secrets, Injection, Jailbreak, Toxicity
│  (regex, <50ms) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│Backend Validators│ ← Guardrails AI (self-hosted, optional)
│  (ML, <2000ms)  │   DetectPII, ToxicLanguage, DetectJailbreak,
└────────┬────────┘   SecretsPresent, UnusualPrompt
         │
         ▼
┌─────────────────┐
│  Risk Scorer +  │ ← Weighted scoring (never blocks)
│ Decision Engine │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
 ALLOW    SANITIZE
    │         │
    │         └─→ ⚠️ Mask findings, show before→after, forward to Copilot
    │
    └─→ ✅ Forward to Copilot
              │
              ▼
       ┌────────────┐
       │   Copilot   │ ← Generates response
       └──────┬─────┘
              │
              ▼
       ┌────────────┐
       │Output Guard │ ← Hallucination, Bias, Toxicity, PII
       │(backend ML) │
       └──────┬─────┘
              │
              ▼
       Response with hallucination badges & confidence bars
```

## Quick Start

### 1. Install the Extension

```bash
# From VSIX
code --install-extension gradril-1.0.0.vsix

# Or install from VS Code marketplace (when published)
```

### 2. Use in Chat

Open the VS Code Chat panel and type:

```
@gradril explain how to set up a kubernetes cluster
```

Gradril validates the prompt, then forwards safe prompts to Copilot.

### 3. (Optional) Set Up Backend

For ML-powered deep validation and hallucination detection, set up the self-hosted Guardrails AI backend:

```bash
cd backend
pip install -r requirements.txt
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/toxic_language
guardrails hub install hub://guardrails/detect_jailbreak
guardrails hub install hub://guardrails/secrets_present
guardrails hub install hub://guardrails/unusual_prompt
guardrails hub install hub://groundedai/grounded_ai_hallucination
guardrails hub install hub://guardrails/bias_check
guardrails start --config config.py
```

Server runs at `http://localhost:8000`. API docs at `http://localhost:8000/docs`.

See [backend/README.md](backend/README.md) for detailed instructions.

> **Note:** Guardrails AI is fully open source (Apache 2.0) and self-hosted. No data leaves your network — zero runtime calls to external cloud APIs.

## Slash Commands

| Command | Description |
|---------|-------------|
| `@gradril /scan <prompt>` | Dry-run scan — shows grouped risk report with masked values, no LLM call |
| `@gradril /status` | Shows guard status, session stats, backend health |
| `@gradril /config` | Opens Gradril settings in VS Code |

## Commands

| Command | Description |
|---------|-------------|
| `Gradril: Toggle Guard` | Enable/disable the guardrail |
| `Gradril: Open Audit Log` | View audit log in a webview panel |
| `Gradril: Test Backend Connection` | Test connectivity to Guardrails AI server |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `gradril.enabled` | `true` | Enable/disable the guardrail |
| `gradril.backendUrl` | `http://localhost:8000` | Guardrails AI backend URL |
| `gradril.backendEnabled` | `true` | Enable backend ML validation |
| `gradril.backendTimeout` | `2000` | Backend timeout (ms), falls back to local-only |
| `gradril.sanitizeThreshold` | `0.3` | Risk score above which prompts are sanitized (0–1) |
| `gradril.enabledValidators` | `["pii","secrets","injection","jailbreak","toxicity"]` | Active local validators |
| `gradril.customBlocklist` | `[]` | Additional blocked terms |
| `gradril.auditLogEnabled` | `true` | Enable SHA-256 hashed audit logging |

## Development

### Prerequisites

- Node.js 18.x or 20.x
- VS Code ^1.90.0
- Python 3.9+ (for backend only)

### Build

```bash
cd extension
npm install
npm run build
```

### Package

```bash
npm run package    # Creates gradril-1.0.0.vsix
```

### Debug

Press `F5` in VS Code to launch the Extension Development Host.

## Project Structure

```
extension/
├── src/
│   ├── extension.ts           # Entry point — wires all modules
│   ├── validators/            # 5 local regex-based validators
│   │   ├── index.ts           # Types (Finding, ValidationResult) & orchestrator
│   │   ├── piiDetector.ts     # SSN, email, phone, credit card, IP, passport, DOB
│   │   ├── secretDetector.ts  # AWS keys, tokens, JWTs, private keys, passwords
│   │   ├── injectionDetector.ts # Instruction override, role hijack, extraction
│   │   ├── jailbreakDetector.ts # DAN, developer mode, encoding evasion
│   │   └── toxicityDetector.ts  # Violence, harassment, custom blocklist
│   ├── sanitizer/             # Mask/strip pipeline
│   │   ├── index.ts           # Orchestrator (SanitizeResult, SanitizeChange)
│   │   ├── piiMasker.ts       # Typed PII placeholders
│   │   ├── secretMasker.ts    # Typed secret placeholders
│   │   └── injectionStripper.ts # Strip injections, preserve questions
│   ├── engine/                # Risk scoring & decisions
│   │   ├── riskScorer.ts      # Weighted multi-signal scoring
│   │   └── decisionEngine.ts  # ALLOW/SANITIZE (never blocks)
│   ├── backend/               # Guardrails AI HTTP client
│   │   ├── types.ts           # Backend API types + HallucinationResult
│   │   └── guardrailsClient.ts # validate() (input) + validateOutput() (output)
│   ├── participant/           # VS Code Chat Participant
│   │   └── handler.ts         # Request handler pipeline + hallucination analysis
│   ├── ui/                    # Visual feedback layer
│   │   ├── statusBar.ts       # Real-time guard status indicator
│   │   ├── feedback.ts        # Rich grouped findings, risk bars, masked values,
│   │   │                      #   before→after redactions, hallucination badges
│   │   └── auditWebview.ts    # Audit log webview panel
│   ├── logging/               # Structured logging & audit
│   │   ├── outputChannel.ts   # VS Code output channel
│   │   └── auditLog.ts        # SHA-256 hashed audit entries
│   └── config/                # Settings management
│       └── settings.ts        # VS Code configuration bindings
├── media/
│   └── icon.svg               # Extension icon (shield + checkmark)
├── package.json               # Extension manifest & contribution points
└── tsconfig.json              # TypeScript compiler configuration

backend/
├── config.py                  # Input guard (5 validators) + Output guard (4 validators)
├── requirements.txt           # Python dependencies
└── README.md                  # Backend setup instructions
```

## Backend Guards

### Input Guard (`gradril_input_guard`)
Applied to user prompts before LLM call:

| Validator | Source | Behavior |
|-----------|--------|----------|
| DetectPII | Presidio ML | `on_fail=fix` — auto-redact |
| ToxicLanguage | ML classifier | `on_fail=exception` — block |
| DetectJailbreak | ML pattern recognition | `on_fail=exception` — block |
| SecretsPresent | Rule + ML hybrid | `on_fail=fix` — auto-redact |
| UnusualPrompt | LLM trickery detection | `on_fail=noop` — log only |

### Output Guard (`gradril_output_guard`)
Applied to LLM responses after generation:

| Validator | Source | Behavior |
|-----------|--------|----------|
| GroundedAIHallucination | GroundedAI ML | `on_fail=noop` — flag for display |
| BiasCheck | ML classifier | `on_fail=noop` — flag for display |
| ToxicLanguage | ML classifier | `on_fail=exception` — block toxic output |
| DetectPII | Presidio ML | `on_fail=fix` — redact training data leaks |

## ML Models & Engines

| Validator | ML Model / Engine | Purpose |
|-----------|-------------------|---------|
| DetectPII | Microsoft Presidio (rule-based NER + spaCy `en_core_web_lg`) | Detect & redact PII (names, emails, SSNs, etc.) |
| ToxicLanguage | `unitary/toxic-bert` (HuggingFace) | Classify toxic/offensive language |
| DetectJailbreak | `GuardrailsAI/prompt-saturation-attack-detector` (HuggingFace) | Detect prompt injection & jailbreak attempts |
| SecretsPresent | Regex-based patterns (no ML model) | Detect API keys, tokens, passwords |
| UnusualPrompt | Statistical analysis (no large ML model) | Flag unusual/suspicious prompt patterns |
| GroundedAIHallucination | `GroundedAI` model (HuggingFace) | Detect hallucinated output |
| BiasCheck | `d4data/bias-detection-model` (HuggingFace) | Detect biased language |

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes
4. Run `npm run build` to verify clean compilation
5. Submit a pull request

## License

MIT — see [LICENSE](LICENSE) for details.
