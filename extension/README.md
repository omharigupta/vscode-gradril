# Gradril — Copilot Prompt Guardrail

A VS Code extension that intercepts prompts sent to GitHub Copilot Chat, validates them for security risks, and guards against credential leaks, PII exposure, prompt injection, and jailbreak attempts.

## Features

- **PII Detection** — SSN, email, phone, credit card, IP address
- **Secret Detection** — AWS keys, GitHub tokens, JWT, DB connection strings, private keys
- **Prompt Injection Prevention** — Blocks "ignore previous instructions", system prompt extraction, role hijacking
- **Jailbreak Detection** — DAN, developer mode, dual response, encoding evasion
- **Toxicity Filtering** — Violence, self-harm, illegal activity, harassment + custom blocklist
- **Automatic Sanitization** — Redacts PII/secrets, strips injection phrases while preserving the legitimate question
- **Hallucination Detection** — Color-coded confidence analysis on LLM responses (via Guardrails AI backend)
- **Bias Detection** — Flags biased LLM output (via Guardrails AI backend)
- **Audit Log** — Local-only logging of decisions (hashes only, never raw text)

## Architecture

```
User Prompt → Local Validators (instant) → Decision Engine → ALLOW / SANITIZE / BLOCK
                    ↕ (parallel)
            Guardrails AI Backend (ML)
                    
LLM Response → Guardrails AI Output Guard → Color-coded hallucination/bias display
```

**Local layer** (TypeScript, ~1-5ms): PII, secrets, injection, jailbreak, toxicity detection + sanitization + risk scoring + decision engine.

**Backend layer** (Guardrails AI, ML models): GroundedAIHallucination, BiasCheck, DetectPII, ToxicLanguage, DetectJailbreak, SecretsPresent, UnusualPrompt.

## Usage

### Chat with @gradril

Type `@gradril` in Copilot Chat to route prompts through the guardrail:

```
@gradril how do I implement authentication in Express?
```

### Slash Commands

| Command | Description |
|---------|-------------|
| `/scan` | Dry-run security scan without sending to AI |
| `/status` | Show guard status and session statistics |
| `/config` | Open Gradril settings |

### Commands (Command Palette)

- **Gradril: Toggle Guard** — Enable/disable the guardrail
- **Gradril: Open Audit Log** — View decision history
- **Gradril: Test Backend Connection** — Check Guardrails AI server connectivity

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `gradril.enabled` | `true` | Enable/disable the guard |
| `gradril.backendUrl` | `http://localhost:8000` | Guardrails AI server URL |
| `gradril.backendEnabled` | `true` | Use backend ML validation |
| `gradril.backendTimeout` | `2000` | Backend timeout (ms) |
| `gradril.blockThreshold` | `0.7` | Risk score to block (0-1) |
| `gradril.sanitizeThreshold` | `0.3` | Risk score to sanitize (0-1) |
| `gradril.enabledValidators` | all | Active validators |
| `gradril.customBlocklist` | `[]` | Additional blocked terms |
| `gradril.auditLogEnabled` | `true` | Enable audit logging |

## Backend Setup (Optional)

The extension works fully offline with local validators. For ML-powered validation:

```bash
pip install "guardrails-ai[api]"
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/toxic_language
guardrails hub install hub://guardrails/detect_jailbreak
guardrails hub install hub://guardrails/secrets_present
guardrails hub install hub://guardrails/unusual_prompt
guardrails hub install hub://groundedai/grounded_ai_hallucination
guardrails hub install hub://guardrails/bias_check
guardrails start --config config.py
```

Server runs at `http://localhost:8000`. All processing stays on your machine — no data leaves localhost.

## Requirements

- VS Code 1.90.0+
- GitHub Copilot Chat extension
- (Optional) Python 3.9+ for Guardrails AI backend

## License

MIT
