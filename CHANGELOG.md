# Changelog

All notable changes to the Gradril extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2024-12-01

### Added

- **Chat Participant** — `@gradril` chat participant for VS Code Copilot Chat
  - `/scan` — Dry-run security scan with detailed risk report
  - `/status` — Session statistics, configuration, and backend health
  - `/config` — Quick-open Gradril settings

- **Local Validators** (regex-based, zero dependencies)
  - PII Detector — SSN, email, phone, credit card, IP address, passport, date of birth
  - Secret Detector — AWS keys, GitHub/GitLab tokens, JWT, API keys, connection strings, private keys, Slack/Stripe/Azure/Twilio/SendGrid/Google/Heroku/npm tokens, passwords
  - Injection Detector — Instruction override, role hijack, prompt extraction, context manipulation, delimiter injection, restriction removal, output manipulation
  - Jailbreak Detector — Named jailbreaks (DAN, developer mode), hypothetical framing, roleplay escalation, token smuggling, multi-turn manipulation, dual response, encoding evasion, base64 decode + rescan, unicode obfuscation
  - Toxicity Detector — Violence incitement, harassment, self-harm, illegal activity, explicit content, custom blocklist with word boundary matching

- **Sanitizer Pipeline**
  - PII Masker — Typed `[REDACTED-*]` placeholders for all PII types
  - Secret Masker — Typed `[REDACTED-*]` placeholders for all secret types
  - Injection Stripper — Removes malicious phrases while preserving legitimate questions
  - Reverse-position processing to prevent offset corruption
  - Overlap deduplication and whitespace cleanup

- **Decision Engine**
  - Weighted risk aggregation across all validator categories
  - Three-outcome decisions: ALLOW, SANITIZE, BLOCK
  - Configurable thresholds (default: sanitize=0.3, block=0.7)
  - Critical severity override (automatic BLOCK)
  - Human-readable decision reasons

- **Guardrails AI Backend Integration** (optional)
  - HTTP client with timeout, retry (exponential backoff), and graceful fallback
  - Periodic health checks (60s interval)
  - Supports `detect_pii`, `toxic_language`, `detect_jailbreak`, `secrets_present`, `unusual_prompt` Hub validators

- **UI & Feedback**
  - Status bar with 3 states: active (shield), local-only, disabled
  - Inline chat feedback: block warnings, sanitize headers/footers, allow footers
  - Audit log webview with auto-refresh (FileSystemWatcher)

- **Logging & Audit**
  - OutputChannel logger with DEBUG/INFO/WARN/ERROR levels
  - JSON-lines audit log with SHA-256 prompt hashing (never stores raw text)
  - Session statistics (allow/sanitize/block counts)

- **Configuration**
  - 9 configurable settings via VS Code Settings UI
  - Runtime settings change listener with automatic reload
  - Custom blocklist support

- **Testing**
  - Validator unit tests (PII, secrets, injection, jailbreak, toxicity)
  - Sanitizer unit tests (masking, stripping, position preservation)
  - Decision engine unit tests (scoring, thresholds, critical override)
  - Integration tests (full pipeline end-to-end)

- **CI/CD**
  - GitHub Actions CI: Node.js 18.x/20.x matrix, build + test
  - VSIX artifact upload on main branch pushes
  - `npm run package` for local VSIX generation
