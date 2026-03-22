# Gradril — Agent Handoff Context

> **Last updated**: 2026-03-19 | **Completed**: Phase 0–8 (All implementation complete) | **Next**: Phase 9 (Testing), Phase 10 (CI & Packaging)

---

## What Has Been Done

### Phase 0 — Project Setup (Tasks 1–5) ✅ COMPLETE

| Task | File(s) | Status |
|---|---|---|
| Task 1: Extension scaffold | `extension/package.json` | ✅ Done |
| Task 2: tsconfig & build | `extension/tsconfig.json` | ✅ Done |
| Task 3: Folder structure | `extension/src/` tree | ✅ Done |
| Task 4: Settings schema | `extension/package.json` → `contributes.configuration` | ✅ Done |
| Task 5: Build/ignore config | `.gitignore`, `.vscodeignore` | ✅ Done |

### Phase 1 — Local Validators (Tasks 6–11) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 6: Validator types + orchestrator | `src/validators/index.ts` | ✅ Done | `Finding`, `ValidatorResult`, `Validator` interfaces + `ValidatorOrchestrator` class |
| Task 7: PII Detector | `src/validators/piiDetector.ts` | ✅ Done | SSN, email, phone, credit card (Luhn), IP, passport, DOB |
| Task 8: Secret Detector | `src/validators/secretDetector.ts` | ✅ Done | AWS, GitHub, GitLab, JWT, connection strings, private keys, Slack, Stripe, Azure, Twilio, SendGrid, Google, Heroku, npm, passwords |
| Task 9: Injection Detector | `src/validators/injectionDetector.ts` | ✅ Done | Override, role hijack, prompt extraction, context manipulation, delimiter injection, restriction removal, output manipulation |
| Task 10: Jailbreak Detector | `src/validators/jailbreakDetector.ts` | ✅ Done | Named jailbreaks (DAN etc), hypothetical framing, roleplay escalation, base64 payload decode + re-scan, unicode/homoglyph detection, multi-turn manipulation |
| Task 11: Toxicity Detector | `src/validators/toxicityDetector.ts` | ✅ Done | Violence, harassment, self-harm, illegal activity, explicit content categories + custom blocklist support |

### Build Verification ✅
- `npm run build` (`tsc -p ./`) → **0 errors**
- All 7 source files compile to `dist/` with declarations and source maps
- VS Code language server reports **0 diagnostics**

---

## What Has Been Done (Phases 2–4)

### Phase 2 — Sanitizer Module (Tasks 12–15) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 12: Sanitizer orchestrator | `src/sanitizer/index.ts` | ✅ Done | `SanitizeResult`, `SanitizeChange`, `Sanitizer` interfaces + `SanitizerOrchestrator` class with reverse-position processing, deduplication, whitespace cleanup |
| Task 13: PII Masker | `src/sanitizer/piiMasker.ts` | ✅ Done | Maps all 8 PII types to `[REDACTED-*]` placeholders (SSN, EMAIL, PHONE, CC, IP, PASSPORT, DOB) |
| Task 14: Secret Masker | `src/sanitizer/secretMasker.ts` | ✅ Done | Maps all 17 secret types to `[REDACTED-*]` placeholders (AWS, GitHub, JWT, etc.) |
| Task 15: Injection Stripper | `src/sanitizer/injectionStripper.ts` | ✅ Done | Strips injection (7 categories) and jailbreak (9 categories) phrases, returning empty string to remove malicious spans |

### Phase 3 — Decision Engine (Tasks 16–17) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 16: Risk Scorer | `src/engine/riskScorer.ts` | ✅ Done | Weighted aggregation (secrets=1.0, PII=1.0, injection=0.9, jailbreak=0.8, toxicity=0.7), critical severity override to 1.0, `RiskBreakdown` type |
| Task 17: Decision Engine | `src/engine/decisionEngine.ts` | ✅ Done | ALLOW/SANITIZE/BLOCK logic with configurable thresholds from VS Code settings, human-readable reasons, `Decision` type |

### Phase 4 — Backend Integration (Tasks 18–20) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 18: Backend config | `backend/config.py`, `backend/requirements.txt`, `backend/README.md` | ✅ Done | Guardrails AI guard with DetectPII, ToxicLanguage, DetectJailbreak, SecretsPresent, UnusualPrompt on messages |
| Task 19: HTTP Client | `src/backend/guardrailsClient.ts` | ✅ Done | Node.js built-in http/https, POST validate, GET health, timeout, retry with exponential backoff (max 2), periodic health checks, graceful fallback |
| Task 20: Backend Types | `src/backend/types.ts` | ✅ Done | `BackendRequest`, `BackendResponse`, `BackendValidation`, `BackendHealthResponse`, `BackendResult` interfaces |

### Phase 5 — Chat Participant & Core Flow (Tasks 21–24) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 21: Chat Request Handler | `src/participant/handler.ts` | ✅ Done | Full pipeline: validate → sanitize → decide → ALLOW/SANITIZE/BLOCK, backend integration, cancellation support, audit logging |
| Task 22: /scan command | `src/participant/handler.ts` | ✅ Done | Dry-run validation with full markdown report (risk score, findings table, recommendations) |
| Task 23: /status command | `src/participant/handler.ts` | ✅ Done | Shows config, backend status, session statistics in markdown tables |
| Task 24: /config command | `src/participant/handler.ts` | ✅ Done | Opens VS Code settings filtered to `gradril.*` |

### Phase 6 — UI & Feedback (Tasks 25–28) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 25: Status Bar | `src/ui/statusBar.ts` | ✅ Done | 3 states (Active/Local Only/Off), click toggles guard, themed colors |
| Task 26: Feedback Renderer | `src/ui/feedback.ts` | ✅ Done | renderBlock, renderSanitizeHeader/Footer, renderAllowFooter, renderScanReport, renderStatusReport |
| Task 27: Output Channel | `src/logging/outputChannel.ts` | ✅ Done | DEBUG/INFO/WARN/ERROR levels, ISO timestamps, logDecision/logBackend helpers |
| Task 28: Audit Webview | `src/ui/auditWebview.ts` | ✅ Done | HTML table with color-coded decisions, score bars, auto-refresh via FileSystemWatcher |

### Phase 7 — Logging & Config (Tasks 29–30) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 29: Audit Logger | `src/logging/auditLog.ts` | ✅ Done | JSON-lines to `.gradril/audit.jsonl`, SHA-256 prompt hashing, readAll(), getStats(), auto-create directory |
| Task 30: Settings Reader | `src/config/settings.ts` | ✅ Done | Singleton with typed getters for all 9 settings, onDidChange event, hot-reload |

### Phase 8 — Extension Wiring (Tasks 31–33) ✅ COMPLETE

| Task | File | Status | Details |
|---|---|---|---|
| Task 31: Wire extension.ts | `src/extension.ts` | ✅ Done | Full activate() wiring: settings→logger→auditLog→validators→sanitizer→engine→backend→UI→handler→participant→commands |
| Task 32: toggleGuard command | `src/extension.ts` | ✅ Done | Toggles setting, updates status bar, shows notification, logs |
| Task 33: testConnection command | `src/extension.ts` | ✅ Done | Calls healthCheck(), shows latency on success, error on failure |

### Build Verification (Phase 0–8) ✅
- `npm run build` (`tsc -p ./`) → **0 errors, 0 warnings**
- 24 source files compile to `dist/` with declarations and source maps
- VS Code language server reports **0 diagnostics**
- Zero new npm runtime dependencies (Node.js built-in http/https/url/crypto/fs/path only)

---

## Project Structure (Current State)

```
gradril/
├── extension/                       ← VS Code Extension (TypeScript)
│   ├── dist/                        ← Compiled output (auto-generated)
│   ├── node_modules/
│   ├── src/
│   │   ├── extension.ts             ← Entry point (stub — needs Phase 5/8 wiring)
│   │   ├── validators/
│   │   │   ├── index.ts             ← Validator interfaces + ValidatorOrchestrator
│   │   │   ├── piiDetector.ts       ← PIIDetector class
│   │   │   ├── secretDetector.ts    ← SecretDetector class
│   │   │   ├── injectionDetector.ts ← InjectionDetector class
│   │   │   ├── jailbreakDetector.ts ← JailbreakDetector class
│   │   │   └── toxicityDetector.ts  ← ToxicityDetector class
│   │   ├── sanitizer/               ← NEW (Phase 2)
│   │   │   ├── index.ts             ← SanitizeResult/SanitizeChange types + SanitizerOrchestrator
│   │   │   ├── piiMasker.ts         ← PIIMasker — [REDACTED-EMAIL], [REDACTED-SSN], etc.
│   │   │   ├── secretMasker.ts      ← SecretMasker — [REDACTED-AWS-KEY], etc.
│   │   │   └── injectionStripper.ts ← InjectionStripper — strips injection/jailbreak phrases
│   │   ├── engine/                   ← NEW (Phase 3)
│   │   │   ├── riskScorer.ts        ← RiskScorer — weighted aggregation + critical override
│   │   │   └── decisionEngine.ts    ← DecisionEngine — ALLOW/SANITIZE/BLOCK logic
│   │   ├── backend/                  ← Phase 4
│   │   │   ├── types.ts             ← BackendRequest, BackendResponse, etc.
│   │   │   └── guardrailsClient.ts  ← HTTP client for Guardrails AI server
│   │   ├── participant/              ← Phase 5
│   │   │   └── handler.ts           ← ChatRequestHandler + /scan, /status, /config
│   │   ├── ui/                       ← Phase 6
│   │   │   ├── statusBar.ts         ← Status bar item (Active/Local Only/Off)
│   │   │   ├── feedback.ts          ← Chat response renderer (ALLOW/SANITIZE/BLOCK)
│   │   │   └── auditWebview.ts      ← Webview panel for audit log
│   │   ├── logging/                  ← Phase 7
│   │   │   ├── outputChannel.ts     ← Debug output channel logger
│   │   │   └── auditLog.ts          ← JSON-lines audit trail
│   │   └── config/                   ← Phase 7
│   │       └── settings.ts          ← Typed settings reader singleton
│   ├── package.json                 ← Extension manifest with chat participant, settings, commands
│   ├── tsconfig.json
│   ├── .gitignore
│   └── .vscodeignore
├── backend/                          ← NEW (Phase 4) — Guardrails AI Python config
│   ├── config.py                    ← Guard definition (5 Hub validators)
│   ├── requirements.txt             ← guardrails-ai>=0.5.0
│   └── README.md                    ← Backend setup instructions
├── hldflow.md                       ← High-level data flow (requirements)
├── requi.yml                        ← Functional/non-functional requirements
├── spec.yml                         ← System specification
├── PLAN.md                          ← Full implementation plan
└── TASKS.md                         ← 41-task breakdown with dependencies
```

---

## Key Interfaces (for next phases to consume)

### From `src/validators/index.ts`:

```typescript
// Every validator returns this
interface ValidatorResult {
    validatorName: string;
    detected: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    findings: Finding[];
    score: number; // 0-1
}

// Individual detection
interface Finding {
    type: string;       // e.g. 'EMAIL', 'AWS_ACCESS_KEY', 'INJECTION'
    match: string;      // masked for safety
    position: number;   // char offset in prompt
    length: number;     // length of matched text
    confidence: number; // 0-1
    severity: 'low' | 'medium' | 'high' | 'critical';
    validator: string;  // which validator found this
}

// All validators implement this
interface Validator {
    readonly name: string;
    validate(prompt: string): ValidatorResult;
}

// Run all validators
class ValidatorOrchestrator {
    register(validator: Validator): void;
    async runAll(prompt: string, enabledValidators?: string[]): Promise<ValidatorResult[]>;
    static flattenFindings(results: ValidatorResult[]): Finding[];
    static highestSeverity(results: ValidatorResult[]): Severity;
}
```

### From `src/sanitizer/index.ts` (Phase 2):

```typescript
interface SanitizeChange {
    finding: Finding;       // The finding that triggered this change
    replacement: string;    // e.g. '[REDACTED-EMAIL]'
    position: number;       // char offset in ORIGINAL prompt
    originalText: string;   // the text that was replaced
}

interface SanitizeResult {
    original: string;       // original prompt
    sanitized: string;      // cleaned prompt
    changes: SanitizeChange[];
    canSanitize: boolean;   // false = must BLOCK
}

interface Sanitizer {
    readonly handledTypes: string[];
    sanitize(finding: Finding, originalText: string): string;
}

class SanitizerOrchestrator {
    register(sanitizer: Sanitizer): void;
    sanitize(prompt: string, findings: Finding[]): SanitizeResult;
}
```

### From `src/engine/riskScorer.ts` (Phase 3):

```typescript
interface RiskBreakdown {
    finalScore: number;          // 0–1
    dominantCategory: string;    // validator with highest weighted score
    breakdown: Record<string, number>;  // per-validator scores
    criticalOverride: boolean;   // any critical finding → 1.0
}

class RiskScorer {
    score(results: ValidatorResult[]): RiskBreakdown;
    setWeight(validatorName: string, weight: number): void;
}
```

### From `src/engine/decisionEngine.ts` (Phase 3):

```typescript
type DecisionAction = 'ALLOW' | 'SANITIZE' | 'BLOCK';

interface Decision {
    action: DecisionAction;
    riskScore: number;
    reason: string;
    findings: Finding[];
    breakdown: RiskBreakdown;
    sanitizedPrompt?: string;
    criticalOverride: boolean;
    latencyMs?: number;
}

class DecisionEngine {
    decide(results: ValidatorResult[], sanitizeResult: SanitizeResult, findings: Finding[]): Decision;
    decideWithThresholds(..., blockThreshold: number, sanitizeThreshold: number): Decision;
}
```

### From `src/backend/guardrailsClient.ts` (Phase 4):

```typescript
class GuardrailsClient {
    isAvailable(): boolean;
    startHealthChecks(): void;
    stopHealthChecks(): void;
    async healthCheck(): Promise<BackendHealthResponse | null>;
    async validate(prompt: string, guardName?: string): Promise<BackendResult | null>;
    dispose(): void;
}
```

### Validator Names (for `enabledValidators` config):
- `'pii'` → `PIIDetector`
- `'secrets'` → `SecretDetector`
- `'injection'` → `InjectionDetector`
- `'jailbreak'` → `JailbreakDetector`
- `'toxicity'` → `ToxicityDetector`

---

## Dependencies

### npm (devDependencies only — zero runtime deps):
```json
{
    "@types/node": "^18.19.0",
    "@types/vscode": "^1.90.0",
    "typescript": "^5.4.0"
}
```

### VS Code API version: `^1.90.0`
### Node.js required: 18.x or 20.x
### TypeScript target: ES2020, commonjs modules

---

## Extension Manifest Key Points (`package.json`)

- **Main entry**: `./dist/extension.js`
- **Activation**: `onStartupFinished`
- **Chat Participant**: `gradril.guard` (name: `@gradril`)
  - Slash commands: `/scan`, `/status`, `/config`
  - Disambiguation enabled for auto-routing
- **Commands**: `gradril.toggleGuard`, `gradril.openAuditLog`, `gradril.testConnection`
- **Settings** (9 total): `gradril.enabled`, `gradril.backendUrl`, `gradril.backendEnabled`, `gradril.backendTimeout`, `gradril.blockThreshold`, `gradril.sanitizeThreshold`, `gradril.enabledValidators`, `gradril.customBlocklist`, `gradril.auditLogEnabled`

---

## What Needs To Be Done Next

### Phase 9 — Testing (Tasks 34–38) ← NEXT
> All implementation is complete. Next step is testing.

- **Task 34**: `src/test/validators.test.ts` — Unit tests for all 5 validators (PII, secrets, injection, jailbreak, toxicity)
- **Task 35**: `src/test/sanitizer.test.ts` — Unit tests for sanitizer (PII/secret masking, injection stripping, position preservation)
- **Task 36**: `src/test/engine.test.ts` — Unit tests for risk scorer and decision engine (threshold boundaries, critical override)
- **Task 37**: `src/test/integration.test.ts` — Full pipeline integration test (clean→ALLOW, PII→SANITIZE, injection→BLOCK, backend offline→fallback)
- **Task 38**: Manual test matrix execution (8 test cases in Extension Development Host)

### Phase 10 — CI & Packaging (Tasks 39–41)
- **Task 39**: `.github/workflows/ci.yml` — GitHub Actions CI (Node 18.x/20.x matrix)
- **Task 40**: `vsce package` → `.vsix` packaging
- **Task 41**: README.md, CHANGELOG.md documentation

---

## Guardrails AI Integration Plan

The backend uses [Guardrails AI](https://guardrailsai.com/) Python server:

```bash
pip install guardrails-ai
guardrails configure    # API key from https://guardrailsai.com/hub/keys
guardrails start --config config.py  # Starts on localhost:8000
```

Hub validators to install:
- `hub://guardrails/detect_pii` — ML-based PII (Microsoft Presidio)
- `hub://guardrails/toxic_language` — ML toxicity classification
- `hub://guardrails/detect_jailbreak` — ML jailbreak detection
- `hub://guardrails/secrets_present` — Rule + ML secret detection
- `hub://guardrails/unusual_prompt` — LLM-based trickery detection

The extension calls the backend via HTTP POST to `/guards/gradril_input_guard/validate`. If the backend is offline, the extension falls back to local-only validation (Phase 1 validators).

---

## How to Build & Run

```bash
cd extension/
npm install          # Install dev dependencies
npm run build        # Compile TypeScript → dist/
# Press F5 in VS Code to launch Extension Development Host
# Type @gradril in the chat to invoke the participant
```

---

## Architecture Decision: Why Chat Participant?

VS Code does NOT expose an API to intercept Copilot prompts directly. `vscode.chat.createChatParticipant()` is the only documented, stable mechanism to sit between the user and the LLM. Users invoke `@gradril` and the handler validates before forwarding to `request.model.sendRequest()`.

---

## Notes for Next Agent

1. **All modules are fully wired** — `extension.ts` initializes everything in `activate()`. No more stubs.
2. **The full pipeline works**: prompt → validators → sanitizer → decision engine → ALLOW/SANITIZE/BLOCK → LLM or block.
3. **For unit tests**, use `decisionEngine.decideWithThresholds()` to avoid needing VS Code context.
4. **ToxicityDetector `setCustomBlocklist()`** is called during activation and on settings change.
5. **Handler uses `createHandler()` factory** — accepts a `HandlerDependencies` object for easy mocking in tests.
6. **Audit log entries use SHA-256 hashes** — raw prompt text is NEVER stored.
7. **Backend integration is graceful** — if unavailable, local-only validation proceeds. GuardrailsClient returns `null`.
8. **Status bar auto-updates** on settings change and backend health check results.
9. **`/scan` is a dry-run** — runs the full pipeline but does NOT call the LLM. Shows a formatted report.
10. **`/status` shows live stats** from the AuditLog plus current config and backend availability.
11. **24 source files compile** with zero errors, zero warnings, zero runtime npm dependencies.
12. **Test structure**: tests should go in `src/test/` (excluded from tsconfig). Use `@vscode/test-electron` for integration tests.
13. **The `participant/handler.ts` streams LLM responses** chunk by chunk: `for await (const chunk of response.text) { stream.markdown(chunk); }`
14. **Backend `config.py` applies validators on `messages`** (not output) — this is input validation. Guard name: `gradril_input_guard`.
