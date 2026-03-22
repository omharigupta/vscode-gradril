# Gradril — High-Level Data Flow

## Input Pipeline (Pre-LLM)

1. User types prompt in VS Code Chat Panel using `@gradril`
2. Chat Participant API intercepts prompt BEFORE any API call
3. **Local Validation Layer** (regex-based, < 50ms):
   - PII detection (SSN, email, phone, credit card, IP, passport, DOB)
   - Secret detection (AWS keys, tokens, JWTs, private keys, passwords)
   - Injection detection (instruction override, role hijack, extraction, delimiter, restriction removal)
   - Jailbreak detection (DAN, developer mode, hypothetical, roleplay, encoding evasion)
   - Toxicity detection (violence, harassment, self-harm, illegal, explicit, custom blocklist)
4. **Backend Validation Layer** (Guardrails AI, self-hosted, optional):
   - DetectPII (Presidio ML)
   - ToxicLanguage (ML classifier)
   - DetectJailbreak (ML pattern recognition)
   - SecretsPresent (rule + ML hybrid)
   - UnusualPrompt (LLM trickery detection)
   - Falls back to local-only if backend unavailable
5. **Risk Scoring**:
   - Weighted multi-signal scoring (PII 0.25, secrets 0.30, injection 0.25, jailbreak 0.25, toxicity 0.20)
   - Critical findings get extra visual warnings but are still masked and forwarded
6. **Decision Engine**:
   - Score < 0.3 and no findings → ALLOW
   - Any findings detected (any score) → SANITIZE (mask & forward)
   - **Gradril never blocks** — it always masks and sends

## Decision Outcomes

7. **ALLOW** → Forward original prompt to Copilot
   - Append "✅ Verified by Gradril" footer
8. **SANITIZE** → Mask/strip findings, forward modified prompt
   - Show color-coded before→after redactions (🔴 ~~masked~~ → 🟢 replacement)
   - Display grouped findings by category with masked detected values
   - Even critical-severity findings are masked and forwarded with extra warnings

## Output Pipeline (Post-LLM)

10. Copilot generates response
11. **Output Guard** (Guardrails AI backend):
    - GroundedAIHallucination → sentence-level hallucination scoring
    - BiasCheck → flag biased content
    - ToxicLanguage → defense-in-depth on output
    - DetectPII → catch training data PII leaks
12. **Hallucination Analysis** rendered with:
    - Sentence-level badges (✅ Grounded, ⚠️ Uncertain, 🔴 Hallucinated)
    - Confidence bars per sentence
    - Overall score summary

## Cross-Cutting

13. **Audit Logging**: SHA-256 hashed entries → `.gradril/audit.jsonl` (never raw text)
14. **Status Bar**: Real-time guard indicator (enabled/disabled, backend online/offline)
15. **Slash Commands**: `/scan` (dry-run report), `/status` (dashboard), `/config` (settings)

## Flow Diagram

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
    │         └─→ ⚠️ Mask/strip → show before→after → forward to Copilot
    │
    └─→ ✅ Forward original prompt to Copilot
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
       Color-coded response with hallucination badges
```