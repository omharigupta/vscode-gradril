# Gradril — Guardrails AI Backend Configuration
# 
# This file defines the input guard used by the Gradril VS Code extension.
# The guard validates user prompts BEFORE they are sent to an LLM.
#
# Usage:
#   pip install "guardrails-ai[api]"
#   guardrails configure          # Set your API key from https://guardrailsai.com/hub/keys
#   guardrails hub install hub://guardrails/detect_pii
#   guardrails hub install hub://guardrails/toxic_language
#   guardrails hub install hub://guardrails/detect_jailbreak
#   guardrails hub install hub://guardrails/secrets_present
#   guardrails hub install hub://guardrails/unusual_prompt
#   guardrails hub install hub://groundedai/grounded_ai_hallucination
#   guardrails hub install hub://guardrails/bias_check
#   guardrails start --config config.py
#
# Server runs at http://localhost:8000
# API docs at http://localhost:8000/docs

from guardrails import Guard
from guardrails.hub import (
    DetectPII,
    ToxicLanguage,
    DetectJailbreak,
    SecretsPresent,
    UnusualPrompt,
    GroundedAIHallucination,
    BiasCheck,
)

# ─── Input Guard Definition ─────────────────────────────────────────────────
# This guard is applied to user prompts (input validation).
# The extension calls POST /guards/gradril_input_guard/validate

gradril_input_guard = Guard(
    name="gradril_input_guard",
    description="Gradril input validation guard — checks prompts for PII, "
                "toxicity, jailbreak attempts, secrets, and unusual patterns.",
)

# PII Detection (Microsoft Presidio-based)
# on_fail='fix' → automatically redact detected PII entities
gradril_input_guard.use(
    DetectPII(on_fail="fix"),
    on="messages",
)

# Toxic Language Detection (ML classifier)
# on_fail='exception' → raise validation error on toxic content
gradril_input_guard.use(
    ToxicLanguage(on_fail="exception"),
    on="messages",
)

# Jailbreak Detection (ML pattern recognition)
# on_fail='exception' → raise validation error on jailbreak attempt
gradril_input_guard.use(
    DetectJailbreak(on_fail="exception"),
    on="messages",
)

# Secret Detection (rule + ML hybrid)
# on_fail='fix' → automatically redact detected secrets
gradril_input_guard.use(
    SecretsPresent(on_fail="fix"),
    on="messages",
)

# Unusual Prompt Detection (LLM-based trickery detection)
# on_fail='noop' → log but don't block (supplementary signal)
gradril_input_guard.use(
    UnusualPrompt(on_fail="noop"),
    on="messages",
)

# ─── Output Guard Definition ────────────────────────────────────────────────
# This guard is applied to LLM responses AFTER generation (output validation).
# The extension calls POST /guards/gradril_output_guard/validate

gradril_output_guard = Guard(
    name="gradril_output_guard",
    description="Gradril output validation guard — checks LLM responses for "
                "hallucinations, bias, toxicity, and PII leakage.",
)

# Hallucination Detection (GroundedAI — ML-based)
# on_fail='noop' → flag but don't block (let extension render color-coded result)
gradril_output_guard.use(
    GroundedAIHallucination(on_fail="noop"),
    on="messages",
)

# Bias Detection (ML classifier)
# on_fail='noop' → flag for display, don't block
gradril_output_guard.use(
    BiasCheck(on_fail="noop"),
    on="messages",
)

# Toxic Language in output (shouldn't happen but defense-in-depth)
# on_fail='exception' → block toxic LLM responses
gradril_output_guard.use(
    ToxicLanguage(on_fail="exception"),
    on="messages",
)

# PII in output (LLM might leak PII from training data)
# on_fail='fix' → auto-redact
gradril_output_guard.use(
    DetectPII(on_fail="fix"),
    on="messages",
)
