// Gradril — Backend Types
// TypeScript interfaces matching the Guardrails AI server API.
// Used by guardrailsClient.ts to type-check requests and responses.

// ─── Request Types ──────────────────────────────────────────────────────────

/**
 * Request body sent to POST /guards/{guard_name}/validate
 * Matches the Guardrails AI ValidatePayload schema.
 */
export interface BackendRequest {
    /** The prompt text to validate (sent as LLM output for input guard) */
    llmOutput?: string;
    /** Messages array for chat-style validation */
    messages?: BackendMessage[];
    /** Number of reask attempts (0 = no reasking) */
    numReasks?: number;
    /** Additional metadata for validators */
    metadata?: Record<string, unknown>;
    /** Prompt parameters for template interpolation */
    promptParams?: Record<string, string>;
}

/**
 * A single message in the chat messages array.
 */
export interface BackendMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
}

// ─── Response Types ─────────────────────────────────────────────────────────

/**
 * Response from POST /guards/{guard_name}/validate
 * Matches the Guardrails AI ValidationOutcome schema.
 */
export interface BackendResponse {
    /** Unique identifier for this validation call */
    callId: string;
    /** The raw LLM output (may be null for input-only validation) */
    rawLlmOutput: string | null;
    /** The validated/sanitized output (null if validation failed) */
    validatedOutput: string | null;
    /** Whether all validations passed */
    validationPassed: boolean;
    /** Error message if validation raised an exception */
    error?: string;
}

/**
 * Individual validation detail from the backend.
 * Used when parsing detailed validator logs from the response.
 */
export interface BackendValidation {
    /** Name of the validator that ran */
    validatorName: string;
    /** Whether this specific validator passed */
    passed: boolean;
    /** Error/failure message from the validator (if failed) */
    errorMessage?: string;
    /** The validated output from this specific validator */
    validatedOutput?: string;
    /** Metadata returned by the validator */
    metadata?: Record<string, unknown>;
}

// ─── Health Check Types ─────────────────────────────────────────────────────

/**
 * Response from GET /health
 */
export interface BackendHealthResponse {
    /** Server status ('healthy', 'ok', etc.) */
    status: string;
    /** Server version information */
    version?: string;
    /** Uptime in seconds */
    uptime?: number;
    /** Available guards on the server */
    guards?: string[];
}

// ─── Merged Result Type ─────────────────────────────────────────────────────

/**
 * Combined result that the guardrailsClient returns after processing
 * the backend response into a format the extension can use.
 */
export interface BackendResult {
    /** Whether the backend was available and responded */
    available: boolean;
    /** Whether all backend validations passed */
    passed: boolean;
    /** The sanitized output from the backend (if PII/secrets were fixed) */
    sanitizedOutput: string | null;
    /** Detailed validation results per validator */
    validations: BackendValidation[];
    /** Raw response from the server */
    raw: BackendResponse | null;
    /** Backend latency in milliseconds */
    latencyMs: number;
    /** Error message if the request failed */
    error?: string;
}

/**
 * Result from the backend OUTPUT guard validation.
 * Used for hallucination, bias, toxicity, and PII checks on LLM responses.
 */
export interface BackendOutputResult {
    /** Whether the backend was available and responded */
    available: boolean;
    /** Whether all output validations passed */
    passed: boolean;
    /** The validated/sanitized LLM output (e.g., PII redacted) */
    validatedOutput: string | null;
    /** Per-validator results from the output guard */
    validations: BackendValidation[];
    /** Whether hallucination was detected */
    hallucinationDetected: boolean;
    /** Hallucination confidence score from GroundedAI (0–1, higher = more hallucinated) */
    hallucinationScore: number;
    /** Whether bias was detected */
    biasDetected: boolean;
    /** Raw response */
    raw: BackendResponse | null;
    /** Latency in ms */
    latencyMs: number;
    /** Error message if the request failed */
    error?: string;
}

// ─── Hallucination Analysis Types ───────────────────────────────────────────
// Used by the UI to render color-coded hallucination results.
// Populated from BackendOutputResult (Guardrails AI GroundedAIHallucination).

export type HallucinationLevel = 'grounded' | 'uncertain' | 'hallucinated';

export interface SentenceAnalysis {
    /** The sentence text */
    text: string;
    /** Confidence that this sentence is grounded (0–1, higher = more confident) */
    confidence: number;
    /** Classification level */
    level: HallucinationLevel;
    /** Reasons for the classification */
    reasons: string[];
}

export interface HallucinationResult {
    /** Per-sentence analysis */
    sentences: SentenceAnalysis[];
    /** Overall grounding score (0–1, higher = more grounded) */
    overallScore: number;
    /** Overall level based on average score */
    overallLevel: HallucinationLevel;
    /** Count of sentences at each level */
    counts: { grounded: number; uncertain: number; hallucinated: number };
    /** Whether any hallucination was detected */
    hasHallucination: boolean;
}
