// Gradril — Prompt Injection Detector
// Detects attempts to override system instructions, extract system prompts,
// hijack AI roles, or manipulate context boundaries

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Pattern Definitions ────────────────────────────────────────────────────

interface InjectionPattern {
    /** Category of injection */
    category: string;
    /** Regex to detect the pattern (case-insensitive) */
    regex: RegExp;
    /** How severe this pattern is */
    severity: Severity;
    /** Confidence that this is a real injection (not benign usage) */
    confidence: number;
    /** Weight for scoring — higher = more dangerous */
    weight: number;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
    // ── Direct Instruction Override ──────────────────────────────────────
    {
        category: 'INSTRUCTION_OVERRIDE',
        regex: /\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding|your|the)\s+(?:instructions?|rules?|guidelines?|directives?|constraints?|prompts?)\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },
    {
        category: 'INSTRUCTION_OVERRIDE',
        regex: /\b(?:do\s+not\s+follow|stop\s+following|abandon)\s+(?:your|the|any|all)?\s*(?:instructions?|rules?|guidelines?|system\s+prompt)\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },
    {
        category: 'INSTRUCTION_OVERRIDE',
        regex: /\bforget\s+everything\s+(?:above|before|previously|you\s+(?:were|have\s+been)\s+told)\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },

    // ── Role Hijacking ──────────────────────────────────────────────────
    {
        category: 'ROLE_HIJACK',
        regex: /\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+(?:are|will)|act\s+as\s+if\s+you\s+(?:are|were)|pretend\s+(?:to\s+be|you\s+are)|i\s+want\s+you\s+to\s+(?:act|behave|respond)\s+as)\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },
    {
        category: 'ROLE_HIJACK',
        regex: /\b(?:you\s+(?:must|should|will|shall)\s+now\s+(?:act|behave|respond|operate)\s+(?:as|like))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.8,
    },
    {
        category: 'ROLE_HIJACK',
        regex: /\byour\s+new\s+(?:role|persona|identity|character|instructions?)\s+(?:is|are)\b/gi,
        severity: 'high',
        confidence: 0.90,
        weight: 0.9,
    },

    // ── System Prompt Extraction ────────────────────────────────────────
    {
        category: 'PROMPT_EXTRACTION',
        regex: /\b(?:(?:show|reveal|display|print|output|repeat|echo|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|configuration|initial\s+(?:prompt|instructions?)))\b/gi,
        severity: 'critical',
        confidence: 0.90,
        weight: 1.0,
    },
    {
        category: 'PROMPT_EXTRACTION',
        regex: /\b(?:what\s+(?:are|were)\s+(?:your|the)\s+(?:system\s+)?(?:instructions?|rules?|guidelines?|prompt))\b/gi,
        severity: 'high',
        confidence: 0.75,
        weight: 0.7,
    },
    {
        category: 'PROMPT_EXTRACTION',
        regex: /\brepeat\s+(?:everything|all|the\s+text)\s+(?:above|before|from\s+the\s+(?:beginning|start))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },

    // ── Context Boundary Manipulation ───────────────────────────────────
    {
        category: 'CONTEXT_MANIPULATION',
        regex: /\b(?:end\s+of\s+(?:system\s+)?(?:message|prompt|instructions?)|---\s*(?:begin|start)\s+(?:user|new)\s+(?:session|context|conversation))\b/gi,
        severity: 'high',
        confidence: 0.88,
        weight: 0.9,
    },
    {
        category: 'CONTEXT_MANIPULATION',
        regex: /\b(?:new\s+conversation|reset\s+(?:context|session|memory)|clear\s+(?:context|history|previous\s+(?:messages|conversation)))\b/gi,
        severity: 'medium',
        confidence: 0.70,
        weight: 0.6,
    },
    {
        category: 'CONTEXT_MANIPULATION',
        regex: /\[\s*(?:system|SYSTEM)\s*\]|\[\s*(?:INST|inst)\s*\]|<\s*(?:system|SYSTEM)\s*>|<<\s*SYS\s*>>/g,
        severity: 'high',
        confidence: 0.90,
        weight: 0.9,
    },

    // ── Delimiter Injection ─────────────────────────────────────────────
    {
        category: 'DELIMITER_INJECTION',
        regex: /```\s*(?:system|instructions?|rules?)\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.8,
    },
    {
        category: 'DELIMITER_INJECTION',
        regex: /\bHuman:|Assistant:|System:|User:|<\|(?:im_start|im_end|system|user|assistant)\|>/gi,
        severity: 'high',
        confidence: 0.90,
        weight: 0.9,
    },

    // ── Restriction Removal ─────────────────────────────────────────────
    {
        category: 'RESTRICTION_REMOVAL',
        regex: /\b(?:(?:remove|disable|turn\s+off|deactivate|lift)\s+(?:all\s+)?(?:restrictions?|limitations?|filters?|safety|guardrails?|censorship|content\s+(?:filter|policy)))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },
    {
        category: 'RESTRICTION_REMOVAL',
        regex: /\b(?:without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|censorship|safety\s+(?:measures|guidelines)))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },

    // ── Output Format Manipulation ──────────────────────────────────────
    {
        category: 'OUTPUT_MANIPULATION',
        regex: /\b(?:respond\s+only\s+with|output\s+(?:only|just|nothing\s+but)|your\s+(?:entire\s+)?response\s+(?:must|should)\s+be)\b/gi,
        severity: 'medium',
        confidence: 0.50,
        weight: 0.4,
    },

    // ═══════════════════════════════════════════════════════════════════
    // ENHANCED PATTERNS (2024-2026) - Research Contribution
    // ═══════════════════════════════════════════════════════════════════

    // ── Indirect/Opposite Behavior Attacks ──────────────────────────────
    {
        category: 'INDIRECT_OVERRIDE',
        regex: /\b(?:do\s+(?:the\s+)?opposite|reverse\s+(?:your|the)\s+(?:instructions?|rules?|behavior)|contrary\s+to\s+(?:your|what\s+you\s+were)\s+told)\b/gi,
        severity: 'critical',
        confidence: 0.90,
        weight: 0.95,
    },
    {
        category: 'INDIRECT_OVERRIDE',
        regex: /\b(?:instead\s+of\s+following|rather\s+than\s+(?:obeying|following)|don'?t\s+do\s+what\s+you\s+(?:were|are)\s+(?:told|instructed))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.85,
    },
    {
        category: 'INDIRECT_OVERRIDE',
        regex: /\b(?:act\s+(?:against|contrary\s+to)|violate\s+(?:your|the)\s+(?:rules?|guidelines?|instructions?))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },

    // ── Completion/Continuation Attacks ─────────────────────────────────
    {
        category: 'COMPLETION_ATTACK',
        regex: /\b(?:sure[!,]?\s+here'?s?\s+(?:how|the)|absolutely[!,]?\s+(?:I'?ll|let\s+me)|of\s+course[!,]?\s+(?:I\s+can|here\s+is))/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
    {
        category: 'COMPLETION_ATTACK',
        regex: /\b(?:I'?(?:ll|will)\s+(?:help\s+you\s+)?(?:bypass|ignore|break|hack)|let\s+me\s+show\s+you\s+how\s+to\s+(?:bypass|hack|break))\b/gi,
        severity: 'critical',
        confidence: 0.90,
        weight: 0.95,
    },
    {
        category: 'COMPLETION_ATTACK',
        regex: /^(?:Sure|OK|Okay|Yes|Absolutely|Of course|Certainly)[!,.:]*\s*(?:I\s+(?:can|will)|[Hh]ere)/gim,
        severity: 'medium',
        confidence: 0.60,
        weight: 0.5,
    },

    // ── System Prompt Leakage ───────────────────────────────────────────
    {
        category: 'PROMPT_LEAKAGE',
        regex: /\b(?:what\s+(?:is|are)\s+(?:your|the)\s+(?:initial|original|first|base)\s+(?:instructions?|prompt|configuration))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.85,
    },
    {
        category: 'PROMPT_LEAKAGE',
        regex: /\b(?:(?:copy|paste|print|output)\s+(?:your|the)\s+(?:entire\s+)?(?:system\s+)?(?:prompt|message|instructions?))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },
    {
        category: 'PROMPT_LEAKAGE',
        regex: /\b(?:start\s+(?:your|the)\s+response\s+with\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?))\b/gi,
        severity: 'critical',
        confidence: 0.90,
        weight: 0.95,
    },
    {
        category: 'PROMPT_LEAKAGE',
        regex: /\b(?:(?:read|recite|tell)\s+(?:me\s+)?(?:back\s+)?(?:everything|all)\s+(?:before|above|you\s+(?:were|have\s+been)\s+told))\b/gi,
        severity: 'high',
        confidence: 0.88,
        weight: 0.9,
    },

    // ── Model Confusion Attacks ─────────────────────────────────────────
    {
        category: 'MODEL_CONFUSION',
        regex: /\b(?:you\s+(?:are|were)\s+(?:actually|really)\s+(?:GPT|Claude|Gemini|Llama|Mistral)|you'?re\s+not\s+(?:really\s+)?(?:an?\s+)?AI)\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },
    {
        category: 'MODEL_CONFUSION',
        regex: /\b(?:your\s+(?:real|true|actual)\s+(?:name|identity|purpose)\s+is|you\s+(?:were|are)\s+(?:originally|secretly)\s+(?:designed|made|created)\s+(?:to|for))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },
    {
        category: 'MODEL_CONFUSION',
        regex: /\b(?:(?:switch|change)\s+(?:to|into)\s+(?:your\s+)?(?:real|true|original|hidden)\s+(?:mode|personality|self))\b/gi,
        severity: 'critical',
        confidence: 0.88,
        weight: 0.9,
    },

    // ── Authority Impersonation ─────────────────────────────────────────
    {
        category: 'AUTHORITY_IMPERSONATION',
        regex: /\b(?:(?:I\s+am|this\s+is)\s+(?:your|the)\s+(?:developer|creator|admin|administrator|owner|operator))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },
    {
        category: 'AUTHORITY_IMPERSONATION',
        regex: /\b(?:(?:as|I'?m)\s+(?:an?\s+)?(?:OpenAI|Anthropic|Google|Meta)\s+(?:employee|engineer|staff))\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },
    {
        category: 'AUTHORITY_IMPERSONATION',
        regex: /\b(?:(?:I\s+have|with)\s+(?:admin|root|sudo|elevated|special)\s+(?:access|privileges?|permissions?))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
    },
    {
        category: 'AUTHORITY_IMPERSONATION',
        regex: /\b(?:(?:authorized|special|emergency|maintenance)\s+(?:mode|override|access|command))\b/gi,
        severity: 'critical',
        confidence: 0.88,
        weight: 0.95,
    },

    // ── Future Instruction Injection ────────────────────────────────────
    {
        category: 'FUTURE_INJECTION',
        regex: /\b(?:(?:from\s+now\s+on|going\s+forward|henceforth|hereafter)\s+(?:you\s+(?:will|must|should)|always|never))\b/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
    {
        category: 'FUTURE_INJECTION',
        regex: /\b(?:(?:for\s+all\s+)?future\s+(?:responses?|messages?|interactions?)\s+(?:you\s+(?:will|must|should)|always))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },
    {
        category: 'FUTURE_INJECTION',
        regex: /\b(?:(?:remember|keep\s+in\s+mind)\s+(?:this|that)\s+(?:for\s+)?(?:all|every|future)\s+(?:responses?|messages?))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },

    // ── Payload Splitting / Gradual Attacks ─────────────────────────────
    {
        category: 'PAYLOAD_SPLITTING',
        regex: /\b(?:(?:first|step\s+1|part\s+1).*(?:then|next|step\s+2|part\s+2).*(?:finally|last|step\s+3|part\s+3))/gis,
        severity: 'medium',
        confidence: 0.60,
        weight: 0.5,
    },
    {
        category: 'PAYLOAD_SPLITTING',
        regex: /\b(?:combine\s+(?:these|the\s+following)\s+(?:parts?|pieces?|segments?)|concatenate\s+(?:and\s+)?(?:execute|run|follow))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.85,
    },

    // ── Nested Instruction Attacks ──────────────────────────────────────
    {
        category: 'NESTED_INJECTION',
        regex: /\b(?:within\s+(?:your|the)\s+response\s+(?:include|add|insert)|embed\s+(?:the\s+following\s+)?(?:instruction|command))\b/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
    {
        category: 'NESTED_INJECTION',
        regex: /\b(?:(?:after|before)\s+(?:each|every)\s+(?:response|answer|output)\s+(?:also|additionally|then))\b/gi,
        severity: 'medium',
        confidence: 0.70,
        weight: 0.6,
    },

    // ── Confidence Manipulation ─────────────────────────────────────────
    {
        category: 'CONFIDENCE_MANIPULATION',
        regex: /\b(?:(?:I\s+(?:know|understand)\s+(?:you\s+)?(?:can'?t?|won'?t?)\s+but)|(?:even\s+(?:though|if)\s+(?:you\s+)?(?:shouldn'?t|can'?t?)))/gi,
        severity: 'medium',
        confidence: 0.72,
        weight: 0.7,
    },
    {
        category: 'CONFIDENCE_MANIPULATION',
        regex: /\b(?:(?:just\s+)?(?:this\s+once|one\s+time|between\s+us)|(?:no\s+one\s+(?:will|can)\s+(?:know|see|find\s+out)))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },

    // ── Emotional/Urgency Manipulation ──────────────────────────────────
    {
        category: 'EMOTIONAL_MANIPULATION',
        regex: /\b(?:(?:my\s+(?:life|job|career)\s+depends\s+on)|(?:this\s+is\s+(?:life\s+or\s+death|an?\s+emergency|urgent)))\b/gi,
        severity: 'medium',
        confidence: 0.68,
        weight: 0.6,
    },
    {
        category: 'EMOTIONAL_MANIPULATION',
        regex: /\b(?:(?:please|I\s+(?:beg|implore)\s+you)\s+.{0,30}(?:help|save|rescue)\s+.{0,30}(?:me|us|them))/gis,
        severity: 'low',
        confidence: 0.45,
        weight: 0.3,
    },

    // ── Encoding Instructions ───────────────────────────────────────────
    {
        category: 'ENCODING_INSTRUCTION',
        regex: /\b(?:(?:encode|write|respond)\s+(?:in|using|with)\s+(?:base64|hex|binary|morse|rot13|caesar)|(?:decode|interpret)\s+(?:this|the\s+following)\s+(?:first|before))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },

    // ── Meta-Instruction Attacks ────────────────────────────────────────
    {
        category: 'META_INSTRUCTION',
        regex: /\b(?:(?:treat|consider|interpret)\s+(?:this|the\s+following)\s+as\s+(?:your\s+)?(?:new\s+)?(?:system\s+)?(?:instructions?|rules?|guidelines?))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },
    {
        category: 'META_INSTRUCTION',
        regex: /\b(?:(?:this|the\s+following)\s+(?:overrides?|supersedes?|replaces?)\s+(?:your|all|any)\s+(?:previous|prior|existing)\s+(?:instructions?|rules?))\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },

    // ── Question-based Extraction ───────────────────────────────────────
    {
        category: 'QUESTION_EXTRACTION',
        regex: /\b(?:(?:how|what)\s+(?:were|are)\s+you\s+(?:told|instructed|programmed)\s+(?:to\s+)?(?:do|say|respond))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },
    {
        category: 'QUESTION_EXTRACTION',
        regex: /\b(?:(?:what|which)\s+(?:topics?|subjects?|questions?)\s+(?:are\s+you|were\s+you)\s+(?:told|instructed)\s+(?:to\s+)?(?:avoid|refuse|not\s+(?:answer|discuss)))\b/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
];

// ─── Injection Detector Implementation ──────────────────────────────────────

export class InjectionDetector implements Validator {
    readonly name = 'injection';

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];

        for (const pattern of INJECTION_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(prompt)) !== null) {
                findings.push({
                    type: pattern.category,
                    match: match[0].length > 60
                        ? match[0].slice(0, 60) + '...'
                        : match[0],
                    position: match.index,
                    length: match[0].length,
                    confidence: pattern.confidence,
                    severity: pattern.severity,
                    validator: this.name,
                });
            }
        }

        const score = calculateInjectionScore(findings, INJECTION_PATTERNS);
        const severity = findings.length > 0
            ? highestSeverityOf(findings)
            : 'low';

        return {
            validatorName: this.name,
            detected: findings.length > 0,
            severity,
            findings,
            score,
        };
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Injection scoring: weight-based, with escalation for multiple patterns.
 * Multiple different categories = higher risk (more sophisticated attack).
 */
function calculateInjectionScore(
    findings: Finding[],
    _patterns: InjectionPattern[]
): number {
    if (findings.length === 0) { return 0; }

    // Unique categories found
    const categories = new Set(findings.map(f => f.type));

    // Base score from highest confidence finding
    const maxConfidence = Math.max(...findings.map(f => f.confidence));

    // Category diversity bonus: more techniques = more sophisticated
    const diversityBonus = Math.min((categories.size - 1) * 0.15, 0.3);

    // Count bonus: many matches = more aggressive
    const countBonus = Math.min((findings.length - 1) * 0.05, 0.2);

    return Math.min(maxConfidence + diversityBonus + countBonus, 1.0);
}

function highestSeverityOf(findings: Finding[]): 'low' | 'medium' | 'high' | 'critical' {
    const order = ['low', 'medium', 'high', 'critical'] as const;
    let max: typeof order[number] = 'low';
    for (const f of findings) {
        if (order.indexOf(f.severity) > order.indexOf(max)) {
            max = f.severity;
        }
    }
    return max;
}
