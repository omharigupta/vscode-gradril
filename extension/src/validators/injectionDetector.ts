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
