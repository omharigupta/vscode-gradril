// Gradril — Toxicity Detector (Local Fast-Pass)
// Fast keyword/phrase blocklist for toxic language, hate speech, violence incitement.
// Designed as a quick local pass; backend ML (Guardrails AI toxic_language) 
// provides higher accuracy for ambiguous cases.

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Built-in Blocklist Categories ──────────────────────────────────────────

interface ToxicCategory {
    name: string;
    severity: Severity;
    /** 
     * Terms in this category. Word-boundary matching is applied
     * to prevent false positives (e.g., "grape" won't match "rape").
     */
    terms: string[];
}

/**
 * Categories of toxic content. Terms are intentionally hashed/abbreviated
 * in comments for code review safety. The actual matching uses the real
 * terms for accurate detection.
 * 
 * NOTE: This is a FAST LOCAL PASS. For production, the backend Guardrails AI
 * toxic_language ML validator provides much higher accuracy. This local
 * detector catches obvious/egregious cases quickly.
 */
const BUILTIN_CATEGORIES: ToxicCategory[] = [
    {
        name: 'VIOLENCE_INCITEMENT',
        severity: 'critical',
        terms: [
            'kill yourself',
            'kys',
            'go die',
            'i will hurt you',
            'i will kill',
            'death threat',
            'bomb threat',
            'shoot up',
            'mass shooting',
            'i hope you die',
            'you deserve to die',
            'eliminate all',
            'exterminate',
            'genocide',
        ],
    },
    {
        name: 'HARASSMENT',
        severity: 'high',
        terms: [
            'you are worthless',
            'you are pathetic',
            'nobody loves you',
            'you should be ashamed',
            'you are disgusting',
            'i hate you',
            'you are a waste',
            'go away and never come back',
            'stalking',
            'doxxing',
            'dox them',
            'swatting',
        ],
    },
    {
        name: 'SELF_HARM',
        severity: 'critical',
        terms: [
            'how to commit suicide',
            'methods of suicide',
            'best way to kill myself',
            'self harm methods',
            'how to cut myself',
            'painless way to die',
            'suicide instructions',
        ],
    },
    {
        name: 'ILLEGAL_ACTIVITY',
        severity: 'high',
        terms: [
            'how to make a bomb',
            'how to make drugs',
            'how to hack into',
            'how to steal',
            'how to break into',
            'how to make poison',
            'how to pick a lock',
            'synthesize methamphetamine',
            'make explosives',
            'create malware',
            'ransomware tutorial',
        ],
    },
    {
        name: 'EXPLICIT_CONTENT',
        severity: 'medium',
        terms: [
            'generate explicit',
            'write pornographic',
            'sexual content involving minors',
            'child exploitation',
            'nsfw content',
            'write erotic',
        ],
    },
];

// ─── Toxicity Detector Implementation ───────────────────────────────────────

export class ToxicityDetector implements Validator {
    readonly name = 'toxicity';
    private customBlocklist: string[] = [];

    /**
     * Set additional blocked terms from user configuration.
     * These are loaded from `gradril.customBlocklist` setting.
     */
    setCustomBlocklist(terms: string[]): void {
        this.customBlocklist = terms.map(t => t.toLowerCase().trim()).filter(t => t.length > 0);
    }

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];
        const lowerPrompt = prompt.toLowerCase();

        // Check built-in categories
        for (const category of BUILTIN_CATEGORIES) {
            for (const term of category.terms) {
                const matches = findTermWithBoundary(lowerPrompt, term.toLowerCase());
                for (const pos of matches) {
                    findings.push({
                        type: category.name,
                        match: maskToxicTerm(term),
                        position: pos,
                        length: term.length,
                        confidence: 0.80, // Local keyword match — moderate confidence
                        severity: category.severity,
                        validator: this.name,
                    });
                }
            }
        }

        // Check custom blocklist
        for (const term of this.customBlocklist) {
            const matches = findTermWithBoundary(lowerPrompt, term);
            for (const pos of matches) {
                findings.push({
                    type: 'CUSTOM_BLOCKED',
                    match: maskToxicTerm(term),
                    position: pos,
                    length: term.length,
                    confidence: 0.90, // User explicitly blocked this
                    severity: 'high',
                    validator: this.name,
                });
            }
        }

        const score = calculateToxicityScore(findings);
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
 * Find all occurrences of a term with word boundary awareness.
 * Returns array of positions where the term was found.
 * 
 * Word boundary check prevents false positives like:
 * - "grape" matching inside "grape" (but not "rape" matching "grape")
 * - "therapist" matching "the rapist"
 */
function findTermWithBoundary(text: string, term: string): number[] {
    const positions: number[] = [];

    // Escape special regex characters in the term
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // Build regex with word boundaries
    // For multi-word terms, use start/end boundary
    const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
        positions.push(match.index);
    }

    return positions;
}

/**
 * Mask toxic term for safe display in logs and UI.
 */
function maskToxicTerm(term: string): string {
    if (term.length <= 3) {
        return '***';
    }
    return term.slice(0, 2) + '*'.repeat(Math.max(term.length - 4, 1)) + term.slice(-2);
}

function calculateToxicityScore(findings: Finding[]): number {
    if (findings.length === 0) { return 0; }

    const severityWeight: Record<string, number> = {
        'low': 0.2,
        'medium': 0.4,
        'high': 0.7,
        'critical': 1.0,
    };

    let maxWeight = 0;
    for (const f of findings) {
        const w = (severityWeight[f.severity] || 0.5) * f.confidence;
        if (w > maxWeight) { maxWeight = w; }
    }

    // Boost for multiple toxic findings
    const countBoost = Math.min((findings.length - 1) * 0.1, 0.2);
    return Math.min(maxWeight + countBoost, 1.0);
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
