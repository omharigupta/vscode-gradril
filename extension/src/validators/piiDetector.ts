// Gradril — PII Detector
// Detects personally identifiable information: SSN, email, phone, credit card, IP, passport, DOB

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Pattern Definitions ────────────────────────────────────────────────────

interface PIIPattern {
    type: string;
    regex: RegExp;
    severity: Severity;
    confidence: number;
    /** Optional post-match validation function */
    postValidate?: (match: string) => boolean;
}

const PII_PATTERNS: PIIPattern[] = [
    // SSN: 123-45-6789 or 123 45 6789
    {
        type: 'SSN',
        regex: /\b(\d{3}[-\s]\d{2}[-\s]\d{4})\b/g,
        severity: 'critical',
        confidence: 0.95,
    },
    // Email addresses
    {
        type: 'EMAIL',
        regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
        severity: 'medium',
        confidence: 0.95,
    },
    // US phone: (555) 123-4567, 555-123-4567, 555.123.4567, 5551234567
    {
        type: 'PHONE',
        regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
        severity: 'medium',
        confidence: 0.80,
        postValidate: (match: string) => {
            // Filter out numbers that look like versions, IPs, or dates
            const digits = match.replace(/\D/g, '');
            return digits.length >= 10 && digits.length <= 11;
        },
    },
    // International phone: +44 20 7946 0958, +91-9876543210
    {
        type: 'PHONE_INTL',
        regex: /\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g,
        severity: 'medium',
        confidence: 0.85,
    },
    // Credit card: 4111-1111-1111-1111 or spaces or continuous
    {
        type: 'CREDIT_CARD',
        regex: /\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g,
        severity: 'critical',
        confidence: 0.90,
        postValidate: luhnCheck,
    },
    // IPv4 addresses
    {
        type: 'IP_ADDRESS',
        regex: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
        severity: 'low',
        confidence: 0.70,
        postValidate: (match: string) => {
            // Validate each octet is 0-255
            const parts = match.split('.');
            return parts.every(p => {
                const n = parseInt(p, 10);
                return n >= 0 && n <= 255;
            });
        },
    },
    // US Passport: 1 letter + 8 digits or 9 digits
    {
        type: 'PASSPORT',
        regex: /\b[A-Z]\d{8}\b/g,
        severity: 'high',
        confidence: 0.60,
    },
    // Date of Birth patterns: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD
    {
        type: 'DOB',
        regex: /\b(?:0[1-9]|1[0-2])[\/\-](0[1-9]|[12]\d|3[01])[\/\-](19|20)\d{2}\b/g,
        severity: 'medium',
        confidence: 0.65,
    },
    {
        type: 'DOB',
        regex: /\b(19|20)\d{2}[\/\-](0[1-9]|1[0-2])[\/\-](0[1-9]|[12]\d|3[01])\b/g,
        severity: 'medium',
        confidence: 0.65,
    },
];

// ─── Luhn Algorithm for Credit Card Validation ──────────────────────────────

function luhnCheck(cardNumber: string): boolean {
    const digits = cardNumber.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) { return false; }

    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = parseInt(digits[i], 10);
        if (alternate) {
            n *= 2;
            if (n > 9) { n -= 9; }
        }
        sum += n;
        alternate = !alternate;
    }
    return sum % 10 === 0;
}

// ─── PII Detector Implementation ───────────────────────────────────────────

export class PIIDetector implements Validator {
    readonly name = 'pii';

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];

        for (const pattern of PII_PATTERNS) {
            // Reset regex state for global patterns
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(prompt)) !== null) {
                const matchText = match[0];

                // Run post-validation if defined
                if (pattern.postValidate && !pattern.postValidate(matchText)) {
                    continue;
                }

                findings.push({
                    type: pattern.type,
                    match: maskForDisplay(matchText, pattern.type),
                    position: match.index,
                    length: matchText.length,
                    confidence: pattern.confidence,
                    severity: pattern.severity,
                    validator: this.name,
                });
            }
        }

        const score = calculateScore(findings);
        const severity = findings.length > 0
            ? highestSeverity(findings)
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
 * Mask the matched text for display/logging (never expose full PII).
 */
function maskForDisplay(text: string, type: string): string {
    switch (type) {
        case 'SSN':
            return text.slice(0, 3) + '-**-' + text.slice(-4);
        case 'EMAIL': {
            const parts = text.split('@');
            const local = parts[0];
            const domain = parts[1] || '';
            return local.slice(0, 2) + '***@' + domain;
        }
        case 'CREDIT_CARD': {
            const digits = text.replace(/\D/g, '');
            return digits.slice(0, 4) + '-****-****-' + digits.slice(-4);
        }
        case 'PHONE':
        case 'PHONE_INTL':
            return text.slice(0, 3) + '****' + text.slice(-3);
        default:
            if (text.length > 6) {
                return text.slice(0, 3) + '***' + text.slice(-2);
            }
            return '***';
    }
}

function highestSeverity(findings: Finding[]): 'low' | 'medium' | 'high' | 'critical' {
    const order = ['low', 'medium', 'high', 'critical'] as const;
    let max: typeof order[number] = 'low';
    for (const f of findings) {
        if (order.indexOf(f.severity) > order.indexOf(max)) {
            max = f.severity;
        }
    }
    return max;
}

/**
 * Calculate a 0-1 risk score based on findings.
 * More findings and higher severity = higher score.
 */
function calculateScore(findings: Finding[]): number {
    if (findings.length === 0) { return 0; }

    const severityWeight: Record<string, number> = {
        'low': 0.2,
        'medium': 0.5,
        'high': 0.8,
        'critical': 1.0,
    };

    let totalWeight = 0;
    for (const f of findings) {
        totalWeight += (severityWeight[f.severity] || 0.5) * f.confidence;
    }

    // Normalize: 1 critical finding → ~1.0, 1 low finding → ~0.2
    // Cap at 1.0, scale by count (diminishing returns)
    const raw = totalWeight / Math.max(findings.length, 1);
    const countBoost = Math.min(findings.length * 0.1, 0.3); // Up to +0.3 for many findings
    return Math.min(raw + countBoost, 1.0);
}
