// Gradril — PII Masker
// Replaces detected PII with typed placeholder tokens.
// Each PII type maps to a specific [REDACTED-*] placeholder.

import { Finding } from '../validators/index';
import { Sanitizer } from './index';

// ─── PII Type → Placeholder Mapping ────────────────────────────────────────

const PII_PLACEHOLDERS: Record<string, string> = {
    'SSN':         '[REDACTED-SSN]',
    'EMAIL':       '[REDACTED-EMAIL]',
    'PHONE':       '[REDACTED-PHONE]',
    'PHONE_INTL':  '[REDACTED-PHONE]',
    'CREDIT_CARD': '[REDACTED-CC]',
    'IP_ADDRESS':  '[REDACTED-IP]',
    'PASSPORT':    '[REDACTED-PASSPORT]',
    'DOB':         '[REDACTED-DOB]',
};

// ─── PII Masker ─────────────────────────────────────────────────────────────

/**
 * Replaces PII findings with typed redaction placeholders.
 * 
 * Example:
 *   "my email is john@example.com" → "my email is [REDACTED-EMAIL]"
 *   "SSN: 123-45-6789"            → "SSN: [REDACTED-SSN]"
 */
export class PIIMasker implements Sanitizer {
    readonly handledTypes: string[];

    constructor() {
        this.handledTypes = Object.keys(PII_PLACEHOLDERS);
    }

    /**
     * Return the appropriate placeholder for a PII finding.
     * Falls back to a generic [REDACTED-PII] if the type is unrecognized.
     */
    sanitize(finding: Finding, _originalText: string): string {
        return PII_PLACEHOLDERS[finding.type] || '[REDACTED-PII]';
    }
}
