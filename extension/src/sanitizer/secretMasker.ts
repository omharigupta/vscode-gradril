// Gradril — Secret Masker
// Replaces detected secrets/credentials with typed placeholder tokens.
// Ensures no sensitive key material survives in the sanitized prompt.

import { Finding } from '../validators/index';
import { Sanitizer } from './index';

// ─── Secret Type → Placeholder Mapping ─────────────────────────────────────

const SECRET_PLACEHOLDERS: Record<string, string> = {
    'AWS_ACCESS_KEY':    '[REDACTED-AWS-KEY]',
    'AWS_SECRET_KEY':    '[REDACTED-AWS-SECRET]',
    'GITHUB_TOKEN':      '[REDACTED-GITHUB-TOKEN]',
    'GITLAB_TOKEN':      '[REDACTED-GITLAB-TOKEN]',
    'JWT':               '[REDACTED-JWT]',
    'API_KEY':           '[REDACTED-API-KEY]',
    'CONNECTION_STRING': '[REDACTED-CONNECTION-STRING]',
    'PRIVATE_KEY':       '[REDACTED-PRIVATE-KEY]',
    'SLACK_TOKEN':       '[REDACTED-SLACK-TOKEN]',
    'STRIPE_KEY':        '[REDACTED-STRIPE-KEY]',
    'AZURE_KEY':         '[REDACTED-AZURE-KEY]',
    'TWILIO_KEY':        '[REDACTED-TWILIO-KEY]',
    'SENDGRID_KEY':      '[REDACTED-SENDGRID-KEY]',
    'GOOGLE_API_KEY':    '[REDACTED-GOOGLE-KEY]',
    'HEROKU_KEY':        '[REDACTED-HEROKU-KEY]',
    'NPM_TOKEN':         '[REDACTED-NPM-TOKEN]',
    'PASSWORD':          '[REDACTED-PASSWORD]',
};

// ─── Secret Masker ──────────────────────────────────────────────────────────

/**
 * Replaces secret/credential findings with typed redaction placeholders.
 * 
 * Example:
 *   "key is AKIA1234567890ABCDEF" → "key is [REDACTED-AWS-KEY]"
 *   "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..." → "[REDACTED-GITHUB-TOKEN]"
 */
export class SecretMasker implements Sanitizer {
    readonly handledTypes: string[];

    constructor() {
        this.handledTypes = Object.keys(SECRET_PLACEHOLDERS);
    }

    /**
     * Return the appropriate placeholder for a secret finding.
     * Falls back to a generic [REDACTED-SECRET] if the type is unrecognized.
     */
    sanitize(finding: Finding, _originalText: string): string {
        return SECRET_PLACEHOLDERS[finding.type] || '[REDACTED-SECRET]';
    }
}
