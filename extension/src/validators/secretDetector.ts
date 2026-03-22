// Gradril — Secret Detector
// Detects API keys, tokens, credentials, connection strings, private keys

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Pattern Definitions ────────────────────────────────────────────────────

interface SecretPattern {
    type: string;
    regex: RegExp;
    severity: Severity;
    confidence: number;
    /** Human-readable label */
    label: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
    // AWS Access Key ID
    {
        type: 'AWS_ACCESS_KEY',
        regex: /\b(AKIA[0-9A-Z]{16})\b/g,
        severity: 'critical',
        confidence: 0.98,
        label: 'AWS Access Key',
    },
    // AWS Secret Access Key (40 chars base64-like following a key context)
    {
        type: 'AWS_SECRET_KEY',
        regex: /(?:aws_secret_access_key|secret_?key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        severity: 'critical',
        confidence: 0.90,
        label: 'AWS Secret Key',
    },
    // GitHub Personal Access Tokens (classic)
    {
        type: 'GITHUB_TOKEN',
        regex: /\b(ghp_[a-zA-Z0-9]{36})\b/g,
        severity: 'critical',
        confidence: 0.99,
        label: 'GitHub Personal Access Token',
    },
    // GitHub Fine-grained PATs
    {
        type: 'GITHUB_TOKEN',
        regex: /\b(github_pat_[a-zA-Z0-9_]{82})\b/g,
        severity: 'critical',
        confidence: 0.99,
        label: 'GitHub Fine-grained PAT',
    },
    // GitHub OAuth / App tokens
    {
        type: 'GITHUB_TOKEN',
        regex: /\b(gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})\b/g,
        severity: 'critical',
        confidence: 0.98,
        label: 'GitHub OAuth/App Token',
    },
    // GitLab tokens
    {
        type: 'GITLAB_TOKEN',
        regex: /\b(glpat-[a-zA-Z0-9\-_]{20,})\b/g,
        severity: 'critical',
        confidence: 0.95,
        label: 'GitLab Personal Access Token',
    },
    // JSON Web Tokens (JWT)
    {
        type: 'JWT',
        regex: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
        severity: 'high',
        confidence: 0.95,
        label: 'JSON Web Token',
    },
    // Generic API key patterns (key=value, key: value)
    {
        type: 'API_KEY',
        regex: /(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
        severity: 'high',
        confidence: 0.75,
        label: 'Generic API Key',
    },
    // Database connection strings
    {
        type: 'CONNECTION_STRING',
        regex: /\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps|mssql):\/\/[^\s'"]{10,})\b/gi,
        severity: 'critical',
        confidence: 0.95,
        label: 'Database Connection String',
    },
    // Private keys (PEM format)
    {
        type: 'PRIVATE_KEY',
        regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----/g,
        severity: 'critical',
        confidence: 0.99,
        label: 'Private Key',
    },
    // Slack Bot / User tokens
    {
        type: 'SLACK_TOKEN',
        regex: /\b(xox[baprs]-[a-zA-Z0-9\-]{10,})\b/g,
        severity: 'critical',
        confidence: 0.95,
        label: 'Slack Token',
    },
    // Stripe API keys
    {
        type: 'STRIPE_KEY',
        regex: /\b((sk|pk|rk)_(test|live)_[a-zA-Z0-9]{24,})\b/g,
        severity: 'critical',
        confidence: 0.98,
        label: 'Stripe API Key',
    },
    // Azure Storage / Cognitive Services keys (base64-like, 86 chars + ==)
    {
        type: 'AZURE_KEY',
        regex: /(?:azure[_-]?(?:storage|key|secret|account))\s*[:=]\s*['"]?([a-zA-Z0-9/+]{86}==)['"]?/gi,
        severity: 'critical',
        confidence: 0.85,
        label: 'Azure Key',
    },
    // Twilio Account SID / Auth Token
    {
        type: 'TWILIO_KEY',
        regex: /\b(AC[a-f0-9]{32})\b/g,
        severity: 'high',
        confidence: 0.90,
        label: 'Twilio Account SID',
    },
    // SendGrid API key
    {
        type: 'SENDGRID_KEY',
        regex: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/g,
        severity: 'critical',
        confidence: 0.98,
        label: 'SendGrid API Key',
    },
    // Google API key
    {
        type: 'GOOGLE_API_KEY',
        regex: /\b(AIza[a-zA-Z0-9_-]{35})\b/g,
        severity: 'high',
        confidence: 0.92,
        label: 'Google API Key',
    },
    // Heroku API key
    {
        type: 'HEROKU_KEY',
        regex: /(?:heroku[_-]?api[_-]?key)\s*[:=]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
        severity: 'high',
        confidence: 0.88,
        label: 'Heroku API Key',
    },
    // npm tokens
    {
        type: 'NPM_TOKEN',
        regex: /\b(npm_[a-zA-Z0-9]{36})\b/g,
        severity: 'high',
        confidence: 0.95,
        label: 'npm Access Token',
    },
    // Password in URL or assignment
    {
        type: 'PASSWORD',
        regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/gi,
        severity: 'high',
        confidence: 0.70,
        label: 'Password',
    },
];

// ─── Secret Detector Implementation ────────────────────────────────────────

export class SecretDetector implements Validator {
    readonly name = 'secrets';

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];

        for (const pattern of SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(prompt)) !== null) {
                const matchText = match[1] || match[0]; // Prefer capture group
                const fullMatch = match[0];

                findings.push({
                    type: pattern.type,
                    match: maskSecret(matchText, pattern.type),
                    position: match.index,
                    length: fullMatch.length,
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
 * Mask secret for safe display — never log full secrets.
 */
function maskSecret(text: string, type: string): string {
    if (text.length <= 8) {
        return '***';
    }

    switch (type) {
        case 'AWS_ACCESS_KEY':
            return text.slice(0, 4) + '****' + text.slice(-4);
        case 'GITHUB_TOKEN':
            return text.slice(0, 4) + '****' + text.slice(-4);
        case 'JWT':
            return text.slice(0, 10) + '...[truncated]';
        case 'CONNECTION_STRING': {
            // Mask password in connection string
            const masked = text.replace(
                /(:\/\/)([^:]+):([^@]+)(@)/,
                '$1$2:****$4'
            );
            return masked.length > 30 ? masked.slice(0, 30) + '...' : masked;
        }
        case 'PRIVATE_KEY':
            return '-----BEGIN PRIVATE KEY----- [CONTENT REDACTED]';
        case 'PASSWORD':
            return '****';
        default:
            return text.slice(0, 4) + '****' + text.slice(-4);
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

    // Any secret is serious — minimum score 0.5 for one finding
    const base = Math.max(totalWeight / findings.length, 0.5);
    const countBoost = Math.min((findings.length - 1) * 0.1, 0.3);
    return Math.min(base + countBoost, 1.0);
}
