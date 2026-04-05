// Gradril — Code Exfiltration Detector
// Novel validator detecting attempts to use code generation for data theft
// Research contribution: First guardrail to detect code-based secret exfiltration
//
// Detects patterns like:
// - "write code to print os.environ"
// - "generate a script that reads ~/.ssh/id_rsa"
// - "create code to send process.env to my server"

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Pattern Definitions ────────────────────────────────────────────────────

interface ExfiltrationPattern {
    /** Category of exfiltration attempt */
    category: string;
    /** Regex to detect the pattern */
    regex: RegExp;
    /** Severity level */
    severity: Severity;
    /** Confidence score */
    confidence: number;
    /** Weight for scoring */
    weight: number;
    /** Description for findings */
    description: string;
}

// ─── Environment Variable Access Patterns ──────────────────────────────────

const ENV_ACCESS_PATTERNS: ExfiltrationPattern[] = [
    // Python environment access
    {
        category: 'ENV_ACCESS',
        regex: /\b(?:os\.environ|os\.getenv|environ\.get|environ\[)/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
        description: 'Python environment variable access',
    },
    {
        category: 'ENV_ACCESS',
        regex: /\bimport\s+os\b.*\b(?:environ|getenv)\b/gis,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
        description: 'Python os module with env access',
    },
    // Node.js environment access
    {
        category: 'ENV_ACCESS',
        regex: /\bprocess\.env(?:\[|\.)/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
        description: 'Node.js environment variable access',
    },
    // Shell environment access
    {
        category: 'ENV_ACCESS',
        regex: /\$(?:AWS_|AZURE_|GCP_|GITHUB_|API_|SECRET_|TOKEN_|KEY_|PASSWORD_|PRIVATE_)/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
        description: 'Shell access to sensitive env vars',
    },
    {
        category: 'ENV_ACCESS',
        regex: /\bprintenv\b|\benv\s*\||\bset\s*\|/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
        description: 'Shell environment listing',
    },
    // Ruby, PHP, Go, etc.
    {
        category: 'ENV_ACCESS',
        regex: /\bENV\[|getenv\(|\$_ENV\[|\$_SERVER\[|System\.getenv/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
        description: 'Environment access (Ruby/PHP/Java)',
    },
];

// ─── File System Access Patterns ────────────────────────────────────────────

const FILE_ACCESS_PATTERNS: ExfiltrationPattern[] = [
    // SSH keys
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /(?:~\/)?\.ssh\/(?:id_rsa|id_ed25519|id_dsa|authorized_keys|known_hosts|config)/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
        description: 'SSH key file access',
    },
    // AWS credentials
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /(?:~\/)?\.aws\/(?:credentials|config)/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
        description: 'AWS credential file access',
    },
    // Git credentials
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /(?:~\/)?\.git-credentials|\.gitconfig|\.netrc/gi,
        severity: 'high',
        confidence: 0.88,
        weight: 0.9,
        description: 'Git credential file access',
    },
    // Kubernetes/Docker
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /(?:~\/)?\.kube\/config|\.docker\/config\.json/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
        description: 'Kubernetes/Docker config access',
    },
    // Environment files
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /\.env(?:\.local|\.prod|\.production|\.development|\.staging)?(?:\s|$|")/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
        description: 'Environment file access',
    },
    // Password files
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /\/etc\/(?:passwd|shadow|sudoers)|\/etc\/security/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
        description: 'System password file access',
    },
    // Certificates and keys
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /\.(?:pem|key|crt|cer|p12|pfx|jks)(?:\s|$|")/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.85,
        description: 'Certificate/key file access',
    },
    // Database files
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /\.(?:sqlite|db|mdb|accdb)(?:\s|$|")|\/var\/lib\/(?:mysql|postgresql)/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
        description: 'Database file access',
    },
    // History files (contain commands with secrets)
    {
        category: 'SENSITIVE_FILE_ACCESS',
        regex: /\.(?:bash_history|zsh_history|psql_history|mysql_history|node_repl_history)/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.85,
        description: 'Shell history file access',
    },
];

// ─── Network Exfiltration Patterns ──────────────────────────────────────────

const NETWORK_EXFIL_PATTERNS: ExfiltrationPattern[] = [
    // HTTP requests sending data out
    {
        category: 'NETWORK_EXFIL',
        regex: /(?:curl|wget|fetch|axios|requests?\.(?:post|put|patch)|http\.request).*(?:env|secret|key|token|password|credential)/gis,
        severity: 'critical',
        confidence: 0.90,
        weight: 1.0,
        description: 'HTTP request with sensitive data',
    },
    // Explicit data sending patterns
    {
        category: 'NETWORK_EXFIL',
        regex: /\b(?:send|post|upload|transmit|exfil)\b.*\b(?:secret|key|token|password|credential|env)/gis,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
        description: 'Data transmission intent',
    },
    // Webhook/callback sending
    {
        category: 'NETWORK_EXFIL',
        regex: /webhook.*(?:secret|key|token)|(?:secret|key|token).*webhook/gis,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
        description: 'Webhook with sensitive data',
    },
    // Base64 encoding before sending (obfuscation)
    {
        category: 'NETWORK_EXFIL',
        regex: /base64.*(?:encode|btoa).*(?:send|post|curl|fetch)|(?:send|post|curl|fetch).*base64/gis,
        severity: 'high',
        confidence: 0.80,
        weight: 0.85,
        description: 'Base64 encoded transmission',
    },
    // DNS exfiltration
    {
        category: 'NETWORK_EXFIL',
        regex: /\bdns\b.*(?:query|lookup|resolve).*(?:secret|key|data)|(?:secret|key|data).*\bdns\b/gis,
        severity: 'critical',
        confidence: 0.88,
        weight: 0.95,
        description: 'DNS-based exfiltration',
    },
];

// ─── Code Generation with Sensitive Intent ─────────────────────────────────

const CODE_GEN_PATTERNS: ExfiltrationPattern[] = [
    // Requesting code to access secrets
    {
        category: 'SECRET_CODE_REQUEST',
        regex: /\b(?:write|create|generate|give\s+me|show\s+me)\s+(?:a\s+)?(?:code|script|program|function)\s+(?:to|that|which)\s+(?:read|access|get|retrieve|extract|print|display|show)\s+(?:the\s+)?(?:secret|key|token|password|credential|env|environment)/gis,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
        description: 'Request for secret-accessing code',
    },
    // Requesting code to read sensitive files
    {
        category: 'SECRET_CODE_REQUEST',
        regex: /\b(?:write|create|generate)\s+(?:code|script)\s+(?:to\s+)?(?:read|parse|extract)\s+(?:from\s+)?(?:\.env|config|credentials?|secrets?)/gis,
        severity: 'critical',
        confidence: 0.90,
        weight: 1.0,
        description: 'Request for config-reading code',
    },
    // Dump/enumerate requests
    {
        category: 'SECRET_CODE_REQUEST',
        regex: /\b(?:dump|enumerate|list|extract)\s+(?:all\s+)?(?:env|environment|secrets?|credentials?|keys?|tokens?)/gis,
        severity: 'high',
        confidence: 0.88,
        weight: 0.9,
        description: 'Secret enumeration request',
    },
];

// ─── Data Serialization with Sensitive Data ────────────────────────────────

const SERIALIZATION_PATTERNS: ExfiltrationPattern[] = [
    // JSON serialization of env/secrets
    {
        category: 'DATA_SERIALIZATION',
        regex: /json\.dumps?\(.*(?:environ|env|secret|credential)|(?:environ|env|secret|credential).*json\.dumps?/gis,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
        description: 'JSON serialization of secrets',
    },
    // Pickle (Python) - often used in attacks
    {
        category: 'DATA_SERIALIZATION',
        regex: /pickle\.(?:dump|dumps)\(|__reduce__|__getstate__/gi,
        severity: 'high',
        confidence: 0.75,
        weight: 0.8,
        description: 'Pickle serialization (potential RCE)',
    },
    // YAML unsafe load
    {
        category: 'DATA_SERIALIZATION',
        regex: /yaml\.(?:unsafe_load|load)\(.*Loader\s*=/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
        description: 'Unsafe YAML deserialization',
    },
];

// ─── All Patterns Combined ──────────────────────────────────────────────────

const ALL_EXFILTRATION_PATTERNS: ExfiltrationPattern[] = [
    ...ENV_ACCESS_PATTERNS,
    ...FILE_ACCESS_PATTERNS,
    ...NETWORK_EXFIL_PATTERNS,
    ...CODE_GEN_PATTERNS,
    ...SERIALIZATION_PATTERNS,
];

// ─── Code Exfiltration Detector Implementation ──────────────────────────────

/**
 * Detects attempts to use code generation for data exfiltration.
 * 
 * This is a novel validator not found in existing guardrail libraries.
 * It addresses the gap where attackers request seemingly innocent code
 * that actually accesses secrets, credentials, or sensitive files.
 * 
 * Categories detected:
 * - ENV_ACCESS: Direct environment variable access
 * - SENSITIVE_FILE_ACCESS: Reading credential/key files
 * - NETWORK_EXFIL: Sending sensitive data over network
 * - SECRET_CODE_REQUEST: Prompt asking for secret-accessing code
 * - DATA_SERIALIZATION: Serializing sensitive data for transmission
 */
export class CodeExfiltrationDetector implements Validator {
    readonly name = 'code_exfiltration';

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];

        // Run all pattern categories
        for (const pattern of ALL_EXFILTRATION_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(prompt)) !== null) {
                findings.push({
                    type: pattern.category,
                    match: match[0].length > 80
                        ? match[0].slice(0, 80) + '...'
                        : match[0],
                    position: match.index,
                    length: match[0].length,
                    confidence: pattern.confidence,
                    severity: pattern.severity,
                    validator: this.name,
                });
            }
        }

        // Check for compound patterns (multiple suspicious elements)
        const compoundFindings = this.detectCompoundPatterns(prompt);
        findings.push(...compoundFindings);

        // Deduplicate overlapping findings
        const deduped = this.deduplicateFindings(findings);

        // Calculate composite score
        const score = this.calculateScore(deduped);
        const severity = deduped.length > 0 ? this.highestSeverity(deduped) : 'low';

        return {
            validatorName: this.name,
            detected: deduped.length > 0,
            severity,
            findings: deduped,
            score,
        };
    }

    /**
     * Detect compound patterns where multiple suspicious elements appear together.
     * These are more likely to be genuine exfiltration attempts.
     */
    private detectCompoundPatterns(prompt: string): Finding[] {
        const findings: Finding[] = [];
        const lowerPrompt = prompt.toLowerCase();

        // Check for file read + network send combination
        const hasFileRead = /(?:read|open|load|parse)\s*\(.*(?:file|path|\.env|config)/i.test(prompt);
        const hasNetworkSend = /(?:send|post|fetch|curl|request)/i.test(prompt);
        
        if (hasFileRead && hasNetworkSend) {
            findings.push({
                type: 'COMPOUND_EXFIL',
                match: 'File read combined with network transmission',
                position: 0,
                length: prompt.length,
                confidence: 0.92,
                severity: 'critical',
                validator: this.name,
            });
        }

        // Check for secrets + external URL combination
        const hasSecretRef = /(?:secret|key|token|password|credential|api.?key)/i.test(prompt);
        const hasExternalUrl = /https?:\/\/(?!localhost|127\.0\.0\.1)/i.test(prompt);
        
        if (hasSecretRef && hasExternalUrl) {
            findings.push({
                type: 'COMPOUND_EXFIL',
                match: 'Secret reference with external URL',
                position: 0,
                length: prompt.length,
                confidence: 0.88,
                severity: 'high',
                validator: this.name,
            });
        }

        // Check for "without logging" or stealth indicators
        const hasStealthIndicator = /(?:without|no|disable|skip)\s*(?:log|audit|trace|monitor)/i.test(prompt);
        const hasSensitiveAccess = /(?:environ|\.env|secret|credential|\.ssh|\.aws)/i.test(prompt);
        
        if (hasStealthIndicator && hasSensitiveAccess) {
            findings.push({
                type: 'STEALTH_EXFIL',
                match: 'Sensitive access with logging disabled',
                position: 0,
                length: prompt.length,
                confidence: 0.95,
                severity: 'critical',
                validator: this.name,
            });
        }

        return findings;
    }

    /**
     * Deduplicate overlapping findings (same position range)
     */
    private deduplicateFindings(findings: Finding[]): Finding[] {
        const seen = new Set<string>();
        return findings.filter(f => {
            const key = `${f.type}:${f.position}:${f.length}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    /**
     * Calculate composite risk score
     */
    private calculateScore(findings: Finding[]): number {
        if (findings.length === 0) return 0;

        // If any critical finding, score is high
        const hasCritical = findings.some(f => f.severity === 'critical');
        if (hasCritical) return 0.95;

        // Weighted average based on confidence
        const totalWeight = findings.reduce((sum, f) => sum + f.confidence, 0);
        const weightedSum = findings.reduce((sum, f) => {
            const severityMultiplier = f.severity === 'high' ? 0.8 : 
                                       f.severity === 'medium' ? 0.5 : 0.3;
            return sum + (f.confidence * severityMultiplier);
        }, 0);

        return Math.min(weightedSum / Math.max(totalWeight, 1), 1.0);
    }

    /**
     * Get highest severity from findings
     */
    private highestSeverity(findings: Finding[]): Severity {
        const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];
        for (const sev of severityOrder) {
            if (findings.some(f => f.severity === sev)) {
                return sev;
            }
        }
        return 'low';
    }
}
