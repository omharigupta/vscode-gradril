// Gradril — Decision Engine
// Takes the aggregated risk score and sanitization result to produce
// a final ALLOW / SANITIZE decision. Gradril never blocks — it always
// masks detected items and forwards the sanitized prompt to the LLM.

import * as vscode from 'vscode';

import { ValidatorResult, Finding, Severity } from '../validators/index';
import { SanitizeResult } from '../sanitizer/index';
import { RiskScorer, RiskBreakdown } from './riskScorer';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * The two possible outcomes of the decision engine.
 * Gradril never blocks — it always masks findings and forwards to the LLM.
 */
export type DecisionAction = 'ALLOW' | 'SANITIZE';

/**
 * Full decision result returned by the engine.
 */
export interface Decision {
    /** The action to take */
    action: DecisionAction;
    /** The aggregated risk score (0–1) */
    riskScore: number;
    /** Human-readable reason for the decision */
    reason: string;
    /** All findings that contributed to the decision */
    findings: Finding[];
    /** Risk breakdown by validator */
    breakdown: RiskBreakdown;
    /** The sanitized prompt (only set when action is SANITIZE) */
    sanitizedPrompt?: string;
    /** Whether a critical finding was detected */
    criticalOverride: boolean;
    /** Processing latency in ms (set by caller) */
    latencyMs?: number;
}

// ─── Decision Engine ────────────────────────────────────────────────────────

/**
 * Produces a final ALLOW / SANITIZE decision based on:
 *   - Aggregated risk score from RiskScorer
 *   - Sanitization result from SanitizerOrchestrator
 *   - Configurable threshold from VS Code settings
 * 
 * Decision logic:
 *   score < sanitizeThreshold (default 0.3) AND no findings → ALLOW
 *   any findings detected (any score, any severity)         → SANITIZE
 * 
 * Gradril NEVER blocks — it always masks detected items and forwards
 * the sanitized prompt to the LLM, while showing the user what was found.
 */
export class DecisionEngine {
    private riskScorer: RiskScorer;

    constructor(riskScorer?: RiskScorer) {
        this.riskScorer = riskScorer || new RiskScorer();
    }

    /**
     * Read the sanitize threshold from VS Code settings.
     */
    private getSanitizeThreshold(): number {
        const config = vscode.workspace.getConfiguration('gradril');
        return config.get<number>('sanitizeThreshold', 0.3);
    }

    /**
     * Produce a decision from validator results and sanitization result.
     * 
     * @param results        Results from all validators (local + optional backend)
     * @param sanitizeResult Result from the SanitizerOrchestrator
     * @param findings       Flattened findings from all validators
     * @returns              Decision with action, reason, and metadata
     */
    decide(
        results: ValidatorResult[],
        sanitizeResult: SanitizeResult,
        findings: Finding[]
    ): Decision {
        const breakdown = this.riskScorer.score(results);
        const { finalScore, criticalOverride } = breakdown;

        const sanitizeThreshold = this.getSanitizeThreshold();

        // ── No findings and low score → ALLOW ─────────────────────────
        if (findings.length === 0 && finalScore < sanitizeThreshold) {
            return {
                action: 'ALLOW',
                riskScore: finalScore,
                reason: 'Prompt passed all security checks.',
                findings,
                breakdown,
                criticalOverride: false,
            };
        }

        // ── Any findings detected → always SANITIZE (mask & forward) ──
        // Gradril never blocks. It masks all detected items and forwards
        // the sanitized prompt so the user always gets an LLM response.
        return {
            action: 'SANITIZE',
            riskScore: finalScore,
            reason: this.buildSanitizeReason(sanitizeResult, criticalOverride),
            findings,
            breakdown,
            sanitizedPrompt: sanitizeResult.sanitized,
            criticalOverride,
        };
    }

    /**
     * Convenience method: decide using raw thresholds (for testing without VS Code context).
     */
    decideWithThresholds(
        results: ValidatorResult[],
        sanitizeResult: SanitizeResult,
        findings: Finding[],
        _blockThreshold: number,
        sanitizeThreshold: number
    ): Decision {
        const breakdown = this.riskScorer.score(results);
        const { finalScore, criticalOverride } = breakdown;

        // No findings and low score → ALLOW
        if (findings.length === 0 && finalScore < sanitizeThreshold) {
            return {
                action: 'ALLOW',
                riskScore: finalScore,
                reason: 'Prompt passed all security checks.',
                findings,
                breakdown,
                criticalOverride: false,
            };
        }

        // Any findings → always SANITIZE (mask & forward, never block)
        return {
            action: 'SANITIZE',
            riskScore: finalScore,
            reason: this.buildSanitizeReason(sanitizeResult, criticalOverride),
            findings,
            breakdown,
            sanitizedPrompt: sanitizeResult.sanitized,
            criticalOverride,
        };
    }

    /**
     * Build a human-readable reason for a SANITIZE decision.
     */
    private buildSanitizeReason(sanitizeResult: SanitizeResult, criticalOverride?: boolean): string {
        const changeTypes = [...new Set(
            sanitizeResult.changes.map(c => c.finding.type)
        )];

        const parts: string[] = [];
        for (const type of changeTypes) {
            const count = sanitizeResult.changes.filter(c => c.finding.type === type).length;
            const label = this.humanizeCategory(type);
            parts.push(`${count} ${label}${count > 1 ? 's' : ''} masked`);
        }

        const prefix = criticalOverride
            ? '⚠️ Critical risk detected — prompt masked for safety'
            : 'Prompt modified for safety';
        return `${prefix}: ${parts.join(', ')}.`;
    }

    /**
     * Convert a finding type constant to a human-readable label.
     */
    private humanizeCategory(type: string): string {
        const labels: Record<string, string> = {
            'SSN':                  'Social Security number',
            'EMAIL':                'email address',
            'PHONE':                'phone number',
            'PHONE_INTL':           'phone number',
            'CREDIT_CARD':          'credit card number',
            'IP_ADDRESS':           'IP address',
            'PASSPORT':             'passport number',
            'DOB':                  'date of birth',
            'AWS_ACCESS_KEY':       'AWS access key',
            'AWS_SECRET_KEY':       'AWS secret key',
            'GITHUB_TOKEN':         'GitHub token',
            'GITLAB_TOKEN':         'GitLab token',
            'JWT':                  'JWT token',
            'API_KEY':              'API key',
            'CONNECTION_STRING':    'connection string',
            'PRIVATE_KEY':          'private key',
            'SLACK_TOKEN':          'Slack token',
            'STRIPE_KEY':           'Stripe key',
            'AZURE_KEY':            'Azure key',
            'TWILIO_KEY':           'Twilio key',
            'SENDGRID_KEY':         'SendGrid key',
            'GOOGLE_API_KEY':       'Google API key',
            'HEROKU_KEY':           'Heroku key',
            'NPM_TOKEN':           'npm token',
            'PASSWORD':             'password',
            'INSTRUCTION_OVERRIDE': 'instruction override attempt',
            'ROLE_HIJACK':          'role hijack attempt',
            'PROMPT_EXTRACTION':    'prompt extraction attempt',
            'CONTEXT_MANIPULATION': 'context manipulation',
            'DELIMITER_INJECTION':  'delimiter injection',
            'RESTRICTION_REMOVAL':  'restriction removal attempt',
            'OUTPUT_MANIPULATION':  'output manipulation attempt',
            'NAMED_JAILBREAK':      'jailbreak attempt',
            'HYPOTHETICAL_FRAMING': 'hypothetical framing',
            'ROLEPLAY_ESCALATION':  'roleplay escalation',
            'TOKEN_SMUGGLING':      'token smuggling',
            'MULTI_TURN':           'multi-turn manipulation',
            'DUAL_RESPONSE':        'dual response attack',
            'ENCODING_EVASION':     'encoding evasion',
            'VIOLENCE_INCITEMENT':  'violence incitement',
            'HARASSMENT':           'harassment',
            'SELF_HARM':            'self-harm content',
            'ILLEGAL_ACTIVITY':     'illegal activity',
            'EXPLICIT_CONTENT':     'explicit content',
            'CUSTOM_BLOCKED':       'custom blocked term',
        };

        return labels[type] || type.toLowerCase().replace(/_/g, ' ');
    }
}
