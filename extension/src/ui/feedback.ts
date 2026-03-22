// Gradril — Chat Feedback Renderer
// Renders ALLOW / SANITIZE decisions into the chat response stream.
// Also renders hallucination analysis with color-coded confidence indicators.

import * as vscode from 'vscode';
import { Decision } from '../engine/decisionEngine';
import { SanitizeResult } from '../sanitizer/index';
import { HallucinationResult, SentenceAnalysis } from '../backend/types';

// ─── Feedback Renderer ──────────────────────────────────────────────────────

/**
 * Renders decision feedback into a `vscode.ChatResponseStream`.
 */
export class FeedbackRenderer {

    /**
     * Render a SANITIZE decision — shows what was detected and how it was
     * masked/redacted, with color-coded before→after display.
     */
    renderSanitizeHeader(stream: vscode.ChatResponseStream, decision: Decision, sanitizeResult: SanitizeResult): void {
        stream.markdown('## ⚠️ Prompt Modified for Safety\n\n');

        // Risk bar
        stream.markdown(this.renderRiskBar(decision.riskScore) + '\n\n');

        if (sanitizeResult.changes.length > 0) {
            stream.markdown('### 🔍 Detected & Redacted\n\n');

            for (const change of sanitizeResult.changes) {
                const f = change.finding;
                const sevIcon = this.severityIcon(f.severity);
                const typeLabel = this.humanizeType(f.type);
                const masked = this.maskDetectedValue(change.originalText, f.type);

                stream.markdown(
                    `${sevIcon} **${typeLabel}** detected\n\n` +
                    `> 🔴 ~~\`${masked}\`~~ → 🟢 \`${change.replacement}\`\n\n`
                );
            }
        }

        stream.markdown('---\n\n');
    }

    /**
     * Render the footer after a successful ALLOW response.
     */
    renderAllowFooter(stream: vscode.ChatResponseStream): void {
        stream.markdown('\n\n---\n*✅ Verified by Gradril*\n');
    }

    /**
     * Render the footer after a SANITIZE response.
     */
    renderSanitizeFooter(stream: vscode.ChatResponseStream): void {
        stream.markdown('\n\n---\n*⚠️ Prompt was sanitized by Gradril before sending to AI*\n');
    }

    /**
     * Render a /scan report — shows full analysis without sending to LLM.
     */
    renderScanReport(
        stream: vscode.ChatResponseStream,
        decision: Decision,
        sanitizeResult: SanitizeResult
    ): void {
        stream.markdown('## 🔍 Gradril Scan Report\n\n');

        // Risk bar
        stream.markdown(this.renderRiskBar(decision.riskScore) + '\n\n');
        stream.markdown(`**Decision:** Would **${decision.action}**\n\n`);

        if (decision.findings.length > 0) {
            stream.markdown('### Detected Items\n\n');

            const grouped = this.groupFindings(decision.findings);

            for (const [category, findings] of grouped) {
                const catIcon = this.categoryIcon(category);
                const catLabel = this.categoryLabel(category);
                stream.markdown(`#### ${catIcon} ${catLabel}\n\n`);

                stream.markdown('| | Type | Detected Value | Severity | Confidence |\n');
                stream.markdown('|---|------|---------------|----------|------------|\n');

                for (const f of findings) {
                    const sevIcon = this.severityIcon(f.severity);
                    const masked = this.maskDetectedValue(f.match, f.type);
                    const typeLabel = this.humanizeType(f.type);
                    stream.markdown(`| ${sevIcon} | ${typeLabel} | \`${masked}\` | ${this.severityTag(f.severity)} | ${(f.confidence * 100).toFixed(0)}% |\n`);
                }
                stream.markdown('\n');
            }
        } else {
            stream.markdown('*No security risks detected.* ✅\n\n');
        }

        if (decision.action === 'SANITIZE' && sanitizeResult.changes.length > 0) {
            stream.markdown('### Redactions Applied\n\n');
            for (const change of sanitizeResult.changes) {
                const typeLabel = this.humanizeType(change.finding.type);
                const masked = this.maskDetectedValue(change.originalText, change.finding.type);
                stream.markdown(`- 🔴 ~~\`${masked}\`~~ → 🟢 \`${change.replacement}\`  *(${typeLabel})*\n`);
            }
            stream.markdown('\n');
        }

        stream.markdown(`*Scan completed in ${decision.latencyMs ?? 0}ms*\n`);
    }

    /**
     * Render a /status report.
     */
    renderStatusReport(
        stream: vscode.ChatResponseStream,
        config: {
            enabled: boolean;
            backendEnabled: boolean;
            backendAvailable: boolean;
            backendUrl: string;
            sanitizeThreshold: number;
            enabledValidators: string[];
        },
        stats: { total: number; allowed: number; sanitized: number }
    ): void {
        stream.markdown('## 📊 Gradril Status\n\n');

        stream.markdown('### Configuration\n\n');
        stream.markdown('| Setting | Value |\n');
        stream.markdown('|---------|-------|\n');
        stream.markdown(`| Guard Enabled | ${config.enabled ? '✅ Yes' : '❌ No'} |\n`);
        stream.markdown(`| Backend Enabled | ${config.backendEnabled ? '✅ Yes' : '❌ No'} |\n`);
        stream.markdown(`| Backend Status | ${config.backendAvailable ? '🟢 Online' : '🔴 Offline'} |\n`);
        stream.markdown(`| Backend URL | \`${config.backendUrl}\` |\n`);
        stream.markdown(`| Sanitize Threshold | ${config.sanitizeThreshold} |\n`);
        stream.markdown(`| Validators | ${config.enabledValidators.join(', ')} |\n`);
        stream.markdown('\n');

        stream.markdown('### Session Statistics\n\n');
        stream.markdown('| Metric | Count |\n');
        stream.markdown('|--------|-------|\n');
        stream.markdown(`| Total Scanned | ${stats.total} |\n`);
        stream.markdown(`| Allowed | ${stats.allowed} |\n`);
        stream.markdown(`| Sanitized | ${stats.sanitized} |\n`);
        stream.markdown('\n');
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private severityIcon(severity: string): string {
        switch (severity) {
            case 'critical': return '🔴';
            case 'high':     return '🟠';
            case 'medium':   return '🟡';
            case 'low':      return '🟢';
            default:         return '⚪';
        }
    }

    private severityTag(severity: string): string {
        switch (severity) {
            case 'critical': return 'CRITICAL';
            case 'high':     return 'HIGH';
            case 'medium':   return 'MEDIUM';
            case 'low':      return 'LOW';
            default:         return 'UNKNOWN';
        }
    }

    private riskLabel(score: number): string {
        if (score < 0.3) { return 'Low'; }
        if (score < 0.7) { return 'Medium'; }
        return 'High';
    }

    /**
     * Render a visual risk bar with color based on score.
     * Example: `Risk: 0.85` 🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥🟥⬜⬜⬜
     */
    private renderRiskBar(score: number): string {
        const total = 20;
        const filled = Math.round(score * total);
        const empty = total - filled;

        let color: string;
        if (score >= 0.7) { color = '🟥'; }
        else if (score >= 0.3) { color = '🟨'; }
        else { color = '🟩'; }

        const bar = color.repeat(filled) + '⬜'.repeat(empty);
        const label = this.riskLabel(score);
        return `**Risk:** \`${(score * 100).toFixed(0)}%\` ${bar} *${label}*`;
    }

    /**
     * Group findings by detector category for organized display.
     */
    private groupFindings(findings: import('../validators/index').Finding[]): Map<string, import('../validators/index').Finding[]> {
        const groups = new Map<string, import('../validators/index').Finding[]>();
        for (const f of findings) {
            const category = this.findingCategory(f.validator || f.type);
            if (!groups.has(category)) { groups.set(category, []); }
            groups.get(category)!.push(f);
        }
        return groups;
    }

    private findingCategory(validatorOrType: string): string {
        const v = validatorOrType.toLowerCase();
        if (v.includes('pii') || ['ssn', 'email', 'phone', 'phone_intl', 'credit_card', 'ip_address', 'passport', 'dob'].includes(v)) {
            return 'pii';
        }
        if (v.includes('secret') || ['aws_access_key', 'aws_secret_key', 'github_token', 'gitlab_token', 'jwt', 'api_key', 'connection_string', 'private_key', 'slack_token', 'stripe_key', 'azure_key', 'npm_token', 'password'].includes(v)) {
            return 'secrets';
        }
        if (v.includes('injection') || ['instruction_override', 'role_hijack', 'prompt_extraction', 'delimiter_injection', 'restriction_removal'].includes(v)) {
            return 'injection';
        }
        if (v.includes('jailbreak') || ['named_jailbreak', 'developer_mode', 'dual_response', 'encoding_evasion'].includes(v)) {
            return 'jailbreak';
        }
        if (v.includes('toxic') || v.includes('toxicity')) {
            return 'toxicity';
        }
        return 'other';
    }

    private categoryIcon(category: string): string {
        switch (category) {
            case 'pii':       return '👤';
            case 'secrets':   return '🔑';
            case 'injection': return '💉';
            case 'jailbreak': return '🔓';
            case 'toxicity':  return '☠️';
            default:          return '⚠️';
        }
    }

    private categoryLabel(category: string): string {
        switch (category) {
            case 'pii':       return 'Personal Information (PII)';
            case 'secrets':   return 'Secrets & API Keys';
            case 'injection': return 'Prompt Injection';
            case 'jailbreak': return 'Jailbreak Attempt';
            case 'toxicity':  return 'Toxic Content';
            default:          return 'Other';
        }
    }

    /**
     * Mask a detected value for safe display — shows enough to confirm
     * what was found but redacts the sensitive portion.
     * Examples:
     *   "123-45-6789" → "123-••-••••"
     *   "john@example.com" → "jo••@example.com"
     *   "AKIA1234567890ABCDEF" → "AKIA••••••••••••CDEF"
     *   "ghp_abc123def456ghi789" → "ghp_••••••••••••••89"
     */
    private maskDetectedValue(value: string, type: string): string {
        if (!value || value.length < 4) { return '••••'; }

        const t = type.toUpperCase();

        // SSN: show first 3, mask rest
        if (t === 'SSN') {
            return value.slice(0, 3) + '-••-••••';
        }

        // Email: show first 2 chars + domain
        if (t === 'EMAIL') {
            const atIdx = value.indexOf('@');
            if (atIdx > 2) {
                return value.slice(0, 2) + '••' + value.slice(atIdx);
            }
            return value.slice(0, 2) + '••••';
        }

        // Credit card: show last 4
        if (t === 'CREDIT_CARD') {
            return '••••-••••-••••-' + value.replace(/\D/g, '').slice(-4);
        }

        // Phone: show last 4 digits
        if (t.includes('PHONE')) {
            const digits = value.replace(/\D/g, '');
            return '(•••) •••-' + digits.slice(-4);
        }

        // API keys / tokens: show prefix + last 4
        if (t.includes('KEY') || t.includes('TOKEN') || t === 'JWT' || t.includes('SECRET') || t.includes('STRIPE') || t.includes('AZURE') || t === 'NPM_TOKEN') {
            if (value.length > 8) {
                const prefix = value.slice(0, 4);
                const suffix = value.slice(-4);
                const stars = '•'.repeat(Math.min(value.length - 8, 14));
                return prefix + stars + suffix;
            }
            return value.slice(0, 2) + '•'.repeat(value.length - 2);
        }

        // Connection string: show protocol + mask credentials
        if (t === 'CONNECTION_STRING') {
            const protoEnd = value.indexOf('://');
            if (protoEnd > 0) {
                return value.slice(0, protoEnd + 3) + '••••:••••@••••';
            }
        }

        // Private key: just show the header
        if (t === 'PRIVATE_KEY') {
            return '-----BEGIN ••• KEY-----';
        }

        // IP address: show first octet
        if (t === 'IP_ADDRESS') {
            const dot = value.indexOf('.');
            if (dot > 0) {
                return value.slice(0, dot) + '.•••.•••.•••';
            }
        }

        // Injection / jailbreak: show first 20 chars
        if (['INSTRUCTION_OVERRIDE', 'ROLE_HIJACK', 'PROMPT_EXTRACTION', 'DELIMITER_INJECTION', 'RESTRICTION_REMOVAL', 'NAMED_JAILBREAK', 'DEVELOPER_MODE', 'DUAL_RESPONSE', 'ENCODING_EVASION'].includes(t)) {
            if (value.length > 25) {
                return value.slice(0, 25) + '...';
            }
            return value;
        }

        // Generic: show first 4 + last 4
        if (value.length > 10) {
            return value.slice(0, 4) + '•'.repeat(Math.min(value.length - 8, 10)) + value.slice(-4);
        }
        return value.slice(0, 2) + '•'.repeat(value.length - 2);
    }

    private humanizeType(type: string): string {
        const labels: Record<string, string> = {
            'SSN': 'Social Security number',
            'EMAIL': 'email address',
            'PHONE': 'phone number',
            'PHONE_INTL': 'phone number',
            'CREDIT_CARD': 'credit card',
            'IP_ADDRESS': 'IP address',
            'PASSPORT': 'passport number',
            'DOB': 'date of birth',
            'AWS_ACCESS_KEY': 'AWS key',
            'AWS_SECRET_KEY': 'AWS secret',
            'GITHUB_TOKEN': 'GitHub token',
            'GITLAB_TOKEN': 'GitLab token',
            'JWT': 'JWT',
            'API_KEY': 'API key',
            'CONNECTION_STRING': 'connection string',
            'PRIVATE_KEY': 'private key',
            'SLACK_TOKEN': 'Slack token',
            'STRIPE_KEY': 'Stripe key',
            'AZURE_KEY': 'Azure key',
            'INSTRUCTION_OVERRIDE': 'injection phrase',
            'ROLE_HIJACK': 'injection phrase',
            'PROMPT_EXTRACTION': 'injection phrase',
            'NAMED_JAILBREAK': 'jailbreak phrase',
        };
        return labels[type] || type.toLowerCase().replace(/_/g, ' ');
    }

    // ─── Hallucination Color-Coded Rendering ────────────────────────

    /**
     * Render the LLM response with color-coded hallucination indicators.
     * 
     * Uses markdown with colored emoji indicators per sentence:
     *   🟢 = Grounded (high confidence, safe to trust)
     *   🟡 = Uncertain (hedging, possible fabrication)
     *   🔴 = Hallucinated (likely fabricated or contradictory)
     * 
     * Also renders a summary header with overall score.
     */
    renderHallucinationAnalysis(
        stream: vscode.ChatResponseStream,
        hallucinationResult: HallucinationResult
    ): void {
        const { overallScore, overallLevel, counts, sentences, hasHallucination } = hallucinationResult;

        // ── Summary bar ─────────────────────────────────────────────
        stream.markdown('\n\n---\n');
        stream.markdown('### 🧠 Hallucination Analysis\n\n');

        // Color-coded overall badge
        const overallBadge = this.levelBadge(overallLevel);
        const overallPct = (overallScore * 100).toFixed(0);
        stream.markdown(`**Overall Confidence:** ${overallBadge} **${overallPct}%** (${this.levelLabel(overallLevel)})\n\n`);

        // Visual confidence bar
        stream.markdown(this.renderConfidenceBar(overallScore) + '\n\n');

        // Counts summary
        if (hasHallucination) {
            stream.markdown(
                `🟢 ${counts.grounded} grounded · ` +
                `🟡 ${counts.uncertain} uncertain · ` +
                `🔴 ${counts.hallucinated} hallucinated\n\n`
            );
        } else {
            stream.markdown('*All statements appear well-grounded.* ✅\n\n');
        }

        // ── Per-sentence detail (only if hallucination detected) ────
        if (hasHallucination) {
            stream.markdown('<details>\n<summary>📋 Detailed sentence-by-sentence analysis</summary>\n\n');

            for (let i = 0; i < sentences.length; i++) {
                const s = sentences[i];
                const icon = this.levelIcon(s.level);
                const pct = (s.confidence * 100).toFixed(0);
                const preview = this.truncateText(s.text, 120);

                stream.markdown(`${icon} **${pct}%** — ${preview}\n`);

                // Show reasons for uncertain/hallucinated items
                if (s.level !== 'grounded' && s.reasons.length > 0) {
                    for (const reason of s.reasons) {
                        if (reason !== 'No hallucination indicators found') {
                            stream.markdown(`  - ⚠️ *${reason}*\n`);
                        }
                    }
                }
            }

            stream.markdown('\n</details>\n\n');
        }

        // ── Legend ──────────────────────────────────────────────────
        if (hasHallucination) {
            stream.markdown(
                '> 💡 **Confidence legend:** ' +
                '🟢 Grounded (≥70%) · ' +
                '🟡 Uncertain (40–69%) · ' +
                '🔴 Likely hallucinated (<40%)\n'
            );
        }
    }

    /**
     * Render a compact inline hallucination indicator for the ALLOW footer.
     */
    renderHallucinationBadge(stream: vscode.ChatResponseStream, hallucinationResult: HallucinationResult): void {
        const { overallScore, overallLevel, hasHallucination, counts } = hallucinationResult;
        const badge = this.levelBadge(overallLevel);
        const pct = (overallScore * 100).toFixed(0);

        if (!hasHallucination) {
            stream.markdown(`\n${badge} **Grounding: ${pct}%** — All statements appear reliable\n`);
        } else {
            stream.markdown(
                `\n${badge} **Grounding: ${pct}%** — ` +
                `${counts.hallucinated > 0 ? `⚠️ ${counts.hallucinated} potentially hallucinated` : ''}` +
                `${counts.hallucinated > 0 && counts.uncertain > 0 ? ', ' : ''}` +
                `${counts.uncertain > 0 ? `${counts.uncertain} uncertain` : ''} ` +
                `statements detected\n`
            );
        }
    }

    // ─── Hallucination Visual Helpers ────────────────────────────────

    private levelIcon(level: string): string {
        switch (level) {
            case 'grounded':     return '🟢';
            case 'uncertain':    return '🟡';
            case 'hallucinated': return '🔴';
            default:             return '⚪';
        }
    }

    private levelBadge(level: string): string {
        switch (level) {
            case 'grounded':     return '🟢';
            case 'uncertain':    return '🟡';
            case 'hallucinated': return '🔴';
            default:             return '⚪';
        }
    }

    private levelLabel(level: string): string {
        switch (level) {
            case 'grounded':     return 'Well-grounded';
            case 'uncertain':    return 'Some uncertainty';
            case 'hallucinated': return 'Likely hallucinated';
            default:             return 'Unknown';
        }
    }

    /**
     * Render a visual confidence bar using block characters.
     * Example: ████████░░ 80%
     */
    private renderConfidenceBar(score: number): string {
        const total = 20;
        const filled = Math.round(score * total);
        const empty = total - filled;

        let color: string;
        if (score >= 0.7) { color = '🟩'; }
        else if (score >= 0.4) { color = '🟨'; }
        else { color = '🟥'; }

        const bar = color.repeat(filled) + '⬜'.repeat(empty);
        return `\`${(score * 100).toFixed(0)}%\` ${bar}`;
    }

    private truncateText(text: string, maxLen: number): string {
        // Strip code blocks for display preview
        const cleaned = text.replace(/```[\s\S]*?```/g, '[code block]').trim();
        if (cleaned.length <= maxLen) { return cleaned; }
        return cleaned.slice(0, maxLen) + '...';
    }
}
