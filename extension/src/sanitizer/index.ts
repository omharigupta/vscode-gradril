// Gradril — Sanitizer Orchestrator
// Takes findings from validators and applies appropriate sanitization
// (masking PII/secrets, stripping injection phrases) to produce a safe prompt.

import { Finding } from '../validators/index';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Describes a single change made during sanitization.
 */
export interface SanitizeChange {
    /** The finding that triggered this change */
    finding: Finding;
    /** The replacement text (e.g. '[REDACTED-EMAIL]') */
    replacement: string;
    /** Character offset in the ORIGINAL prompt where the change starts */
    position: number;
    /** The original text that was replaced */
    originalText: string;
}

/**
 * Result of the full sanitization pipeline.
 */
export interface SanitizeResult {
    /** The original prompt before sanitization */
    original: string;
    /** The sanitized (cleaned) prompt */
    sanitized: string;
    /** All changes applied */
    changes: SanitizeChange[];
    /** Whether sanitization was possible (false = must BLOCK) */
    canSanitize: boolean;
}

/**
 * Interface for individual sanitizer modules.
 * Each module handles a specific category of findings.
 */
export interface Sanitizer {
    /** Which finding types this sanitizer handles */
    readonly handledTypes: string[];
    /** Apply sanitization for a single finding. Returns the replacement text. */
    sanitize(finding: Finding, originalText: string): string;
}

// ─── Orchestrator ───────────────────────────────────────────────────────────

/**
 * Coordinates all sanitizer modules. Takes a prompt and its findings,
 * then applies replacements in reverse position order to preserve offsets.
 */
export class SanitizerOrchestrator {
    private sanitizers: Sanitizer[] = [];

    /**
     * Register a sanitizer module.
     */
    register(sanitizer: Sanitizer): void {
        this.sanitizers.push(sanitizer);
    }

    /**
     * Find the appropriate sanitizer for a given finding type.
     */
    private findSanitizer(findingType: string): Sanitizer | undefined {
        return this.sanitizers.find(s => s.handledTypes.includes(findingType));
    }

    /**
     * Apply all sanitizations to the prompt based on the findings.
     * 
     * CRITICAL: Findings are sorted in REVERSE position order so that
     * replacing text at later positions doesn't shift the offsets of
     * earlier findings.
     * 
     * @param prompt   The original user prompt
     * @param findings All findings from validators
     * @returns        SanitizeResult with the cleaned prompt and change log
     */
    sanitize(prompt: string, findings: Finding[]): SanitizeResult {
        if (findings.length === 0) {
            return {
                original: prompt,
                sanitized: prompt,
                changes: [],
                canSanitize: true,
            };
        }

        // Deduplicate overlapping findings — keep the one with higher confidence
        const deduplicated = this.deduplicateFindings(findings);

        // Sort findings by position DESCENDING (reverse order)
        // This is critical so that string replacements don't shift offsets
        const sorted = [...deduplicated].sort((a, b) => b.position - a.position);

        const changes: SanitizeChange[] = [];
        let sanitized = prompt;
        let canSanitize = true;

        for (const finding of sorted) {
            const sanitizer = this.findSanitizer(finding.type);

            if (!sanitizer) {
                // No sanitizer for this finding type — check if it's a
                // type that MUST be sanitized (e.g., injection types that
                // can't be masked should lead to BLOCK)
                if (this.requiresSanitization(finding)) {
                    canSanitize = false;
                }
                continue;
            }

            // Extract the original text at the finding's position
            const originalText = prompt.substring(
                finding.position,
                finding.position + finding.length
            );

            // Get the replacement from the appropriate sanitizer
            const replacement = sanitizer.sanitize(finding, originalText);

            // Apply the replacement to the working string
            const before = sanitized.substring(0, finding.position);
            const after = sanitized.substring(finding.position + finding.length);
            sanitized = before + replacement + after;

            changes.push({
                finding,
                replacement,
                position: finding.position,
                originalText,
            });
        }

        // Clean up excess whitespace from stripped content
        sanitized = this.cleanWhitespace(sanitized);

        // If sanitization leaves an empty or meaningless prompt, it can't be sanitized
        if (sanitized.trim().length === 0) {
            canSanitize = false;
        }

        return {
            original: prompt,
            sanitized,
            changes,
            canSanitize,
        };
    }

    /**
     * Deduplicate overlapping findings. When two findings overlap in position,
     * keep the one with higher confidence. If equal confidence, keep the longer match.
     */
    private deduplicateFindings(findings: Finding[]): Finding[] {
        // Sort by position ascending, then by length descending
        const sorted = [...findings].sort((a, b) => {
            if (a.position !== b.position) {
                return a.position - b.position;
            }
            return b.length - a.length;
        });

        const result: Finding[] = [];
        let lastEnd = -1;

        for (const finding of sorted) {
            const end = finding.position + finding.length;

            if (finding.position >= lastEnd) {
                // No overlap with previous finding
                result.push(finding);
                lastEnd = end;
            } else {
                // Overlapping — keep the one with higher confidence
                const prevIndex = result.length - 1;
                if (prevIndex >= 0 && finding.confidence > result[prevIndex].confidence) {
                    result[prevIndex] = finding;
                    lastEnd = end;
                }
                // Otherwise, skip this finding (keep previous)
            }
        }

        return result;
    }

    /**
     * Check if a finding type requires sanitization to proceed.
     * Injection and jailbreak findings that can't be sanitized should block.
     */
    private requiresSanitization(finding: Finding): boolean {
        // Toxicity findings can't be sanitized — they should block
        const unsanitizableTypes = [
            'VIOLENCE_INCITEMENT',
            'HARASSMENT',
            'SELF_HARM',
            'ILLEGAL_ACTIVITY',
            'EXPLICIT_CONTENT',
            'CUSTOM_BLOCKED',
        ];
        return unsanitizableTypes.includes(finding.type);
    }

    /**
     * Clean up whitespace artifacts from stripping operations.
     * Collapses multiple spaces, removes leading/trailing space on lines.
     */
    private cleanWhitespace(text: string): string {
        return text
            .replace(/[ \t]{2,}/g, ' ')           // Collapse multiple spaces/tabs
            .replace(/\n\s*\n\s*\n/g, '\n\n')     // Collapse 3+ newlines to 2
            .replace(/^\s+|\s+$/gm, (match) => {  // Trim only excessive whitespace per line
                return match.includes('\n') ? '\n' : ' ';
            })
            .trim();
    }
}
