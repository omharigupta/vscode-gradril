// Gradril — Validator Types & Orchestrator
// Defines shared interfaces and runs all validators in parallel

// ─── Shared Types ───────────────────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * A single finding detected by a validator.
 */
export interface Finding {
    /** Category of the finding, e.g. 'EMAIL', 'AWS_KEY', 'INJECTION' */
    type: string;
    /** The matched text (may be truncated for secrets) */
    match: string;
    /** Character offset in the original prompt */
    position: number;
    /** Length of the matched text */
    length: number;
    /** Confidence score 0-1 */
    confidence: number;
    /** Severity level */
    severity: Severity;
    /** Which validator produced this finding */
    validator: string;
}

/**
 * Result returned by each validator.
 */
export interface ValidatorResult {
    /** Name of the validator that produced this result */
    validatorName: string;
    /** Whether any issues were detected */
    detected: boolean;
    /** Highest severity among findings (defaults to 'low' if none) */
    severity: Severity;
    /** All findings */
    findings: Finding[];
    /** Overall risk score from this validator (0-1) */
    score: number;
}

/**
 * Interface every validator must implement.
 */
export interface Validator {
    /** Unique name for this validator */
    readonly name: string;
    /** Run validation on a prompt, return findings  */
    validate(prompt: string): ValidatorResult;
}

// ─── Orchestrator ───────────────────────────────────────────────────────────

/**
 * Runs all enabled validators in parallel and collects results.
 */
export class ValidatorOrchestrator {
    private validators: Validator[] = [];

    /**
     * Register a validator instance.
     */
    register(validator: Validator): void {
        this.validators.push(validator);
    }

    /**
     * Run all registered validators whose name is in the enabled list.
     * Returns an array of ValidatorResult, one per enabled validator.
     */
    async runAll(prompt: string, enabledValidators?: string[]): Promise<ValidatorResult[]> {
        const active = enabledValidators
            ? this.validators.filter(v => enabledValidators.includes(v.name))
            : this.validators;

        // All validators are synchronous (regex-based), but we wrap in
        // Promise.resolve to keep the interface async-ready for future
        // ML or network-based validators
        const results = await Promise.all(
            active.map(v => Promise.resolve(v.validate(prompt)))
        );

        return results;
    }

    /**
     * Get list of registered validator names.
     */
    getRegisteredNames(): string[] {
        return this.validators.map(v => v.name);
    }

    /**
     * Flatten all findings from multiple results into a single array.
     */
    static flattenFindings(results: ValidatorResult[]): Finding[] {
        return results.flatMap(r => r.findings);
    }

    /**
     * Get the highest severity across all results.
     */
    static highestSeverity(results: ValidatorResult[]): Severity {
        const order: Severity[] = ['low', 'medium', 'high', 'critical'];
        let max: Severity = 'low';
        for (const r of results) {
            if (order.indexOf(r.severity) > order.indexOf(max)) {
                max = r.severity;
            }
        }
        return max;
    }
}
