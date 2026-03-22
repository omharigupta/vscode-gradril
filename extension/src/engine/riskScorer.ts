// Gradril — Risk Scorer
// Weighted aggregation of validator results into a single 0–1 risk score.
// If any finding has critical severity, the score is overridden to 1.0.

import { ValidatorResult, Severity } from '../validators/index';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Breakdown of risk score by validator category.
 */
export interface RiskBreakdown {
    /** Final aggregated score (0–1) */
    finalScore: number;
    /** The validator category that contributed most to the score */
    dominantCategory: string;
    /** Per-validator score breakdown */
    breakdown: Record<string, number>;
    /** Whether a critical finding triggered the override */
    criticalOverride: boolean;
}

// ─── Default Weights ────────────────────────────────────────────────────────

/**
 * Weight per validator name. Higher weight = more influence on final score.
 * These match the PLAN.md specification.
 */
const DEFAULT_WEIGHTS: Record<string, number> = {
    'secrets':   1.0,
    'pii':       1.0,
    'injection': 0.9,
    'jailbreak': 0.8,
    'toxicity':  0.7,
};

// ─── Risk Scorer ────────────────────────────────────────────────────────────

/**
 * Computes a weighted risk score from an array of ValidatorResults.
 * 
 * Formula:
 *   finalScore = Σ(validator.score × weight) / Σ(weights)
 * 
 * Override rules:
 *   - If ANY finding has severity === 'critical' → finalScore = 1.0
 *   - Backend ML results can override local scores for toxicity/jailbreak
 *     (handled by caller merging results before scoring)
 */
export class RiskScorer {
    private weights: Record<string, number>;

    constructor(weights?: Record<string, number>) {
        this.weights = weights || { ...DEFAULT_WEIGHTS };
    }

    /**
     * Update the weight for a specific validator.
     */
    setWeight(validatorName: string, weight: number): void {
        this.weights[validatorName] = Math.max(0, Math.min(1, weight));
    }

    /**
     * Get the current weight configuration.
     */
    getWeights(): Record<string, number> {
        return { ...this.weights };
    }

    /**
     * Compute the aggregated risk score from validator results.
     * 
     * @param results Array of ValidatorResult from the orchestrator
     * @returns       RiskBreakdown with the final score and per-validator detail
     */
    score(results: ValidatorResult[]): RiskBreakdown {
        // Check for critical severity override first
        const hasCritical = this.hasCriticalFinding(results);

        if (results.length === 0) {
            return {
                finalScore: 0,
                dominantCategory: 'none',
                breakdown: {},
                criticalOverride: false,
            };
        }

        // Calculate weighted sum
        let weightedSum = 0;
        let totalWeight = 0;
        const breakdown: Record<string, number> = {};
        let dominantCategory = 'none';
        let dominantScore = -1;

        for (const result of results) {
            const weight = this.weights[result.validatorName] ?? 0.5;
            const weightedScore = result.score * weight;

            breakdown[result.validatorName] = result.score;
            weightedSum += weightedScore;
            totalWeight += weight;

            if (weightedScore > dominantScore) {
                dominantScore = weightedScore;
                dominantCategory = result.validatorName;
            }
        }

        // Avoid division by zero
        let finalScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

        // Clamp to 0–1
        finalScore = Math.max(0, Math.min(1, finalScore));

        // Critical override: if any finding is critical -> 1.0
        if (hasCritical) {
            finalScore = 1.0;
        }

        return {
            finalScore,
            dominantCategory,
            breakdown,
            criticalOverride: hasCritical,
        };
    }

    /**
     * Check if any finding across all results has critical severity.
     */
    private hasCriticalFinding(results: ValidatorResult[]): boolean {
        for (const result of results) {
            if (result.severity === 'critical') {
                return true;
            }
            for (const finding of result.findings) {
                if (finding.severity === 'critical') {
                    return true;
                }
            }
        }
        return false;
    }
}
