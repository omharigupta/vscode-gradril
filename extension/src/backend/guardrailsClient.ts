// Gradril — Guardrails AI HTTP Client
// Communicates with the Guardrails AI server for ML-based validation.
// Uses Node.js built-in http/https modules — zero external dependencies.
// Features: timeout, retry with exponential backoff, graceful fallback.

import * as http from 'http';
import * as https from 'https';
import * as url from 'url';
import * as vscode from 'vscode';

import {
    BackendRequest,
    BackendResponse,
    BackendHealthResponse,
    BackendResult,
    BackendValidation,
    BackendOutputResult,
} from './types';

// ─── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_GUARD_NAME = 'gradril_input_guard';
const DEFAULT_OUTPUT_GUARD_NAME = 'gradril_output_guard';
const MAX_RETRIES = 2;
const BASE_RETRY_DELAY_MS = 500;
const HEALTH_CHECK_INTERVAL_MS = 60_000;

// ─── Guardrails Client ─────────────────────────────────────────────────────

/**
 * HTTP client for the Guardrails AI server.
 * 
 * - POST /guards/{guard_name}/validate — validate a prompt
 * - GET /health — health check
 * 
 * Graceful degradation: if the backend is unavailable, returns null
 * so the caller can fall back to local-only validation.
 */
export class GuardrailsClient {
    private _available: boolean = false;
    private _lastHealthCheck: number = 0;
    private _healthCheckTimer: ReturnType<typeof setInterval> | null = null;

    /**
     * Get the configured backend URL from VS Code settings.
     */
    private getBaseUrl(): string {
        const config = vscode.workspace.getConfiguration('gradril');
        return config.get<string>('backendUrl', 'http://localhost:8000');
    }

    /**
     * Get the configured timeout from VS Code settings.
     */
    private getTimeout(): number {
        const config = vscode.workspace.getConfiguration('gradril');
        return config.get<number>('backendTimeout', 5000);
    }

    /**
     * Whether the backend is enabled in settings.
     */
    private isEnabled(): boolean {
        const config = vscode.workspace.getConfiguration('gradril');
        return config.get<boolean>('backendEnabled', true);
    }

    /**
     * Cached availability status from the last health check.
     */
    isAvailable(): boolean {
        return this._available;
    }

    /**
     * Start periodic health checks (every 60s).
     * Call this during extension activation.
     */
    startHealthChecks(): void {
        // Do an immediate health check
        this.healthCheck().catch(() => { /* swallow */ });

        // Schedule periodic checks
        this._healthCheckTimer = setInterval(() => {
            this.healthCheck().catch(() => { /* swallow */ });
        }, HEALTH_CHECK_INTERVAL_MS);
    }

    /**
     * Stop periodic health checks.
     * Call this during extension deactivation.
     */
    stopHealthChecks(): void {
        if (this._healthCheckTimer) {
            clearInterval(this._healthCheckTimer);
            this._healthCheckTimer = null;
        }
    }

    /**
     * Check if the backend server is reachable.
     * Updates the cached availability state.
     * 
     * @returns Health response or null if unreachable
     */
    async healthCheck(): Promise<BackendHealthResponse | null> {
        if (!this.isEnabled()) {
            this._available = false;
            return null;
        }

        try {
            const baseUrl = this.getBaseUrl();
            const response = await this.httpGet(`${baseUrl}/health`, 5000);
            const parsed = JSON.parse(response) as BackendHealthResponse;
            this._available = true;
            this._lastHealthCheck = Date.now();
            return parsed;
        } catch {
            this._available = false;
            return null;
        }
    }

    /**
     * Validate a prompt against the Guardrails AI server.
     * 
     * @param prompt    The user prompt to validate
     * @param guardName The guard to use (defaults to 'gradril_input_guard')
     * @returns         BackendResult with validation outcome, or null if unavailable
     */
    async validate(
        prompt: string,
        guardName: string = DEFAULT_GUARD_NAME
    ): Promise<BackendResult | null> {
        if (!this.isEnabled() || !this._available) {
            return null;
        }

        const startTime = Date.now();
        const baseUrl = this.getBaseUrl();
        const timeout = this.getTimeout();
        const endpoint = `${baseUrl}/guards/${encodeURIComponent(guardName)}/validate`;

        const requestBody: BackendRequest = {
            llmOutput: prompt,
            numReasks: 0,
        };

        let lastError: Error | null = null;

        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            try {
                // Exponential backoff on retries
                if (attempt > 0) {
                    const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                    await this.sleep(delay);
                }

                const rawResponse = await this.httpPost(
                    endpoint,
                    JSON.stringify(requestBody),
                    timeout
                );

                const response = this.parseResponse(rawResponse);
                const latencyMs = Date.now() - startTime;

                return {
                    available: true,
                    passed: response.validationPassed,
                    sanitizedOutput: response.validatedOutput,
                    validations: this.extractValidations(response),
                    raw: response,
                    latencyMs,
                };
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));

                // Don't retry on certain errors
                if (this.isNonRetryableError(lastError)) {
                    break;
                }
            }
        }

        // All retries exhausted — mark backend as unavailable
        this._available = false;
        const latencyMs = Date.now() - startTime;

        return {
            available: false,
            passed: true, // Fail open — don't block if backend is down
            sanitizedOutput: null,
            validations: [],
            raw: null,
            latencyMs,
            error: lastError?.message || 'Backend unavailable',
        };
    }

    /**
     * Validate an LLM response against the output guard (hallucination, bias, PII, toxicity).
     * Uses the Guardrails AI GroundedAIHallucination + BiasCheck validators.
     *
     * @param llmResponse The LLM-generated response text to validate
     * @param guardName   The output guard name (defaults to 'gradril_output_guard')
     * @returns           BackendOutputResult with hallucination/bias findings, or null if unavailable
     */
    async validateOutput(
        llmResponse: string,
        guardName: string = DEFAULT_OUTPUT_GUARD_NAME
    ): Promise<BackendOutputResult | null> {
        if (!this.isEnabled() || !this._available) {
            return null;
        }

        const startTime = Date.now();
        const baseUrl = this.getBaseUrl();
        const timeout = this.getTimeout();
        const endpoint = `${baseUrl}/guards/${encodeURIComponent(guardName)}/validate`;

        const requestBody: BackendRequest = {
            llmOutput: llmResponse,
            numReasks: 0,
        };

        let lastError: Error | null = null;

        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            try {
                if (attempt > 0) {
                    const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
                    await this.sleep(delay);
                }

                const rawResponse = await this.httpPost(
                    endpoint,
                    JSON.stringify(requestBody),
                    timeout
                );

                const response = this.parseResponse(rawResponse);
                const latencyMs = Date.now() - startTime;
                const validations = this.extractValidations(response);

                // Parse hallucination/bias signals from the response
                const hallucinationDetected = !response.validationPassed ||
                    validations.some(v => v.validatorName.toLowerCase().includes('hallucination') && !v.passed);
                const hallucinationScore = this.extractHallucinationScore(response, validations);
                const biasDetected = validations.some(v => v.validatorName.toLowerCase().includes('bias') && !v.passed);

                return {
                    available: true,
                    passed: response.validationPassed,
                    validatedOutput: response.validatedOutput,
                    validations,
                    hallucinationDetected,
                    hallucinationScore,
                    biasDetected,
                    raw: response,
                    latencyMs,
                };
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));
                if (this.isNonRetryableError(lastError)) {
                    break;
                }
            }
        }

        const latencyMs = Date.now() - startTime;
        return {
            available: false,
            passed: true,
            validatedOutput: null,
            validations: [],
            hallucinationDetected: false,
            hallucinationScore: 0,
            biasDetected: false,
            raw: null,
            latencyMs,
            error: lastError?.message || 'Backend unavailable',
        };
    }

    // ─── HTTP Primitives (Node.js built-in) ─────────────────────────────

    /**
     * HTTP GET request using Node.js built-in http/https modules.
     */
    private httpGet(requestUrl: string, timeoutMs: number): Promise<string> {
        return new Promise((resolve, reject) => {
            const parsed = new url.URL(requestUrl);
            const transport = parsed.protocol === 'https:' ? https : http;

            const options: http.RequestOptions = {
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: 'GET',
                timeout: timeoutMs,
                headers: {
                    'Accept': 'application/json',
                },
            };

            const req = transport.request(options, (res) => {
                let data = '';
                res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error(`Request timed out after ${timeoutMs}ms`));
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.end();
        });
    }

    /**
     * HTTP POST request using Node.js built-in http/https modules.
     */
    private httpPost(requestUrl: string, body: string, timeoutMs: number): Promise<string> {
        return new Promise((resolve, reject) => {
            const parsed = new url.URL(requestUrl);
            const transport = parsed.protocol === 'https:' ? https : http;

            const options: http.RequestOptions = {
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.pathname + parsed.search,
                method: 'POST',
                timeout: timeoutMs,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                },
            };

            const req = transport.request(options, (res) => {
                let data = '';
                res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error(`Request timed out after ${timeoutMs}ms`));
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.write(body);
            req.end();
        });
    }

    // ─── Response Parsing ───────────────────────────────────────────────

    /**
     * Parse the raw JSON response from the Guardrails AI server.
     * Handles both camelCase and snake_case field names.
     */
    private parseResponse(raw: string): BackendResponse {
        const data = JSON.parse(raw);

        return {
            callId: data.callId || data.call_id || '',
            rawLlmOutput: data.rawLlmOutput ?? data.raw_llm_output ?? null,
            validatedOutput: data.validatedOutput ?? data.validated_output ?? null,
            validationPassed: data.validationPassed ?? data.validation_passed ?? false,
            error: data.error || undefined,
        };
    }

    /**
     * Extract individual validation results from the backend response.
     * The Guardrails AI server may include validator logs in the response.
     */
    private extractValidations(response: BackendResponse): BackendValidation[] {
        // The basic ValidationOutcome doesn't always include per-validator details.
        // We infer from the overall result. In a more advanced integration,
        // we could fetch /guards/{name}/history/{call_id} for detailed logs.
        const validations: BackendValidation[] = [];

        if (response.error) {
            validations.push({
                validatorName: 'backend',
                passed: false,
                errorMessage: response.error,
            });
        } else {
            validations.push({
                validatorName: 'backend',
                passed: response.validationPassed,
                validatedOutput: response.validatedOutput || undefined,
            });
        }

        return validations;
    }

    /**
     * Determine if an error is non-retryable (e.g., 4xx client errors).
     */
    private isNonRetryableError(error: Error): boolean {
        const message = error.message || '';
        // Don't retry on client errors (4xx)
        if (/HTTP 4\d{2}/.test(message)) {
            return true;
        }
        return false;
    }

    /**
     * Extract hallucination score from the backend response.
     * GroundedAI returns a score in the validator metadata.
     */
    private extractHallucinationScore(
        _response: BackendResponse,
        validations: BackendValidation[]
    ): number {
        for (const v of validations) {
            if (v.validatorName.toLowerCase().includes('hallucination') && v.metadata) {
                // GroundedAI returns score in metadata as 'hallucination_score' or 'score'
                const score = v.metadata['hallucination_score'] ?? v.metadata['score'];
                if (typeof score === 'number') {
                    return score;
                }
            }
        }
        // If no explicit score, infer from pass/fail
        const hallucinationValidator = validations.find(
            v => v.validatorName.toLowerCase().includes('hallucination')
        );
        if (hallucinationValidator) {
            return hallucinationValidator.passed ? 0.1 : 0.8;
        }
        return 0;
    }

    /**
     * Simple async sleep helper.
     */
    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Clean up resources.
     */
    dispose(): void {
        this.stopHealthChecks();
    }
}
