// Gradril — Chat Request Handler
// Core interception pipeline: normalize → validate → sanitize → decide → act.
// This is the main handler for the @gradril chat participant.

import * as vscode from 'vscode';

import { ValidatorOrchestrator, ValidatorResult, Finding } from '../validators/index';
import { SanitizerOrchestrator, SanitizeResult } from '../sanitizer/index';
import { RiskScorer } from '../engine/riskScorer';
import { DecisionEngine, Decision } from '../engine/decisionEngine';
import { GuardrailsClient } from '../backend/guardrailsClient';
import { GradrilSettings } from '../config/settings';
import { OutputChannelLogger } from '../logging/outputChannel';
import { AuditLog } from '../logging/auditLog';
import { FeedbackRenderer } from '../ui/feedback';
import { TextNormalizer, NormalizationResult } from '../preprocessor/textNormalizer';

// ─── Handler Dependencies ───────────────────────────────────────────────────

export interface HandlerDependencies {
    validatorOrchestrator: ValidatorOrchestrator;
    sanitizerOrchestrator: SanitizerOrchestrator;
    riskScorer: RiskScorer;
    decisionEngine: DecisionEngine;
    guardrailsClient: GuardrailsClient;
    settings: GradrilSettings;
    logger: OutputChannelLogger;
    auditLog: AuditLog;
    feedbackRenderer: FeedbackRenderer;
    textNormalizer?: TextNormalizer;  // Optional: text preprocessing
}

// ─── Handler ────────────────────────────────────────────────────────────────

/**
 * Creates the `vscode.ChatRequestHandler` function that processes all
 * @gradril chat messages and slash commands.
 */
export function createHandler(deps: HandlerDependencies): vscode.ChatRequestHandler {

    return async (
        request: vscode.ChatRequest,
        _context: vscode.ChatContext,
        stream: vscode.ChatResponseStream,
        token: vscode.CancellationToken
    ): Promise<vscode.ChatResult> => {

        // ── Slash commands ──────────────────────────────────────────
        if (request.command === 'scan') {
            return handleScan(request, stream, token, deps);
        }
        if (request.command === 'status') {
            return handleStatus(stream, deps);
        }
        if (request.command === 'config') {
            return handleConfig(stream);
        }

        // ── Guard disabled → pass-through ───────────────────────────
        if (!deps.settings.enabled) {
            deps.logger.info('Guard disabled — passing through to LLM.');
            return forwardToLLM(request, stream, token);
        }

        // ── Full validation pipeline ────────────────────────────────
        const startTime = Date.now();
        const prompt = request.prompt;

        stream.progress('Scanning prompt for security risks...');

        // 0. Preprocess: Normalize text to defeat encoding evasion attacks
        let normalizedPrompt = prompt;
        let normalizationResult: NormalizationResult | undefined;
        
        if (deps.textNormalizer) {
            normalizationResult = deps.textNormalizer.normalize(prompt);
            normalizedPrompt = normalizationResult.normalized;
            
            // Log obfuscation detection
            if (normalizationResult.wasTransformed) {
                deps.logger.info(
                    `Text normalization applied: ${normalizationResult.transformations.join(', ')} ` +
                    `(obfuscation score: ${normalizationResult.obfuscationScore.toFixed(2)})`
                );
            }
        }

        // 1. Run local validators in parallel (on normalized text)
        const enabledList = deps.settings.enabledValidators;
        let localResults: ValidatorResult[];
        try {
            localResults = await deps.validatorOrchestrator.runAll(normalizedPrompt, enabledList);
        } catch (err) {
            deps.logger.error(`Validator error: ${err}`);
            localResults = [];
        }
        
        // Add obfuscation finding if significant obfuscation was detected
        if (normalizationResult && normalizationResult.obfuscationScore > 0.15) {
            const obfuscationFinding: Finding = {
                type: 'OBFUSCATION_DETECTED',
                match: `Detected encoding evasion: ${normalizationResult.transformations.join(', ')}`,
                position: 0,
                length: prompt.length,
                confidence: Math.min(normalizationResult.obfuscationScore * 2, 0.95),
                severity: normalizationResult.obfuscationScore > 0.3 ? 'high' : 'medium',
                validator: 'normalizer',
            };
            
            // Create a synthetic result for the obfuscation detection
            localResults.push({
                validatorName: 'normalizer',
                detected: true,
                severity: obfuscationFinding.severity,
                findings: [obfuscationFinding],
                score: normalizationResult.obfuscationScore,
            });
        }

        if (token.isCancellationRequested) { return {}; }

        // 2. Run backend validation in parallel (if enabled and available)
        let backendUsed = false;
        if (deps.settings.backendEnabled && deps.guardrailsClient.isAvailable()) {
            try {
                const backendResult = await deps.guardrailsClient.validate(prompt);
                if (backendResult && backendResult.available && !backendResult.passed) {
                    // Backend flagged the prompt — inject a synthetic result
                    const backendValidatorResult: ValidatorResult = {
                        validatorName: 'backend',
                        detected: true,
                        severity: 'high',
                        findings: [{
                            type: 'BACKEND_FLAG',
                            match: '[backend validation failed]',
                            position: 0,
                            length: prompt.length,
                            confidence: 0.9,
                            severity: 'high',
                            validator: 'backend',
                        }],
                        score: 0.8,
                    };
                    localResults.push(backendValidatorResult);
                    backendUsed = true;
                    deps.logger.logBackend('validation failed', backendResult.error);
                } else if (backendResult?.available) {
                    backendUsed = true;
                    deps.logger.logBackend('validation passed');
                } else {
                    deps.logger.logBackend('unavailable — using local only');
                }
            } catch (err) {
                deps.logger.warn(`Backend error: ${err}`);
            }
        }

        if (token.isCancellationRequested) { return {}; }

        // 3. Flatten findings and sanitize
        const allFindings = ValidatorOrchestrator.flattenFindings(localResults);
        const sanitizeResult = deps.sanitizerOrchestrator.sanitize(prompt, allFindings);

        // 4. Decide
        const decision = deps.decisionEngine.decide(localResults, sanitizeResult, allFindings);
        const latencyMs = Date.now() - startTime;
        decision.latencyMs = latencyMs;

        // 5. Log
        deps.logger.logDecision(decision.action, decision.riskScore, latencyMs);

        if (deps.settings.auditLogEnabled) {
            const findingSummary = allFindings.map(f => ({
                type: f.type,
                severity: f.severity,
                validator: f.validator,
            }));
            await deps.auditLog.log(
                prompt,
                decision.action.toLowerCase() as 'allow' | 'sanitize',
                decision.riskScore,
                findingSummary,
                backendUsed,
                latencyMs
            );
        }

        if (token.isCancellationRequested) { return {}; }

        // 6. Act on decision
        switch (decision.action) {
            case 'ALLOW':
                return handleAllow(request, stream, token, deps);

            case 'SANITIZE':
                return handleSanitize(request, stream, token, decision, sanitizeResult, deps);
        }
    };
}

// ─── Decision Handlers ──────────────────────────────────────────────────────

/**
 * ALLOW: Forward original prompt to LLM, then analyze response for hallucinations.
 * Uses Guardrails AI backend (GroundedAIHallucination) when available, local regex as fallback.
 */
async function handleAllow(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken,
    deps: HandlerDependencies
): Promise<vscode.ChatResult> {
    const { responseText, result } = await forwardToLLMAndCapture(request, stream, token);

    // Run hallucination analysis (backend ML + local heuristics)
    const hallucinationResult = await analyzeForHallucination(responseText, deps);

    if (hallucinationResult.hasHallucination) {
        deps.feedbackRenderer.renderHallucinationAnalysis(stream, hallucinationResult);
        deps.logger.info(
            `Hallucination detected: score=${hallucinationResult.overallScore.toFixed(2)}, ` +
            `grounded=${hallucinationResult.counts.grounded}, ` +
            `uncertain=${hallucinationResult.counts.uncertain}, ` +
            `hallucinated=${hallucinationResult.counts.hallucinated}`
        );
    } else {
        deps.feedbackRenderer.renderHallucinationBadge(stream, hallucinationResult);
    }

    deps.feedbackRenderer.renderAllowFooter(stream);
    return { ...result, metadata: { decision: 'allow', hallucinationScore: hallucinationResult.overallScore } };
}

/**
 * SANITIZE: Show warning, forward sanitized prompt to LLM, analyze response.
 */
async function handleSanitize(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken,
    decision: Decision,
    sanitizeResult: SanitizeResult,
    deps: HandlerDependencies
): Promise<vscode.ChatResult> {
    // Show sanitization header
    deps.feedbackRenderer.renderSanitizeHeader(stream, decision, sanitizeResult);

    // Forward sanitized prompt to LLM and capture the response text
    const sanitizedPrompt = sanitizeResult.sanitized;
    let responseText = '';
    try {
        const messages = [
            vscode.LanguageModelChatMessage.User(sanitizedPrompt)
        ];
        const response = await request.model.sendRequest(messages, {}, token);
        for await (const chunk of response.text) {
            if (token.isCancellationRequested) { break; }
            stream.markdown(chunk);
            responseText += chunk;
        }
    } catch (err) {
        if (!token.isCancellationRequested) {
            deps.logger.error(`LLM error (sanitized path): ${err}`);
            stream.markdown('\n\n*Error communicating with the language model.*\n');
        }
    }

    // Run hallucination analysis on LLM response (backend ML + local heuristics)
    if (responseText.length > 0) {
        const hallucinationResult = await analyzeForHallucination(responseText, deps);
        if (hallucinationResult.hasHallucination) {
            deps.feedbackRenderer.renderHallucinationAnalysis(stream, hallucinationResult);
        } else {
            deps.feedbackRenderer.renderHallucinationBadge(stream, hallucinationResult);
        }
    }

    deps.feedbackRenderer.renderSanitizeFooter(stream);
    return { metadata: { decision: 'sanitize', riskScore: decision.riskScore } };
}

/**
 * Forward a prompt directly to the LLM, stream response, and capture the full text.
 * Returns both the chat result and the collected response text for hallucination analysis.
 */
async function forwardToLLMAndCapture(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<{ responseText: string; result: vscode.ChatResult }> {
    let responseText = '';
    try {
        const messages = [
            vscode.LanguageModelChatMessage.User(request.prompt)
        ];
        const response = await request.model.sendRequest(messages, {}, token);
        for await (const chunk of response.text) {
            if (token.isCancellationRequested) { break; }
            stream.markdown(chunk);
            responseText += chunk;
        }
    } catch (err) {
        if (!token.isCancellationRequested) {
            stream.markdown('*Error communicating with the language model.*\n');
        }
    }
    return { responseText, result: {} };
}

// ─── Hallucination Analysis (Guardrails AI Backend) ─────────────────────────

import { HallucinationResult } from '../backend/types';

/**
 * Analyze LLM output for hallucinations using the Guardrails AI backend.
 *
 * Calls `POST /guards/gradril_output_guard/validate` which runs:
 *   - GroundedAIHallucination (ML-based hallucination detection)
 *   - BiasCheck (ML-based bias classifier)
 *   - ToxicLanguage (toxic content in output)
 *   - DetectPII (PII leakage from LLM)
 *
 * Converts the BackendOutputResult into a HallucinationResult for the UI
 * to render color-coded confidence indicators.
 *
 * Returns a "no data" result when the backend is unavailable.
 */
async function analyzeForHallucination(
    responseText: string,
    deps: HandlerDependencies
): Promise<HallucinationResult> {
    // Backend must be enabled and available
    if (!deps.settings.backendEnabled || !deps.guardrailsClient.isAvailable()) {
        deps.logger.info('Backend unavailable — skipping hallucination analysis.');
        return createUnavailableResult();
    }

    try {
        const backendResult = await deps.guardrailsClient.validateOutput(responseText);

        if (!backendResult || !backendResult.available) {
            deps.logger.warn('Backend output guard returned unavailable — skipping hallucination analysis.');
            return createUnavailableResult();
        }

        deps.logger.info(
            `Guardrails AI output guard: hallucination=${backendResult.hallucinationDetected}, ` +
            `score=${backendResult.hallucinationScore.toFixed(2)}, ` +
            `bias=${backendResult.biasDetected}, ` +
            `passed=${backendResult.passed}, ` +
            `latency=${backendResult.latencyMs}ms`
        );

        // Convert BackendOutputResult → HallucinationResult for the UI
        return convertBackendToHallucinationResult(responseText, backendResult);

    } catch (err) {
        deps.logger.warn(`Backend output validation error: ${err}`);
        return createUnavailableResult();
    }
}

/**
 * Convert a BackendOutputResult (from Guardrails AI) into a HallucinationResult
 * that the FeedbackRenderer can display with color-coded indicators.
 */
function convertBackendToHallucinationResult(
    responseText: string,
    backendResult: import('../backend/types').BackendOutputResult
): HallucinationResult {
    // GroundedAI score: high = hallucinated. Our UI: high = grounded. Invert.
    const groundingScore = 1 - backendResult.hallucinationScore;

    // Classify overall level
    let overallLevel: import('../backend/types').HallucinationLevel;
    if (groundingScore >= 0.7) { overallLevel = 'grounded'; }
    else if (groundingScore >= 0.4) { overallLevel = 'uncertain'; }
    else { overallLevel = 'hallucinated'; }

    const sentences: import('../backend/types').SentenceAnalysis[] = [];
    const counts = { grounded: 0, uncertain: 0, hallucinated: 0 };

    // Main hallucination assessment from GroundedAIHallucination
    if (backendResult.hallucinationDetected) {
        sentences.push({
            text: responseText.length > 200 ? responseText.slice(0, 200) + '...' : responseText,
            confidence: groundingScore,
            level: overallLevel,
            reasons: [`GroundedAIHallucination: score ${backendResult.hallucinationScore.toFixed(2)} (ML model)`],
        });
        counts[overallLevel]++;
    } else {
        sentences.push({
            text: responseText.length > 200 ? responseText.slice(0, 200) + '...' : responseText,
            confidence: groundingScore,
            level: 'grounded',
            reasons: ['GroundedAIHallucination: response appears well-grounded (ML model)'],
        });
        counts.grounded++;
    }

    // Bias flag from BiasCheck
    if (backendResult.biasDetected) {
        sentences.push({
            text: '[Guardrails AI: BiasCheck detected potential bias in response]',
            confidence: 0.4,
            level: 'uncertain',
            reasons: ['Bias detected by ML classifier (Guardrails AI BiasCheck)'],
        });
        counts.uncertain++;
    }

    // Add per-validator details if available
    for (const v of backendResult.validations) {
        if (!v.passed && !v.validatorName.toLowerCase().includes('hallucination') &&
            !v.validatorName.toLowerCase().includes('bias')) {
            sentences.push({
                text: `[${v.validatorName}: ${v.errorMessage || 'validation failed'}]`,
                confidence: 0.3,
                level: 'hallucinated',
                reasons: [`${v.validatorName} flagged this response`],
            });
            counts.hallucinated++;
        }
    }

    const hasHallucination = backendResult.hallucinationDetected ||
                             backendResult.biasDetected ||
                             !backendResult.passed;

    return {
        sentences,
        overallScore: groundingScore,
        overallLevel,
        counts,
        hasHallucination,
    };
}

/**
 * Return a neutral result when the backend is unavailable.
 * The UI will show a simple "analysis unavailable" badge.
 */
function createUnavailableResult(): HallucinationResult {
    return {
        sentences: [{
            text: '[Hallucination analysis unavailable — Guardrails AI backend not connected]',
            confidence: 1.0,
            level: 'grounded',
            reasons: ['Backend unavailable — no analysis performed'],
        }],
        overallScore: 1.0,
        overallLevel: 'grounded',
        counts: { grounded: 1, uncertain: 0, hallucinated: 0 },
        hasHallucination: false,
    };
}

/**
 * Forward a prompt directly to the LLM and stream the response (legacy, no capture).
 */
async function forwardToLLM(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    const { result } = await forwardToLLMAndCapture(request, stream, token);
    return result;
}

// ─── Slash Command Handlers ─────────────────────────────────────────────────

/**
 * /scan — Dry-run validation with full report, no LLM call.
 */
async function handleScan(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken,
    deps: HandlerDependencies
): Promise<vscode.ChatResult> {
    const startTime = Date.now();
    const prompt = request.prompt;

    if (!prompt.trim()) {
        stream.markdown('*Please provide text to scan. Usage:* `/scan your text here`\n');
        return {};
    }

    stream.progress('Running security scan...');

    // Run local validators
    const enabledList = deps.settings.enabledValidators;
    const localResults = await deps.validatorOrchestrator.runAll(prompt, enabledList);

    if (token.isCancellationRequested) { return {}; }

    // Sanitize
    const allFindings = ValidatorOrchestrator.flattenFindings(localResults);
    const sanitizeResult = deps.sanitizerOrchestrator.sanitize(prompt, allFindings);

    // Decide
    const decision = deps.decisionEngine.decide(localResults, sanitizeResult, allFindings);
    decision.latencyMs = Date.now() - startTime;

    // Render report (no LLM call)
    deps.feedbackRenderer.renderScanReport(stream, decision, sanitizeResult);

    return { metadata: { command: 'scan', decision: decision.action } };
}

/**
 * /status — Show configuration and session statistics.
 */
async function handleStatus(
    stream: vscode.ChatResponseStream,
    deps: HandlerDependencies
): Promise<vscode.ChatResult> {
    deps.feedbackRenderer.renderStatusReport(
        stream,
        {
            enabled: deps.settings.enabled,
            backendEnabled: deps.settings.backendEnabled,
            backendAvailable: deps.guardrailsClient.isAvailable(),
            backendUrl: deps.settings.backendUrl,
            sanitizeThreshold: deps.settings.sanitizeThreshold,
            enabledValidators: deps.settings.enabledValidators,
        },
        deps.auditLog.getStats()
    );
    return { metadata: { command: 'status' } };
}

/**
 * /config — Open Gradril settings in VS Code.
 */
async function handleConfig(
    stream: vscode.ChatResponseStream
): Promise<vscode.ChatResult> {
    stream.markdown('*Opening Gradril settings...*\n');
    await vscode.commands.executeCommand('workbench.action.openSettings', 'gradril');
    return { metadata: { command: 'config' } };
}
