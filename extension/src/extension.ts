// Gradril — VS Code Copilot Prompt Guardrail Extension
// Entry point: registers the @gradril chat participant, commands, and UI.
// Wires together all modules: validators, sanitizer, engine, backend, UI, logging.

import * as vscode from 'vscode';

// ─── Module Imports ─────────────────────────────────────────────────────────

import { ValidatorOrchestrator } from './validators/index';
import { PIIDetector } from './validators/piiDetector';
import { SecretDetector } from './validators/secretDetector';
import { InjectionDetector } from './validators/injectionDetector';
import { JailbreakDetector } from './validators/jailbreakDetector';
import { ToxicityDetector } from './validators/toxicityDetector';
import { CodeExfiltrationDetector } from './validators/codeExfiltrationDetector';

import { SanitizerOrchestrator } from './sanitizer/index';
import { PIIMasker } from './sanitizer/piiMasker';
import { SecretMasker } from './sanitizer/secretMasker';
import { InjectionStripper } from './sanitizer/injectionStripper';

import { RiskScorer } from './engine/riskScorer';
import { DecisionEngine } from './engine/decisionEngine';
import { ConversationTracker, sessionManager } from './engine/conversationTracker';

import { GuardrailsClient } from './backend/guardrailsClient';

import { GradrilSettings } from './config/settings';
import { OutputChannelLogger } from './logging/outputChannel';
import { AuditLog } from './logging/auditLog';

import { GradrilStatusBar } from './ui/statusBar';
import { FeedbackRenderer } from './ui/feedback';
import { AuditWebview } from './ui/auditWebview';

import { createHandler } from './participant/handler';

// ─── Preprocessors ──────────────────────────────────────────────────────────

import { TextNormalizer } from './preprocessor/textNormalizer';

// ─── Activate ───────────────────────────────────────────────────────────────

export async function activate(context: vscode.ExtensionContext) {
    // 1. Settings singleton
    const settings = GradrilSettings.instance;
    context.subscriptions.push(settings);

    // 2. Logger
    const logger = new OutputChannelLogger();
    context.subscriptions.push(logger);
    logger.info('Gradril activating...');

    // 3. Audit log
    const auditLog = new AuditLog();
    await auditLog.initialize();

    // 4. Validators
    const validatorOrchestrator = new ValidatorOrchestrator();

    const piiDetector = new PIIDetector();
    const secretDetector = new SecretDetector();
    const injectionDetector = new InjectionDetector();
    const jailbreakDetector = new JailbreakDetector();
    const toxicityDetector = new ToxicityDetector();
    
    // Enhanced validators (2024-2026 Research Contribution)
    const codeExfiltrationDetector = new CodeExfiltrationDetector();
    const conversationTracker = sessionManager.getTracker();

    // Load custom blocklist into toxicity detector
    toxicityDetector.setCustomBlocklist(settings.customBlocklist);

    // Register all validators
    validatorOrchestrator.register(piiDetector);
    validatorOrchestrator.register(secretDetector);
    validatorOrchestrator.register(injectionDetector);
    validatorOrchestrator.register(jailbreakDetector);
    validatorOrchestrator.register(toxicityDetector);
    validatorOrchestrator.register(codeExfiltrationDetector);
    validatorOrchestrator.register(conversationTracker);
    
    // 4.5. Text Normalizer (preprocessing layer for encoding evasion)
    const textNormalizer = new TextNormalizer();
    logger.info(`Registered ${validatorOrchestrator.getRegisteredNames().length} validators`);

    // 5. Sanitizer
    const sanitizerOrchestrator = new SanitizerOrchestrator();
    sanitizerOrchestrator.register(new PIIMasker());
    sanitizerOrchestrator.register(new SecretMasker());
    sanitizerOrchestrator.register(new InjectionStripper());

    // 6. Engine
    const riskScorer = new RiskScorer();
    const decisionEngine = new DecisionEngine(riskScorer);

    // 7. Backend client
    const guardrailsClient = new GuardrailsClient();
    if (settings.backendEnabled) {
        guardrailsClient.startHealthChecks();
    }

    // 8. UI
    const statusBar = new GradrilStatusBar();
    context.subscriptions.push(statusBar);
    const feedbackRenderer = new FeedbackRenderer();
    const auditWebview = new AuditWebview(auditLog);

    // Update status bar based on current state
    function updateStatusBar(): void {
        if (!settings.enabled) {
            statusBar.update('off');
        } else if (settings.backendEnabled && !guardrailsClient.isAvailable()) {
            statusBar.update('local-only');
        } else {
            statusBar.update('active');
        }
    }
    updateStatusBar();

    // 9. Chat Participant Handler
    const handler = createHandler({
        validatorOrchestrator,
        sanitizerOrchestrator,
        riskScorer,
        decisionEngine,
        guardrailsClient,
        settings,
        logger,
        auditLog,
        feedbackRenderer,
        textNormalizer,  // Enhanced: text preprocessing for encoding evasion
    });

    // 10. Register chat participant
    const participant = vscode.chat.createChatParticipant('gradril.guard', handler);
    participant.iconPath = vscode.Uri.joinPath(context.extensionUri, 'media', 'icon.png');
    context.subscriptions.push(participant);

    // 11. Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('gradril.toggleGuard', () => {
            const config = vscode.workspace.getConfiguration('gradril');
            const current = config.get<boolean>('enabled', true);
            config.update('enabled', !current, vscode.ConfigurationTarget.Workspace);
            vscode.window.showInformationMessage(
                `Gradril guard ${!current ? 'enabled' : 'disabled'}.`
            );
            logger.info(`Guard toggled: ${!current ? 'enabled' : 'disabled'}`);
            updateStatusBar();
        }),

        vscode.commands.registerCommand('gradril.openAuditLog', async () => {
            await auditWebview.open(context.extensionUri);
        }),

        vscode.commands.registerCommand('gradril.testConnection', async () => {
            const startMs = Date.now();
            const health = await guardrailsClient.healthCheck();
            const elapsed = Date.now() - startMs;

            if (health) {
                vscode.window.showInformationMessage(
                    `Gradril: Backend reachable (latency: ${elapsed}ms)`
                );
                logger.logBackend('health check OK', `${elapsed}ms`);
            } else {
                vscode.window.showErrorMessage(
                    'Gradril: Backend unreachable — check that the Guardrails AI server is running.'
                );
                logger.logBackend('health check FAILED');
            }
            updateStatusBar();
        })
    );

    // 12. Listen for settings changes
    settings.onDidChange(() => {
        // Reload custom blocklist
        toxicityDetector.setCustomBlocklist(settings.customBlocklist);

        // Manage backend health checks
        if (settings.backendEnabled) {
            guardrailsClient.startHealthChecks();
        } else {
            guardrailsClient.stopHealthChecks();
        }

        updateStatusBar();
        logger.info('Settings changed — reloaded.');
    });

    // 13. Cleanup on deactivation
    context.subscriptions.push({
        dispose: () => {
            guardrailsClient.dispose();
            auditWebview.dispose();
        }
    });

    logger.info('Gradril activation complete.');

    // 14. Auto-start: show notification and open chat with @gradril
    // Once the user sends the first message via @gradril, isSticky keeps it
    // selected for all subsequent messages — acting like an auto-connector.
    const isFirstRun = !context.globalState.get<boolean>('gradril.welcomed');
    if (isFirstRun) {
        const action = await vscode.window.showInformationMessage(
            '🛡️ Gradril is now active! All your Copilot prompts will be guarded for PII, secrets, injections & more.',
            'Open Gradril Chat',
            'Dismiss'
        );
        if (action === 'Open Gradril Chat') {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: '@gradril ' });
        }
        await context.globalState.update('gradril.welcomed', true);
    } else {
        // Returning user — silently open chat with @gradril pre-selected
        // so the guard is always active without any extra steps
        setTimeout(async () => {
            try {
                await vscode.commands.executeCommand('workbench.action.chat.open', { query: '@gradril ' });
            } catch {
                // Chat panel may already be open or command unavailable — silently ignore
            }
        }, 2000);
    }
}

export function deactivate() {
    GradrilSettings.reset();
}
