// Gradril — Output Channel Logger
// Structured logging to VS Code Output panel with severity levels.

import * as vscode from 'vscode';

// ─── Log Levels ─────────────────────────────────────────────────────────────

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

// ─── Output Channel Logger ──────────────────────────────────────────────────

/**
 * Logs to the "Gradril" output channel in VS Code.
 * Format: [ISO-timestamp] [LEVEL] message
 */
export class OutputChannelLogger {
    private channel: vscode.OutputChannel;

    constructor() {
        this.channel = vscode.window.createOutputChannel('Gradril');
    }

    /**
     * Get the underlying output channel (for disposal).
     */
    getChannel(): vscode.OutputChannel {
        return this.channel;
    }

    /**
     * Show the output channel in the VS Code panel.
     */
    show(): void {
        this.channel.show(true);
    }

    // ─── Logging Methods ────────────────────────────────────────────────

    debug(msg: string): void {
        this.log('DEBUG', msg);
    }

    info(msg: string): void {
        this.log('INFO', msg);
    }

    warn(msg: string): void {
        this.log('WARN', msg);
    }

    error(msg: string): void {
        this.log('ERROR', msg);
    }

    /**
     * Log a decision event with structured details.
     */
    logDecision(decision: string, score: number, latencyMs: number): void {
        this.info(`Decision: ${decision} (score: ${score.toFixed(2)}, latency: ${latencyMs}ms)`);
    }

    /**
     * Log a backend event.
     */
    logBackend(event: string, details?: string): void {
        const suffix = details ? ` — ${details}` : '';
        this.info(`Backend: ${event}${suffix}`);
    }

    // ─── Internal ───────────────────────────────────────────────────────

    private log(level: LogLevel, msg: string): void {
        const ts = new Date().toISOString();
        this.channel.appendLine(`[${ts}] [${level}] ${msg}`);
    }

    dispose(): void {
        this.channel.dispose();
    }
}
