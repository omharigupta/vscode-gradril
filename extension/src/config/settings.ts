// Gradril — Settings Reader
// Typed, singleton settings reader with hot-reload support.
// Wraps vscode.workspace.getConfiguration('gradril') with typed getters.

import * as vscode from 'vscode';

// ─── Settings ───────────────────────────────────────────────────────────────

/**
 * Typed settings reader for all `gradril.*` configuration keys.
 * Singleton pattern — use `GradrilSettings.instance` across the extension.
 */
export class GradrilSettings {
    private static _instance: GradrilSettings | null = null;
    private _onDidChange: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    private _disposable: vscode.Disposable;

    /**
     * Fires when any `gradril.*` setting changes.
     */
    readonly onDidChange: vscode.Event<void> = this._onDidChange.event;

    private constructor() {
        // Listen for configuration changes and fire event if gradril.* changed
        this._disposable = vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('gradril')) {
                this._onDidChange.fire();
            }
        });
    }

    /**
     * Get the singleton instance.
     */
    static get instance(): GradrilSettings {
        if (!GradrilSettings._instance) {
            GradrilSettings._instance = new GradrilSettings();
        }
        return GradrilSettings._instance;
    }

    /**
     * Reset the singleton (for testing).
     */
    static reset(): void {
        if (GradrilSettings._instance) {
            GradrilSettings._instance.dispose();
            GradrilSettings._instance = null;
        }
    }

    // ─── Typed Getters ──────────────────────────────────────────────────

    private get config(): vscode.WorkspaceConfiguration {
        return vscode.workspace.getConfiguration('gradril');
    }

    /** Master toggle for the guard */
    get enabled(): boolean {
        return this.config.get<boolean>('enabled', true);
    }

    /** URL of the Guardrails AI backend server */
    get backendUrl(): string {
        return this.config.get<string>('backendUrl', 'http://localhost:8000');
    }

    /** Whether to call the backend for deep ML validation */
    get backendEnabled(): boolean {
        return this.config.get<boolean>('backendEnabled', true);
    }

    /** Backend request timeout in milliseconds */
    get backendTimeout(): number {
        return this.config.get<number>('backendTimeout', 2000);
    }

    /** Risk score threshold above which prompts are sanitized (0-1) */
    get sanitizeThreshold(): number {
        return this.config.get<number>('sanitizeThreshold', 0.3);
    }

    /** List of enabled validator names */
    get enabledValidators(): string[] {
        return this.config.get<string[]>('enabledValidators', [
            'pii', 'secrets', 'injection', 'jailbreak', 'toxicity'
        ]);
    }

    /** Custom blocklist terms/patterns */
    get customBlocklist(): string[] {
        return this.config.get<string[]>('customBlocklist', []);
    }

    /** Whether local audit logging is enabled */
    get auditLogEnabled(): boolean {
        return this.config.get<boolean>('auditLogEnabled', true);
    }

    // ─── Disposal ───────────────────────────────────────────────────────

    dispose(): void {
        this._disposable.dispose();
        this._onDidChange.dispose();
    }
}
