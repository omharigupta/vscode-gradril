// Gradril — Audit Log Webview
// Displays the .gradril/audit.jsonl entries in a VS Code Webview panel.

import * as vscode from 'vscode';
import { AuditLog, AuditEntry } from '../logging/auditLog';

// ─── Audit Webview ──────────────────────────────────────────────────────────

/**
 * Opens and manages a Webview panel showing the Gradril audit log.
 */
export class AuditWebview {
    private panel: vscode.WebviewPanel | null = null;
    private auditLog: AuditLog;
    private watcher: vscode.FileSystemWatcher | null = null;

    constructor(auditLog: AuditLog) {
        this.auditLog = auditLog;
    }

    /**
     * Open the audit log webview, creating it if needed.
     */
    async open(extensionUri: vscode.Uri): Promise<void> {
        if (this.panel) {
            this.panel.reveal();
            await this.refresh();
            return;
        }

        this.panel = vscode.window.createWebviewPanel(
            'gradrilAuditLog',
            'Gradril Audit Log',
            vscode.ViewColumn.One,
            {
                enableScripts: false,
                localResourceRoots: [],
            }
        );

        this.panel.onDidDispose(() => {
            this.panel = null;
            this.disposeWatcher();
        });

        // Watch for audit file changes
        const logPath = this.auditLog.getLogFilePath();
        if (logPath) {
            this.watcher = vscode.workspace.createFileSystemWatcher(logPath);
            this.watcher.onDidChange(() => this.refresh());
            this.watcher.onDidCreate(() => this.refresh());
        }

        await this.refresh();
    }

    /**
     * Refresh the webview content from the audit log.
     */
    private async refresh(): Promise<void> {
        if (!this.panel) { return; }

        const entries = await this.auditLog.readAll();
        this.panel.webview.html = this.buildHtml(entries);
    }

    /**
     * Build the HTML content for the webview.
     */
    private buildHtml(entries: AuditEntry[]): string {
        const rows = entries
            .slice()
            .reverse() // newest first
            .map((e, i) => {
                const badge = this.decisionBadge(e.decision);
                const findingSummary = e.findings.length > 0
                    ? e.findings.map(f => `${f.type} (${f.severity})`).join(', ')
                    : 'None';
                const scoreBar = this.scoreBar(e.riskScore);
                const ts = new Date(e.timestamp).toLocaleString();
                const bgColor = i % 2 === 0 ? '#1e1e1e' : '#252526';

                return `<tr style="background:${bgColor}">
                    <td>${ts}</td>
                    <td>${badge}</td>
                    <td>${scoreBar} ${e.riskScore.toFixed(2)}</td>
                    <td>${findingSummary}</td>
                    <td>${e.latencyMs}ms</td>
                    <td>${e.backendUsed ? '✅' : '❌'}</td>
                </tr>`;
            })
            .join('\n');

        const stats = this.auditLog.getStats();

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: var(--vscode-font-family, sans-serif); color: #ccc; background: #1e1e1e; margin: 8px; }
        h1 { font-size: 1.3em; margin-bottom: 4px; }
        .stats { display: flex; gap: 16px; margin-bottom: 12px; font-size: 0.9em; }
        .stat { padding: 4px 10px; border-radius: 4px; }
        .stat-allow { background: #2d4a2d; }
        .stat-sanitize { background: #4a3d2d; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #444; background: #2d2d30; }
        td { padding: 5px 8px; border-bottom: 1px solid #333; }
        .badge { padding: 2px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }
        .badge-allow { background: #2d6a2d; color: #8f8; }
        .badge-sanitize { background: #6a5a2d; color: #ff8; }
        .score-bar { display: inline-block; width: 60px; height: 10px; background: #333; border-radius: 3px; overflow: hidden; vertical-align: middle; }
        .score-fill { height: 100%; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🛡️ Gradril Audit Log</h1>
    <div class="stats">
        <span class="stat">Total: ${stats.total}</span>
        <span class="stat stat-allow">Allowed: ${stats.allowed}</span>
        <span class="stat stat-sanitize">Sanitized: ${stats.sanitized}</span>
    </div>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Decision</th>
                <th>Risk Score</th>
                <th>Findings</th>
                <th>Latency</th>
                <th>Backend</th>
            </tr>
        </thead>
        <tbody>
            ${rows || '<tr><td colspan="6" style="text-align:center;padding:20px;">No entries yet</td></tr>'}
        </tbody>
    </table>
</body>
</html>`;
    }

    private decisionBadge(decision: string): string {
        const cls = `badge-${decision}`;
        const label = decision.charAt(0).toUpperCase() + decision.slice(1);
        return `<span class="badge ${cls}">${label}</span>`;
    }

    private scoreBar(score: number): string {
        const pct = Math.round(score * 100);
        const color = score < 0.3 ? '#4a4' : score < 0.7 ? '#cc4' : '#c44';
        return `<span class="score-bar"><span class="score-fill" style="width:${pct}%;background:${color}"></span></span>`;
    }

    private disposeWatcher(): void {
        if (this.watcher) {
            this.watcher.dispose();
            this.watcher = null;
        }
    }

    dispose(): void {
        this.disposeWatcher();
        if (this.panel) {
            this.panel.dispose();
            this.panel = null;
        }
    }
}
