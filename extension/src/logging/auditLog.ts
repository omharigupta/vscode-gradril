// Gradril — Audit Logger
// Append-only JSON-lines audit trail stored in .gradril/audit.jsonl.
// NEVER stores raw prompt text — only SHA-256 hashes.

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * A single audit log entry.
 */
export interface AuditEntry {
    /** ISO 8601 timestamp */
    timestamp: string;
    /** SHA-256 hash of the raw prompt (never stores raw text) */
    promptHash: string;
    /** The decision that was made */
    decision: 'allow' | 'sanitize';
    /** Aggregated risk score (0–1) */
    riskScore: number;
    /** Summary of findings (type + severity + validator only) */
    findings: { type: string; severity: string; validator: string }[];
    /** Whether the backend was used in this validation */
    backendUsed: boolean;
    /** Total pipeline latency in milliseconds */
    latencyMs: number;
}

/**
 * Aggregate statistics from the audit log.
 */
export interface AuditStats {
    total: number;
    allowed: number;
    sanitized: number;
}

// ─── Audit Logger ───────────────────────────────────────────────────────────

/**
 * Append-only JSON-lines logger for audit trail.
 * 
 * File: `.gradril/audit.jsonl` in the workspace root.
 * Each line is a JSON-serialized AuditEntry.
 */
export class AuditLog {
    private logDir: string | null = null;
    private logFile: string | null = null;
    private stats: AuditStats = { total: 0, allowed: 0, sanitized: 0 };
    private initialized: boolean = false;

    /**
     * Initialize the audit log directory and file path.
     * Auto-creates .gradril/ if it doesn't exist.
     */
    async initialize(): Promise<void> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            // No workspace — audit logging disabled
            return;
        }

        const root = workspaceFolders[0].uri.fsPath;
        this.logDir = path.join(root, '.gradril');
        this.logFile = path.join(this.logDir, 'audit.jsonl');

        // Create .gradril/ directory if it doesn't exist
        try {
            if (!fs.existsSync(this.logDir)) {
                fs.mkdirSync(this.logDir, { recursive: true });
            }
            // Load existing stats
            await this.loadStats();
            this.initialized = true;
        } catch {
            // Silently fail — audit logging is best-effort
            this.initialized = false;
        }
    }

    /**
     * Log an audit entry. Appends a JSON line to the audit file.
     * 
     * @param prompt    The raw prompt (will be hashed, NEVER stored)
     * @param decision  The decision made
     * @param riskScore The aggregated risk score
     * @param findings  Findings summary (type, severity, validator only)
     * @param backendUsed Whether the backend was consulted
     * @param latencyMs Pipeline latency
     */
    async log(
        prompt: string,
        decision: 'allow' | 'sanitize',
        riskScore: number,
        findings: { type: string; severity: string; validator: string }[],
        backendUsed: boolean,
        latencyMs: number
    ): Promise<void> {
        if (!this.initialized || !this.logFile) {
            return;
        }

        const entry: AuditEntry = {
            timestamp: new Date().toISOString(),
            promptHash: this.hashPrompt(prompt),
            decision,
            riskScore,
            findings,
            backendUsed,
            latencyMs,
        };

        try {
            fs.appendFileSync(this.logFile, JSON.stringify(entry) + '\n', 'utf-8');
            // Update in-memory stats
            this.stats.total++;
            if (decision === 'allow') { this.stats.allowed++; }
            else if (decision === 'sanitize') { this.stats.sanitized++; }
        } catch {
            // Silently fail — audit logging is best-effort
        }
    }

    /**
     * Read all entries from the audit log.
     */
    async readAll(): Promise<AuditEntry[]> {
        if (!this.logFile || !fs.existsSync(this.logFile)) {
            return [];
        }

        try {
            const content = fs.readFileSync(this.logFile, 'utf-8');
            const lines = content.trim().split('\n').filter(l => l.length > 0);
            return lines.map(line => JSON.parse(line) as AuditEntry);
        } catch {
            return [];
        }
    }

    /**
     * Get aggregate statistics.
     */
    getStats(): AuditStats {
        return { ...this.stats };
    }

    /**
     * Get the path to the audit log file.
     */
    getLogFilePath(): string | null {
        return this.logFile;
    }

    // ─── Internal ───────────────────────────────────────────────────────

    /**
     * SHA-256 hash of the prompt. NEVER stores the raw prompt.
     */
    private hashPrompt(prompt: string): string {
        return crypto.createHash('sha256').update(prompt, 'utf-8').digest('hex');
    }

    /**
     * Load stats from existing audit file.
     */
    private async loadStats(): Promise<void> {
        if (!this.logFile || !fs.existsSync(this.logFile)) {
            return;
        }

        try {
            const entries = await this.readAll();
            this.stats = {
                total: entries.length,
                allowed: entries.filter(e => e.decision === 'allow').length,
                sanitized: entries.filter(e => e.decision === 'sanitize').length,
            };
        } catch {
            // Reset stats on error
            this.stats = { total: 0, allowed: 0, sanitized: 0 };
        }
    }
}
