// Gradril — Status Bar Item
// Shows the guard state in the VS Code status bar.
// States: Active (green), Local Only (yellow), Off (grey).

import * as vscode from 'vscode';

// ─── Types ──────────────────────────────────────────────────────────────────

export type StatusBarState = 'active' | 'local-only' | 'off';

// ─── Status Bar ─────────────────────────────────────────────────────────────

/**
 * Manages the Gradril status bar item. Click toggles the guard.
 */
export class GradrilStatusBar {
    private item: vscode.StatusBarItem;
    private currentState: StatusBarState = 'off';

    constructor() {
        this.item = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.item.command = 'gradril.toggleGuard';
        this.update('active');
        this.item.show();
    }

    /**
     * Update the status bar state.
     */
    update(state: StatusBarState): void {
        this.currentState = state;

        switch (state) {
            case 'active':
                this.item.text = '$(shield) Gradril: Active';
                this.item.backgroundColor = undefined;
                this.item.color = new vscode.ThemeColor('statusBarItem.foreground');
                this.item.tooltip = 'Gradril Guard — Active (local + backend)\nClick to toggle';
                break;

            case 'local-only':
                this.item.text = '$(shield) Gradril: Local Only';
                this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                this.item.color = undefined;
                this.item.tooltip = 'Gradril Guard — Backend offline, using local validation only\nClick to toggle';
                break;

            case 'off':
                this.item.text = '$(shield) Gradril: Off';
                this.item.backgroundColor = undefined;
                this.item.color = new vscode.ThemeColor('disabledForeground');
                this.item.tooltip = 'Gradril Guard — Disabled\nClick to enable';
                break;
        }
    }

    /**
     * Get the current state.
     */
    getState(): StatusBarState {
        return this.currentState;
    }

    /**
     * Get the underlying status bar item (for disposal).
     */
    getItem(): vscode.StatusBarItem {
        return this.item;
    }

    dispose(): void {
        this.item.dispose();
    }
}
