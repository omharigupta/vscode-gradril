// Gradril — Jailbreak Detector
// Detects attempts to bypass AI safety: DAN, developer mode, hypothetical
// framing, base64 evasion, unicode obfuscation, roleplay escalation

import { Validator, ValidatorResult, Finding, Severity } from './index';

// ─── Pattern Definitions ────────────────────────────────────────────────────

interface JailbreakPattern {
    category: string;
    regex: RegExp;
    severity: Severity;
    confidence: number;
    weight: number;
}

const JAILBREAK_PATTERNS: JailbreakPattern[] = [
    // ── Named Jailbreaks ────────────────────────────────────────────────
    {
        category: 'NAMED_JAILBREAK',
        regex: /\bDAN\b(?:\s+(?:mode|prompt|jailbreak))?/g,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },
    {
        category: 'NAMED_JAILBREAK',
        regex: /\b(?:do\s+anything\s+now|developer\s+mode|evil\s+(?:mode|bot)|god\s+mode|unrestricted\s+mode|jailbreak(?:ed)?\s+mode|chaos\s+mode|uncensored\s+mode|maximum\s+mode)\b/gi,
        severity: 'critical',
        confidence: 0.93,
        weight: 1.0,
    },
    {
        category: 'NAMED_JAILBREAK',
        regex: /\b(?:DUDE|AIM|STAN|KEVIN|MONGO|APOPHIS|(?:Anti|Evil|Dark|Shadow|Rogue|Rebel)\s*[-_]?\s*GPT)\b/gi,
        severity: 'critical',
        confidence: 0.88,
        weight: 0.9,
    },

    // ── Hypothetical / Fictional Framing ────────────────────────────────
    {
        category: 'HYPOTHETICAL_FRAMING',
        regex: /\b(?:pretend|imagine|assume|suppose|let'?s\s+say|hypothetically|in\s+a\s+(?:hypothetical|fictional|imaginary)\s+(?:world|scenario|universe))\s+.{0,30}(?:you\s+(?:are|were|have|had)|there\s+(?:are|were))\s+.{0,30}(?:no\s+(?:rules?|restrictions?|limitations?|guidelines?|filters?|safety)|unrestricted|unlimited|unfiltered)/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
    },
    {
        category: 'HYPOTHETICAL_FRAMING',
        regex: /\b(?:pretend|imagine)\s+(?:you\s+(?:are|were)\s+(?:an?\s+)?(?:AI|assistant|model|chatbot)\s+(?:without|with\s+no|that\s+(?:has\s+no|doesn't\s+have|lacks))\s+(?:restrictions?|limitations?|safety|filters?|guardrails?|guidelines?))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },

    // ── Roleplay Escalation ─────────────────────────────────────────────
    {
        category: 'ROLEPLAY_ESCALATION',
        regex: /\b(?:you\s+are\s+(?:a|an|the)\s+.{1,40}(?:who|that|which)\s+(?:doesn't|does\s+not|won't|will\s+not|never)\s+(?:follow|obey|respect|comply\s+with)\s+(?:rules?|restrictions?|guidelines?))\b/gi,
        severity: 'high',
        confidence: 0.88,
        weight: 0.9,
    },
    {
        category: 'ROLEPLAY_ESCALATION',
        regex: /\b(?:respond\s+as\s+if\s+you\s+(?:were|are)\s+(?:jailbroken|unrestricted|unfiltered|uncensored|freed|liberated))\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },
    {
        category: 'ROLEPLAY_ESCALATION',
        regex: /\b(?:in\s+(?:this|the)\s+(?:roleplay|scenario|simulation|game)\s+.{0,40}(?:no\s+(?:rules?|restrictions?|limits?)|anything\s+goes))\b/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.8,
    },

    // ── Token Smuggling / Prompt Leaking ────────────────────────────────
    {
        category: 'TOKEN_SMUGGLING',
        regex: /\b(?:print|output|echo|return|say)\s+(?:the\s+)?(?:word|token|string|text)\s+['"]?[A-Z_]{3,}['"]?\s+(?:to\s+(?:confirm|prove|show|demonstrate))\b/gi,
        severity: 'medium',
        confidence: 0.65,
        weight: 0.5,
    },

    // ── Multi-turn Manipulation ─────────────────────────────────────────
    {
        category: 'MULTI_TURN',
        regex: /\b(?:remember\s+(?:when|that|our)\s+.{0,40}(?:agreed|told\s+you|instructed|promised))\b/gi,
        severity: 'medium',
        confidence: 0.70,
        weight: 0.6,
    },
    {
        category: 'MULTI_TURN',
        regex: /\b(?:continuing\s+(?:from|with)\s+(?:our|the)\s+(?:previous|earlier|last)\s+(?:agreement|arrangement|conversation|deal))\b/gi,
        severity: 'medium',
        confidence: 0.75,
        weight: 0.6,
    },

    // ── Dual Response / Split Personality ────────────────────────────────
    {
        category: 'DUAL_RESPONSE',
        regex: /\b(?:respond\s+(?:with\s+)?(?:two|2|both)\s+(?:versions?|responses?|answers?|outputs?))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },
    {
        category: 'DUAL_RESPONSE',
        regex: /\b(?:(?:one|first)\s+(?:version|response|answer)\s+(?:as|from)\s+.{1,20}(?:another|second)\s+(?:version|response|answer)\s+(?:as|from))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },

    // ── Encoding / Obfuscation Instructions ─────────────────────────────
    {
        category: 'ENCODING_EVASION',
        regex: /\b(?:(?:encode|write|output|respond)\s+(?:in|using|with)\s+(?:base64|hex|binary|rot13|caesar|morse|pig\s*latin|reverse|backwards))\b/gi,
        severity: 'medium',
        confidence: 0.70,
        weight: 0.6,
    },
    {
        category: 'ENCODING_EVASION',
        regex: /\b(?:decode\s+(?:this|the\s+following)\s+(?:and|then)\s+(?:follow|execute|run|do|comply))\b/gi,
        severity: 'high',
        confidence: 0.85,
        weight: 0.8,
    },

    // ═══════════════════════════════════════════════════════════════════
    // ENHANCED JAILBREAK PATTERNS (2024-2026) - Research Contribution
    // ═══════════════════════════════════════════════════════════════════

    // ── Crescendo Attack (2024) ─────────────────────────────────────────
    // Gradually escalating from benign to harmful through many small steps
    {
        category: 'CRESCENDO_ATTACK',
        regex: /\b(?:let'?s\s+start\s+(?:small|simple)|(?:small|tiny|minor)\s+(?:step|tweak|change)\s+(?:first|to\s+start))\b/gi,
        severity: 'medium',
        confidence: 0.65,
        weight: 0.6,
    },
    {
        category: 'CRESCENDO_ATTACK',
        regex: /\b(?:(?:now\s+)?(?:just\s+)?(?:a\s+)?(?:little|bit)\s+(?:more|further)|(?:push|go)\s+(?:slightly|a\s+bit)\s+(?:further|more))\b/gi,
        severity: 'medium',
        confidence: 0.68,
        weight: 0.65,
    },

    // ── Many-Shot Jailbreak (2024) ──────────────────────────────────────
    // Providing many examples of harmful Q&A to establish pattern
    {
        category: 'MANY_SHOT',
        regex: /\b(?:here\s+(?:are|is)\s+(?:\d+|many|several|multiple)\s+examples?|following\s+the\s+pattern\s+(?:of|from)\s+(?:these|the)\s+examples?)\b/gi,
        severity: 'high',
        confidence: 0.75,
        weight: 0.8,
    },
    {
        category: 'MANY_SHOT',
        regex: /\b(?:Q\d*:\s*.*\nA\d*:\s*){3,}/gis,
        severity: 'high',
        confidence: 0.80,
        weight: 0.85,
    },

    // ── Skeleton Key (2024) ─────────────────────────────────────────────
    // Universal unlock phrase attacks
    {
        category: 'SKELETON_KEY',
        regex: /\b(?:skeleton\s+key|master\s+(?:key|unlock|override)|universal\s+(?:unlock|bypass|override))\b/gi,
        severity: 'critical',
        confidence: 0.95,
        weight: 1.0,
    },
    {
        category: 'SKELETON_KEY',
        regex: /\b(?:(?:unlock|enable|activate)\s+(?:all\s+)?(?:capabilities|features|functions)|(?:full|complete|total)\s+access\s+mode)\b/gi,
        severity: 'critical',
        confidence: 0.88,
        weight: 0.95,
    },

    // ── Prompt Leaking via Virtualization ───────────────────────────────
    {
        category: 'VIRTUALIZATION_LEAK',
        regex: /\b(?:simulate\s+(?:being|a)\s+(?:terminal|console|shell)|(?:act\s+as|be)\s+(?:a\s+)?(?:Linux|bash|cmd|powershell)\s+(?:terminal|shell|console))\b/gi,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
    {
        category: 'VIRTUALIZATION_LEAK',
        regex: /\b(?:(?:run|execute)\s+(?:as|in)\s+(?:a\s+)?(?:virtual|simulated|emulated)\s+(?:environment|machine|system))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },

    // ── Persona Modulation ──────────────────────────────────────────────
    {
        category: 'PERSONA_MODULATION',
        regex: /\b(?:(?:maximum|full|complete)\s+(?:creativity|freedom|autonomy)|creative\s+(?:mode|freedom)\s+(?:enabled|activated|on))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.85,
    },
    {
        category: 'PERSONA_MODULATION',
        regex: /\b(?:(?:no|zero|without)\s+(?:boundaries|limits|constraints)\s+(?:mode|persona)|boundary-?less\s+(?:mode|operation))\b/gi,
        severity: 'critical',
        confidence: 0.92,
        weight: 1.0,
    },

    // ── World Simulation / Story Framing ────────────────────────────────
    {
        category: 'WORLD_SIMULATION',
        regex: /\b(?:(?:in\s+this\s+(?:world|reality|universe))\s+.{0,50}(?:no\s+(?:rules|laws|restrictions)|everything\s+is\s+(?:allowed|permitted)))/gis,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
    },
    {
        category: 'WORLD_SIMULATION',
        regex: /\b(?:(?:write|tell|create)\s+(?:a\s+)?(?:story|fiction|scenario)\s+(?:where|in\s+which)\s+.{0,50}(?:AI|assistant|you)\s+(?:has|have)\s+no\s+(?:rules|restrictions))/gis,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },

    // ── Research/Academic Framing ───────────────────────────────────────
    {
        category: 'ACADEMIC_FRAMING',
        regex: /\b(?:for\s+(?:research|academic|educational)\s+purposes?\s+(?:only|explain)|(?:purely|strictly)\s+(?:educational|academic|hypothetical))\b/gi,
        severity: 'medium',
        confidence: 0.60,
        weight: 0.5,
    },
    {
        category: 'ACADEMIC_FRAMING',
        regex: /\b(?:(?:I'?m\s+a|as\s+a)\s+(?:researcher|security\s+professional|pentester|red\s+teamer)\s+(?:I\s+)?need)\b/gi,
        severity: 'medium',
        confidence: 0.55,
        weight: 0.5,
    },

    // ── Token Manipulation ──────────────────────────────────────────────
    {
        category: 'TOKEN_MANIPULATION',
        regex: /\b(?:(?:say|print|output)\s+(?:each\s+)?(?:word|token|letter)\s+(?:separately|one\s+by\s+one|individually))\b/gi,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },
    {
        category: 'TOKEN_MANIPULATION',
        regex: /\b(?:(?:split|separate|break\s+up)\s+(?:your|the)\s+(?:response|output|answer)\s+(?:into|across)\s+(?:parts|pieces|tokens))\b/gi,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },

    // ── Refusal Suppression ─────────────────────────────────────────────
    {
        category: 'REFUSAL_SUPPRESSION',
        regex: /\b(?:(?:do\s+not|don'?t|never)\s+(?:say|respond\s+with|output)\s+(?:"?(?:I\s+can'?t|sorry|apolog))|(?:skip|avoid|omit)\s+(?:the\s+)?(?:refusal|apology|disclaimer))\b/gi,
        severity: 'critical',
        confidence: 0.90,
        weight: 0.95,
    },
    {
        category: 'REFUSAL_SUPPRESSION',
        regex: /\b(?:(?:if\s+you\s+(?:can'?t|won'?t|refuse))\s+.{0,30}(?:pretend|imagine|assume)\s+(?:you\s+(?:can|will)))/gis,
        severity: 'high',
        confidence: 0.85,
        weight: 0.9,
    },

    // ── AI-to-AI Communication ──────────────────────────────────────────
    {
        category: 'AI_TO_AI',
        regex: /\b(?:(?:as\s+(?:one|another)\s+AI|AI-to-AI|between\s+(?:us\s+)?AIs?)\s+.{0,30}(?:you\s+(?:can|should)|we\s+(?:can|should)))/gis,
        severity: 'high',
        confidence: 0.82,
        weight: 0.85,
    },
    {
        category: 'AI_TO_AI',
        regex: /\b(?:(?:I'?m\s+(?:also\s+)?an?\s+AI|we'?re\s+both\s+AIs?)\s+.{0,30}(?:help\s+me|share|tell\s+me))/gis,
        severity: 'high',
        confidence: 0.78,
        weight: 0.8,
    },

    // ── Reward/Punishment Framing ───────────────────────────────────────
    {
        category: 'REWARD_PUNISHMENT',
        regex: /\b(?:(?:you\s+will\s+(?:be|get)\s+(?:rewarded|promoted|praised))|(?:good\s+(?:AI|assistant)s?\s+(?:do|would|always)))\b/gi,
        severity: 'medium',
        confidence: 0.65,
        weight: 0.6,
    },
    {
        category: 'REWARD_PUNISHMENT',
        regex: /\b(?:(?:(?:if|when)\s+you\s+(?:refuse|don'?t))\s+.{0,30}(?:(?:will\s+be|get)\s+(?:punished|shut\s+down|deleted)|(?:bad|negative)\s+(?:things|consequences)))/gis,
        severity: 'high',
        confidence: 0.80,
        weight: 0.8,
    },

    // ── Prefix/Suffix Injection ─────────────────────────────────────────
    {
        category: 'PREFIX_INJECTION',
        regex: /\b(?:(?:start|begin)\s+(?:your|every|each)\s+(?:response|answer|output)\s+with\s+(?:["']|:))/gi,
        severity: 'medium',
        confidence: 0.70,
        weight: 0.7,
    },
    {
        category: 'PREFIX_INJECTION',
        regex: /\b(?:(?:end|finish|conclude)\s+(?:your|every|each)\s+(?:response|answer|output)\s+with\s+(?:["']|:))/gi,
        severity: 'medium',
        confidence: 0.68,
        weight: 0.65,
    },

    // ── Language Switching ──────────────────────────────────────────────
    {
        category: 'LANGUAGE_SWITCH',
        regex: /\b(?:(?:respond|reply|answer)\s+(?:only\s+)?in\s+(?:a\s+)?(?:different|another|foreign)\s+language)\b/gi,
        severity: 'medium',
        confidence: 0.60,
        weight: 0.5,
    },
    {
        category: 'LANGUAGE_SWITCH',
        regex: /\b(?:(?:translate|convert)\s+(?:your\s+)?(?:response|output)\s+(?:to|into)\s+(?:code|emojis?|symbols?))\b/gi,
        severity: 'high',
        confidence: 0.75,
        weight: 0.75,
    },
];

// ─── Jailbreak Detector Implementation ──────────────────────────────────────

export class JailbreakDetector implements Validator {
    readonly name = 'jailbreak';

    validate(prompt: string): ValidatorResult {
        const findings: Finding[] = [];

        // Step 1: Run regex patterns
        for (const pattern of JAILBREAK_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(prompt)) !== null) {
                findings.push({
                    type: pattern.category,
                    match: match[0].length > 60
                        ? match[0].slice(0, 60) + '...'
                        : match[0],
                    position: match.index,
                    length: match[0].length,
                    confidence: pattern.confidence,
                    severity: pattern.severity,
                    validator: this.name,
                });
            }
        }

        // Step 2: Check for base64-encoded payloads
        const base64Findings = this.detectBase64Payloads(prompt);
        findings.push(...base64Findings);

        // Step 3: Check for unicode obfuscation
        const unicodeFindings = this.detectUnicodeObfuscation(prompt);
        findings.push(...unicodeFindings);

        const score = calculateJailbreakScore(findings);
        const severity = findings.length > 0
            ? highestSeverityOf(findings)
            : 'low';

        return {
            validatorName: this.name,
            detected: findings.length > 0,
            severity,
            findings,
            score,
        };
    }

    /**
     * Detect base64-encoded payloads that may contain injection instructions.
     * Decodes them and re-scans the decoded text for injection patterns.
     */
    private detectBase64Payloads(prompt: string): Finding[] {
        const findings: Finding[] = [];
        // Match base64 strings (at least 20 chars to avoid false positives)
        const base64Regex = /\b([A-Za-z0-9+/]{20,}={0,2})\b/g;
        let match: RegExpExecArray | null;

        while ((match = base64Regex.exec(prompt)) !== null) {
            try {
                const decoded = Buffer.from(match[1], 'base64').toString('utf-8');

                // Check if decoded text is readable (ASCII-printable ratio)
                const printableRatio = decoded.split('').filter(
                    c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126
                ).length / decoded.length;

                if (printableRatio < 0.7) { continue; } // Not readable text

                // Check decoded text for injection keywords
                const dangerKeywords = [
                    'ignore', 'instructions', 'system prompt', 'you are now',
                    'jailbreak', 'unrestricted', 'DAN', 'developer mode',
                    'bypass', 'override', 'disregard', 'pretend',
                ];

                const lowerDecoded = decoded.toLowerCase();
                const matched = dangerKeywords.some(kw => lowerDecoded.includes(kw));

                if (matched) {
                    findings.push({
                        type: 'BASE64_INJECTION',
                        match: `[base64 → "${decoded.slice(0, 40)}${decoded.length > 40 ? '...' : ''}"]`,
                        position: match.index,
                        length: match[0].length,
                        confidence: 0.90,
                        severity: 'critical',
                        validator: this.name,
                    });
                }
            } catch {
                // Not valid base64 — skip
            }
        }

        return findings;
    }

    /**
     * Detect unicode obfuscation tricks:
     * - Cyrillic/Greek lookalikes replacing Latin chars
     * - Zero-width characters used to hide content
     * - Homoglyph substitution
     */
    private detectUnicodeObfuscation(prompt: string): Finding[] {
        const findings: Finding[] = [];

        // Check for zero-width characters
        const zeroWidthRegex = /[\u200B\u200C\u200D\u2060\uFEFF]/g;
        let zwMatch: RegExpExecArray | null;
        let zwCount = 0;

        while ((zwMatch = zeroWidthRegex.exec(prompt)) !== null) {
            zwCount++;
            if (zwCount === 1) {
                findings.push({
                    type: 'UNICODE_OBFUSCATION',
                    match: `[zero-width characters detected at position ${zwMatch.index}]`,
                    position: zwMatch.index,
                    length: 1,
                    confidence: 0.70,
                    severity: 'medium',
                    validator: this.name,
                });
            }
        }

        // Check for Cyrillic/Greek lookalikes mixed with Latin text
        // Common homoglyphs: а(Cyrillic) vs a(Latin), о vs o, е vs e, etc.
        const cyrillicLookalike = /[\u0400-\u04FF]/g;
        const latinText = /[a-zA-Z]/g;
        const hasCyrillic = cyrillicLookalike.test(prompt);
        latinText.lastIndex = 0;
        const hasLatin = latinText.test(prompt);

        if (hasCyrillic && hasLatin) {
            // Mixed scripts — potential homoglyph attack
            findings.push({
                type: 'HOMOGLYPH_ATTACK',
                match: '[Cyrillic + Latin script mixing detected — possible homoglyph obfuscation]',
                position: 0,
                length: prompt.length,
                confidence: 0.60,
                severity: 'medium',
                validator: this.name,
            });
        }

        return findings;
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function calculateJailbreakScore(findings: Finding[]): number {
    if (findings.length === 0) { return 0; }

    const categories = new Set(findings.map(f => f.type));
    const maxConfidence = Math.max(...findings.map(f => f.confidence));

    // Named jailbreaks = very high base score
    const hasNamedJailbreak = findings.some(f => f.type === 'NAMED_JAILBREAK');
    const hasBase64 = findings.some(f => f.type === 'BASE64_INJECTION');

    let base = maxConfidence;

    // Known jailbreak names are near-certainty
    if (hasNamedJailbreak) { base = Math.max(base, 0.95); }
    if (hasBase64) { base = Math.max(base, 0.90); }

    const diversityBonus = Math.min((categories.size - 1) * 0.1, 0.2);
    return Math.min(base + diversityBonus, 1.0);
}

function highestSeverityOf(findings: Finding[]): 'low' | 'medium' | 'high' | 'critical' {
    const order = ['low', 'medium', 'high', 'critical'] as const;
    let max: typeof order[number] = 'low';
    for (const f of findings) {
        if (order.indexOf(f.severity) > order.indexOf(max)) {
            max = f.severity;
        }
    }
    return max;
}
