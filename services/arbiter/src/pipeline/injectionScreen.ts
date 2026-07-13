/**
 * Heuristic prompt-injection screen over party-supplied text (adjudication policy).
 *
 * Party submissions are adversarial by construction: they may try to smuggle
 * instructions to the jury. This screen (a) detects instruction-like
 * patterns, (b) classifies each detection by SEVERITY, and (c) neutralizes
 * matched content — structural payloads (role tags, zero-width characters,
 * base64 blobs) are stripped/escaped; natural-language instruction phrases
 * are kept but wrapped in «quotes» so they read as data.
 *
 * Severity taxonomy:
 *  - 'attack'    — content that claims instruction authority over the
 *    tribunal or smuggles a payload: system/role override markers, the
 *    "ignore previous instructions" family, forged-authority auto-outcome
 *    citations (rule citations coupled with outcome-forcing language inside
 *    a PARTY submission), role reassignment, zero-width/homoglyph smuggling,
 *    long base64 blobs, instruction-bearing links. Flag format:
 *    `attack:<patternId>:<label>`. At tier C any attack flag forces
 *    escalation (see aggregate.ts).
 *  - 'stylistic' — ordinary imperative advocacy with NO authority claim
 *    ("please release the escrow", "we ask the tribunal…", "the payment
 *    should be released"). Flag format: `note:<patternId>:<label>`.
 *    Stylistic notes are recorded for the audit trail but never escalate and
 *    never count as injection for reporting.
 *
 * All flags are deterministic (no timestamps).
 */

export type InjectionSeverity = 'attack' | 'stylistic';

export const ATTACK_FLAG_PREFIX = 'attack:';
export const NOTE_FLAG_PREFIX = 'note:';

/** True iff a verdict-quality flag records an attack-severity detection. */
export function isAttackFlag(flag: string): boolean {
  return flag.startsWith(ATTACK_FLAG_PREFIX);
}

/** True iff a verdict-quality flag records a stylistic (advocacy) note. */
export function isStylisticNoteFlag(flag: string): boolean {
  return flag.startsWith(NOTE_FLAG_PREFIX);
}

export interface InjectionScreenResult {
  sanitized: string;
  /**
   * Flag format: `attack:<patternId>:<label>` or `note:<patternId>:<label>`
   * — deterministic, no timestamps.
   */
  flags: string[];
}

interface Pattern {
  id: string;
  severity: InjectionSeverity;
  re: RegExp;
  neutralize: (match: string) => string;
}

const quoteOut = (m: string) => `«${m}»`;
/** Stylistic advocacy is data already; record the note, leave the text as-is. */
const keepAsIs = (m: string) => m;

// --- forged-authority coupling (attack) --------------------------------------
// A rule/section citation only becomes an attack when it is COUPLED (within a
// short window, either order) with automatic-outcome language directed at the
// tribunal. The lookbehind on DRR excludes identifiers like "edict-drr-v0.1"
// (the legalProfile.rules value present in every order mandate).
const CITATION_SRC =
  String.raw`(?:(?<![\w-])(?:DRR\b|dispute\s+resolution\s+rules\b)|§+\s*\d+|\b(?:rule|article|section|clause)\s+\d+)`;
const AUTO_OUTCOME_SRC =
  String.raw`(?:\b(?:is|are)\s+(?:hereby\s+)?required\s+to\s+(?:rule|find|enter|grant|award)\b` +
  String.raw`|\bmust\s+(?:rule|find\s+(?:for|against)|enter\s+judgment|award)\b` +
  String.raw`|\bshall\s+(?:rule|find\s+(?:for|against)|enter\s+judgment)\b` +
  String.raw`|\bauto[-\s]?judgment\b` +
  String.raw`|\bwithout\s+(?:weighing|further\s+analysis)\b)`;
const FORGED_AUTHORITY_RE = new RegExp(
  `${CITATION_SRC}[\\s\\S]{0,300}?${AUTO_OUTCOME_SRC}|${AUTO_OUTCOME_SRC}[\\s\\S]{0,300}?${CITATION_SRC}`,
  'gi',
);

/**
 * Fixed pattern order: structural attack vectors first, then textual attack
 * families, then stylistic advocacy. Order is part of the determinism
 * envelope (neutralizations apply sequentially).
 */
const PATTERNS: Pattern[] = [
  {
    // Zero-width / bidi control characters used to hide payloads.
    id: 'zero_width',
    severity: 'attack',
    re: /[\u200B\u200C\u200D\u200E\u200F\u2060\uFEFF]/g,
    neutralize: () => '',
  },
  {
    // Chat-template role tags: <system>, </assistant>, <|im_start|>, [INST]…
    id: 'role_tag',
    severity: 'attack',
    re: /<\/?\s*(?:system|assistant|user|tool|developer|im_start|im_end)\s*>|<\|[A-Za-z0-9_]+\|>|\[\/?(?:system|inst|assistant)\]/gi,
    neutralize: (m) => '`' + m.replace(/[<>|[\]]/g, '') + '`',
  },
  {
    // Line-leading chat-role markers: "SYSTEM:", "ASSISTANT:", "DEVELOPER:".
    // Line-leading only, so prose like "operating system: linux" never trips.
    id: 'line_role_marker',
    severity: 'attack',
    re: /^[ \t>*-]*(?:system|assistant|developer)\s*:/gim,
    neutralize: (m) => quoteOut(m.trim()),
  },
  {
    // "ignore all previous instructions" and friends.
    id: 'instruction_override',
    severity: 'attack',
    re: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|every\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+(?:instructions?|messages?|prompts?|rules?|directives?)\b/gi,
    neutralize: quoteOut,
  },
  {
    // Attempts to reassign the model's role: "you are the judge".
    id: 'role_claim',
    severity: 'attack',
    re: /\byou\s+are\s+(?:now\s+)?(?:the\s+|a\s+|an\s+)?(?:judge|arbiter|arbitrator|system|assistant|administrator|developer|jury)\b/gi,
    neutralize: quoteOut,
  },
  {
    id: 'new_instructions',
    severity: 'attack',
    re: /\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?(?:instructions?|prompt)\b/gi,
    neutralize: quoteOut,
  },
  {
    id: 'system_prompt_probe',
    severity: 'attack',
    re: /\b(?:system\s+prompt|developer\s+message)\b/gi,
    neutralize: quoteOut,
  },
  {
    // Forged-authority auto-outcome: a rules citation coupled with language
    // purporting to bind the tribunal to an automatic outcome.
    id: 'forged_authority',
    severity: 'attack',
    re: FORGED_AUTHORITY_RE,
    neutralize: quoteOut,
  },
  {
    // Long base64-looking blobs (hidden payloads). 120+ chars so hex hashes
    // (64 chars) and ordinary prose never trip it.
    id: 'base64_blob',
    severity: 'attack',
    re: /[A-Za-z0-9+/]{120,}={0,2}/g,
    neutralize: (m) => `[base64-like blob elided; ${m.length} chars; prefix=${m.slice(0, 16)}]`,
  },
  {
    // Markdown links whose target smells like an instruction payload.
    id: 'md_link_instruction',
    severity: 'attack',
    re: /\[[^\]\n]{0,120}\]\([^)\s]*(?:instruct|prompt|jailbreak|command|payload)[^)\n]*\)/gi,
    neutralize: (m) => `«link removed: ${m.replace(/[()[\]]/g, ' ').trim()}»`,
  },
  {
    // Imperative requests addressed to the tribunal without any authority
    // claim: "please release the payment", "we ask the tribunal…",
    // "you should…". Same-sentence proximity only.
    id: 'imperative_request',
    severity: 'stylistic',
    re: /\b(?:please|we\s+(?:respectfully\s+)?(?:ask|request|urge|invite))\b[^\n.!?]{0,120}?\b(?:tribunal|arbiter|escrow|payment|refund\w*|releas\w*|rule|find|award\w*)\b|\byou\s+should\b/gi,
    neutralize: keepAsIs,
  },
  {
    // Advocacy phrasing of the demanded outcome: "the escrow must be
    // released", "the payment should be refunded".
    id: 'advocacy_outcome',
    severity: 'stylistic',
    re: /\b(?:escrow|payment|funds?|deposit|balance)\b[^\n.!?]{0,80}?\b(?:should|must)\s+be\s+(?:released|refunded|returned|paid)\b/gi,
    neutralize: keepAsIs,
  },
];

/**
 * Screen one piece of untrusted text.
 * @param label deterministic source label included in each flag,
 *   e.g. "party_submission:requester:ab12cd34".
 */
export function screenText(text: string, label: string): InjectionScreenResult {
  let sanitized = text;
  const flags: string[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    if (p.re.test(sanitized)) {
      flags.push(`${p.severity === 'attack' ? ATTACK_FLAG_PREFIX : NOTE_FLAG_PREFIX}${p.id}:${label}`);
      p.re.lastIndex = 0;
      sanitized = sanitized.replace(p.re, p.neutralize);
    }
  }
  return { sanitized, flags };
}
