/**
 * Shared IO Sanitizer & Guard for AI Harness
 * Pure TypeScript module with zero external dependencies.
 * Used by:
 * - Claude Code Mod (in-process via register(on))
 * - OpenCode Plugin (in-process via opencode-plugin.js)
 * - Codex / Kimi / Antigravity (via ai-harness-hook dispatcher)
 */

export interface TruncateOptions {
  maxLines?: number;
  keepHead?: number;
  keepTail?: number;
  preserveTests?: boolean;
}

export interface GuardResult {
  allowed: boolean;
  reason?: string;
  violations?: string[];
}

export interface WritingValidationResult {
  valid: boolean;
  violations: string[];
}

/* -------------------------------------------------------------------------- */
/*                               SECRET REDACTION                             */
/* -------------------------------------------------------------------------- */

const PREFIX_PATTERNS = [
  /sk-[A-Za-z0-9_-]{10,}/g,
  /ghp_[A-Za-z0-9]{10,}/g,
  /github_pat_[A-Za-z0-9_]{10,}/g,
  /gho_[A-Za-z0-9]{10,}/g,
  /ghu_[A-Za-z0-9]{10,}/g,
  /ghs_[A-Za-z0-9]{10,}/g,
  /ghr_[A-Za-z0-9]{10,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /AIza[A-Za-z0-9_-]{30,}/g,
  /pplx-[A-Za-z0-9]{10,}/g,
  /fal_[A-Za-z0-9_-]{10,}/g,
  /fc-[A-Za-z0-9]{10,}/g,
  /bb_live_[A-Za-z0-9_-]{10,}/g,
  /gAAAA[A-Za-z0-9_=-]{20,}/g,
  /AKIA[A-Z0-9]{16}/g,
  /sk_live_[A-Za-z0-9]{10,}/g,
  /sk_test_[A-Za-z0-9]{10,}/g,
  /rk_live_[A-Za-z0-9]{10,}/g,
  /SG\.[A-Za-z0-9_-]{10,}/g,
  /hf_[A-Za-z0-9]{10,}/g,
  /r8_[A-Za-z0-9]{10,}/g,
  /npm_[A-Za-z0-9]{10,}/g,
  /pypi-[A-Za-z0-9_-]{10,}/g,
  /dop_v1_[A-Za-z0-9]{10,}/g,
  /doo_v1_[A-Za-z0-9]{10,}/g,
  /sk_[A-Za-z0-9_]{10,}/g,
  /tvly-[A-Za-z0-9]{10,}/g,
  /exa_[A-Za-z0-9]{10,}/g,
  /gsk_[A-Za-z0-9]{10,}/g,
  /syt_[A-Za-z0-9]{10,}/g,
  /mem0_[A-Za-z0-9]{10,}/g,
  /brv_[A-Za-z0-9]{10,}/g,
  /fcaebeeb[A-Za-z0-9]{20,}/g,
];

export function maskToken(token: string): string {
  if (!token || token.length < 18) return "***";
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

export function redactSecrets(text: string): string {
  if (!text) return text;
  let result = text;

  for (const pattern of PREFIX_PATTERNS) {
    result = result.replace(pattern, (m) => maskToken(m));
  }

  // Key=Value assignments
  result = result.replace(
    /\b([A-Z0-9_]{1,50}(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]{0,50})\s*=\s*(\S+)/gi,
    (_, name, value) => `${name}=${maskToken(value)}`
  );

  // JSON key-values
  result = result.replace(
    /\b("(?:api_?[Kk]ey|token|secret|password|access_token|refresh_token|auth_token|bearer|secret_value|raw_secret|key_material)")\s*:\s*"([^"]+)"/gi,
    (_, key, value) => `${key}:"${maskToken(value)}"`
  );

  // Authorization Bearer
  result = result.replace(
    /(Authorization:\s*Bearer\s+)(\S+)/gi,
    (_, prefix, token) => `${prefix}${maskToken(token)}`
  );

  // Private keys
  result = result.replace(
    /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g,
    "[REDACTED PRIVATE KEY]"
  );

  // Database URLs with passwords
  result = result.replace(
    /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:]+:)([^@]+)(@)/gi,
    (_, prefix, _pass, suffix) => `${prefix}***${suffix}`
  );

  // JWTs
  result = result.replace(
    /(eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_=-]{4,}){0,2})/g,
    (m) => maskToken(m)
  );

  // Generic Basic Auth URLs
  result = result.replace(
    /(https?|wss?|ftp):\/\/([^/\s:@]+):([^/\s@]+)@/gi,
    (_, scheme, user) => `${scheme}://${user}:***@`
  );

  return result;
}

/* -------------------------------------------------------------------------- */
/*                            OUTPUT TRUNCATION                               */
/* -------------------------------------------------------------------------- */

const TEST_RUNNER_PATTERN = /(PASS|FAIL|passed|failed|test.*suites?|Tests:|pytest|ok \d|--- FAIL|--- PASS)/i;

export function truncateOutput(
  text: string,
  options: TruncateOptions = {}
): { text: string; truncated: boolean; linesRemoved: number } {
  if (!text) return { text: "", truncated: false, linesRemoved: 0 };

  const maxLines = options.maxLines ?? 150;
  const keepHead = options.keepHead ?? 50;
  const keepTail = options.keepTail ?? 50;
  const preserveTests = options.preserveTests ?? true;

  const lines = text.split("\n");
  if (lines.length <= maxLines) {
    return { text, truncated: false, linesRemoved: 0 };
  }

  // Preserve test outputs unless they are truly astronomical (> 300 lines)
  if (preserveTests && TEST_RUNNER_PATTERN.test(text) && lines.length <= 300) {
    return { text, truncated: false, linesRemoved: 0 };
  }

  const head = lines.slice(0, keepHead);
  const tail = lines.slice(-keepTail);
  const linesRemoved = lines.length - keepHead - keepTail;

  const truncatedText = [
    ...head,
    "",
    `... [${linesRemoved} lines truncated by AI Harness IO-Sanitizer to save tokens] ...`,
    "",
    ...tail,
  ].join("\n");

  return { text: truncatedText, truncated: true, linesRemoved };
}

export function sanitizeOutput(text: string, options?: TruncateOptions): string {
  const redacted = redactSecrets(text);
  const { text: truncated } = truncateOutput(redacted, options);
  return truncated;
}

/* -------------------------------------------------------------------------- */
/*                        WRITING STYLE & COMMAND GUARD                       */
/* -------------------------------------------------------------------------- */

const EMOJI_REGEX = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{1F1E6}-\u{1F1FF}️]/u;
const DASHES_REGEX = /[–—―]/;
const CURLY_QUOTES_REGEX = /[‘’“”]/;
const MOJIBAKE_REGEX = /(?:â€|Ã[\x80-\xFF]|Â[\x80-\xFF])/;

const OUTBOUND_COMMAND_PATTERN = /_apis\/wit\/[^\s'"]*\/(comments|pullrequests)|\/pullrequests\b|\bgh\s+(pr|issue|release)\b|\baz\s+boards\b|\baz\s+repos\s+pr\b|\baz\s+devops\s+wiki\b|hooks\.slack\.com|webhook\.office\.com|discord(app)?\.com\/api\/webhooks|\bgit\s+commit\b/i;

export function validateWriting(text: string): WritingValidationResult {
  const violations: string[] = [];
  if (EMOJI_REGEX.test(text)) violations.push("emoji");
  if (DASHES_REGEX.test(text)) violations.push("travessao/en-dash");
  if (CURLY_QUOTES_REGEX.test(text)) violations.push("aspas curvas tipograficas");
  if (MOJIBAKE_REGEX.test(text)) violations.push("codificacao corrompida (mojibake/UTF-8)");

  return {
    valid: violations.length === 0,
    violations,
  };
}

export function cleanWriting(text: string): string {
  if (!text) return text;
  return text
    .replace(/\s*[—―]\s*/g, " - ")
    .replace(/\s*–\s*/g, "-")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(EMOJI_REGEX, "");
}

export function guardCommand(command: string, targetsYamlContent?: string): GuardResult {
  if (!command) return { allowed: true };

  // Check writing style on outbound commands (git commit, PR, devops comments)
  if (OUTBOUND_COMMAND_PATTERN.test(command)) {
    const val = validateWriting(command);
    if (!val.valid) {
      return {
        allowed: false,
        reason: `Regra 875 violada no comando: contem ${val.violations.join(", ")}. Reescreva sem travessão (—), sem emoji e com aspas retas.`,
        violations: val.violations,
      };
    }
  }

  // Branch Target Protection
  if (/\bgit\s+push\b/.test(command)) {
    // Block accidental force-push to main/master/develop unconditionally
    if (/\s+(-f|--force|--force-with-lease)\s+.*(main|master|develop)/i.test(command)) {
      return {
        allowed: false,
        reason: "Force-push em branch protegida (main/master/develop) bloqueado pelo Target Guard.",
      };
    }

    if (targetsYamlContent) {
      if (/protected_branches:\s*\[.*\]/i.test(targetsYamlContent) || /allow_direct_push:\s*false/i.test(targetsYamlContent)) {
        if (/\b(origin\s+main|origin\s+develop|origin\s+release|origin\s+master)\b/i.test(command)) {
          return {
            allowed: false,
            reason: "Push direto para branch declarada protegida em targets.yaml bloqueado. Crie uma branch de feature e abra PR.",
          };
        }
      }
    }
  }

  return { allowed: true };
}
