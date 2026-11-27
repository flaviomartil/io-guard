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

const COMBINED_PREFIX_PATTERN =
  /(?:github_pat_[A-Za-z0-9_]{10,}|gh[pousr]_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|sk_[A-Za-z0-9_]{10,}|sk-[A-Za-z0-9_-]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{30,}|pplx-[A-Za-z0-9]{10,}|fal_[A-Za-z0-9_-]{10,}|fc-[A-Za-z0-9]{10,}|bb_live_[A-Za-z0-9_-]{10,}|gAAAA[A-Za-z0-9_=-]{20,}|AKIA[A-Z0-9]{16}|SG\.[A-Za-z0-9_-]{10,}|hf_[A-Za-z0-9]{10,}|r8_[A-Za-z0-9]{10,}|npm_[A-Za-z0-9]{10,}|pypi-[A-Za-z0-9_-]{10,}|dop_v1_[A-Za-z0-9]{10,}|doo_v1_[A-Za-z0-9]{10,}|tvly-[A-Za-z0-9]{10,}|exa_[A-Za-z0-9]{10,}|gsk_[A-Za-z0-9]{10,}|syt_[A-Za-z0-9]{10,}|mem0_[A-Za-z0-9]{10,}|brv_[A-Za-z0-9]{10,}|fcaebeeb[A-Za-z0-9]{20,})/g;

const ENV_SECRET_RE =
  /\b([A-Z0-9_]{1,50}(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]{0,50})\s*=\s*(\S+)/gi;
const JSON_SECRET_RE =
  /\b("(?:api_?[Kk]ey|token|secret|password|access_token|refresh_token|auth_token|bearer|secret_value|raw_secret|key_material)")\s*:\s*"([^"]+)"/gi;
const BEARER_RE = /(Authorization:\s*Bearer\s+)(\S+)/gi;
const PRIVATE_KEY_RE = /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g;
const DB_URL_RE = /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:]+:)([^@]+)(@)/gi;
const JWT_RE = /(eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_=-]{4,}){0,2})/g;
const BASIC_AUTH_URL_RE = /(https?|wss?|ftp):\/\/([^/\s:@]+):([^/\s@]+)@/gi;

export function maskToken(token: string): string {
  if (!token || token.length < 18) return "***";
  return `${token.slice(0, 6)}...${token.slice(-4)}`;
}

export function redactSecrets(text: string): string {
  if (!text) return text;
  let result = text.replace(COMBINED_PREFIX_PATTERN, (m) => maskToken(m));

  if (result.includes("-----BEGIN")) {
    result = result.replace(PRIVATE_KEY_RE, "[REDACTED PRIVATE KEY]");
  }

  if (result.includes("=")) {
    result = result.replace(ENV_SECRET_RE, (_, name, value) => `${name}=${maskToken(value)}`);
  }

  if (result.includes(":")) {
    result = result.replace(JSON_SECRET_RE, (_, key, value) => `${key}:"${maskToken(value)}"`);
    result = result.replace(BEARER_RE, (_, prefix, token) => `${prefix}${maskToken(token)}`);
  }

  if (result.includes("://")) {
    result = result.replace(DB_URL_RE, (_, prefix, _pass, suffix) => `${prefix}***${suffix}`);
  }

  if (result.includes("eyJ")) {
    result = result.replace(JWT_RE, (m) => maskToken(m));
  }

  if (result.includes("://")) {
    result = result.replace(BASIC_AUTH_URL_RE, (_, scheme, user) => `${scheme}://${user}:***@`);
  }

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
