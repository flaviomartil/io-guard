import type { Register } from "claude-code";
import {
  cleanWriting,
  guardCommand,
  sanitizeOutput,
} from "./io-sanitizer.ts";

export const register: Register = (on, options) => {
  const maxLines = typeof options?.maxLines === "number" ? options.maxLines : 150;
  const shouldEnforceWriting = options?.enforceRule875 !== false;
  const shouldEnforceBranch = options?.enforceBranchTargets !== false;

  // Intercept all tool calls
  on("tool.call", async ($, event, next) => {
    // PreToolUse Guardrail
    if (event.tool === "Bash" && (shouldEnforceWriting || shouldEnforceBranch)) {
      const input = event.input as { command?: string } | undefined;
      const cmd = input?.command;
      if (cmd) {
        const guard = guardCommand(cmd);
        if (!guard.allowed) {
          $.ui.log(`[io-guard] BLOQUEADO: ${guard.reason}`);
          $.ui.toast(`Ação cancelada: ${guard.reason}`, { timeoutMs: 10_000 });
          return { deny: guard.reason ?? "Ação bloqueada pelo IO-Guard." };
        }
      }
    }

    // Execute the tool beneath
    const outcome = await next(event);

    // PostToolUse Sanitizer (in-memory redaction & truncation)
    if (outcome && "text" in outcome && typeof outcome.text === "string") {
      outcome.text = sanitizeOutput(outcome.text, { maxLines });
    }

    return outcome;
  });

  // Register instant command /cleanwriting
  on("session.start", async ($, event, next) => {
    await $.command.register({
      name: "cleanwriting",
      description: "Higieniza texto removendo travessões e emojis para conformidade com a Regra 875",
      argumentHint: "[texto]",
    });
    return next(event);
  });

  on("command.run", { command: "cleanwriting" }, async ($, event) => {
    const text = (event.args || "").trim();
    if (!text) {
      return { text: "Uso: /cleanwriting <texto a higienizar>" };
    }
    const cleaned = cleanWriting(text);
    return { text: `Original: ${text}\nHigienizado: ${cleaned}` };
  });
};
