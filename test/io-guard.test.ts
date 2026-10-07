import { describe, expect, it } from "bun:test";
import { register } from "../hooks/register.js";

describe("io-guard plugin", () => {
  it("registers tool.call, session.start and command.run", () => {
    const handlers: Record<string, Function> = {};
    const on = (event: string, filterOrHandler: unknown, maybeHandler?: unknown) => {
      const handler = (maybeHandler ?? filterOrHandler) as Function;
      handlers[event] = handler;
    };

    register(on as any, { maxLines: 100 });

    expect(typeof handlers["tool.call"]).toBe("function");
    expect(typeof handlers["session.start"]).toBe("function");
    expect(typeof handlers["command.run"]).toBe("function");
  });

  it("blocks commands violating Rule 875", async () => {
    const handlers: Record<string, Function> = {};
    const on = (event: string, filterOrHandler: unknown, maybeHandler?: unknown) => {
      const handler = (maybeHandler ?? filterOrHandler) as Function;
      handlers[event] = handler;
    };

    register(on as any, {});

    const mockDollar = {
      ui: { log: () => {}, toast: () => {} },
    };

    const next = () => ({ status: "allowed" });
    const event = {
      tool: "Bash",
      input: { command: 'git commit -m "feat: commit — violando regra"' },
    };

    const result = await handlers["tool.call"](mockDollar, event, next);
    expect(result).toHaveProperty("deny");
    expect(result.deny).toContain("Regra 875 violada");
  });

  it("sanitizes tool output in tool.call", async () => {
    const handlers: Record<string, Function> = {};
    const on = (event: string, filterOrHandler: unknown, maybeHandler?: unknown) => {
      const handler = (maybeHandler ?? filterOrHandler) as Function;
      handlers[event] = handler;
    };

    register(on as any, { maxLines: 50 });

    const mockDollar = {
      ui: { log: () => {}, toast: () => {} },
    };
    const event = { tool: "Bash", input: { command: "cat secret.txt" } };
    const next = () => ({ text: "Secret: sk-live-1234567890abcdef1234567890" });

    const result = await handlers["tool.call"](mockDollar, event, next);
    expect(result.text).not.toContain("sk-live-1234567890abcdef1234567890");
    expect(result.text).toContain("sk-liv...7890");
  });

  it("handles /cleanwriting command", async () => {
    const handlers: Record<string, Function> = {};
    const on = (event: string, filterOrHandler: unknown, maybeHandler?: unknown) => {
      const handler = (maybeHandler ?? filterOrHandler) as Function;
      handlers[event] = handler;
    };

    register(on as any, {});

    const mockDollar = {};
    const event = { args: "Refatoração — ajuste fino 🚀" };
    const result = await handlers["command.run"](mockDollar, event);
    expect(result.text).toContain("Higienizado: Refatoração - ajuste fino");
  });
});
