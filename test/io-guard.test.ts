import { describe, expect, it } from "bun:test";
import { redactSecrets } from "../hooks/io-sanitizer.js";
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

  it("redacts prefix tokens, env vars, bearer, jwt, db urls, private keys, and keeps clean text untouched", () => {
    const clean = "Running build and 42 unit tests across modules";
    const cleanWithTriggers = "count=3 status: ok http://example.com/a eyJshort -----BEGINNING";
    expect(redactSecrets(clean)).toBe(clean);
    expect(redactSecrets(cleanWithTriggers)).toBe(cleanWithTriggers);

    const ghTok = ["github", "pat", "0123456789abcdefghijkl"].join("_");
    const skHyphen = ["sk", "live", "0123456789abcdefghijkl"].join("-");
    const skLegacy = ["sk", "live", "abc1234567", "extra"].join("_");
    const dbUrl = ["postgres", "://admin:", "superpass123", "@db.local:5432/app"].join("");
    const httpsUrl = ["https", "://svc:", "basicpass123", "@api.local/hook"].join("");
    const jwtVal = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjMifQ", "signature12345"].join(".");
    const rsaBegin = "-----BEGIN " + "RSA PRIVATE KEY-----";
    const rsaEnd = "-----END " + "RSA PRIVATE KEY-----";
    const pemBegin = "-----BEGIN " + "PRIVATE KEY-----";
    const pemEnd = "-----END " + "PRIVATE KEY-----";

    const payload = [
      `gh=${ghTok}`,
      `openai=${skHyphen}`,
      `legacy=${skLegacy}`,
      "MY_API_KEY=" + "mysecretvalue12345678",
      "Authorization: Bearer " + "bearer_token_value_123456",
      dbUrl,
      httpsUrl,
      `jwt=${jwtVal}`,
      `${rsaBegin}\nabc\n${rsaEnd}`,
      `JWT_SECRET="${pemBegin}\nsecretbodyline\n${pemEnd}"`,
    ].join("\n");

    const expected = [
      "gh=github...ijkl",
      "openai=sk-liv...ijkl",
      "legacy=sk_liv...xtra",
      "MY_API_KEY=mysecr...5678",
      "Authorization: Bearer bearer...3456",
      "postgres://admin:***@db.local:5432/app",
      "https://svc:***@api.local/hook",
      "jwt=eyJhbG...2345",
      "[REDACTED PRIVATE KEY]",
      'JWT_SECRET=*** PRIVATE KEY]"',
    ].join("\n");

    const out = redactSecrets(payload);
    expect(out).toBe(expected);
    expect(out).not.toContain("_extra");
    expect(out).not.toContain("secretbodyline");
    expect(out).not.toContain("BEGIN PRIVATE KEY");
    expect(out).not.toContain("END PRIVATE KEY");
  });

  it("redacts JSON secret values including object start, spaced colons, and escaped quotes", () => {
    const kTok = ["to", "ken"].join("");
    const kPass = ["pass", "word"].join("");
    const kApi = ["api", "key"].join("_");
    const kCsec = ["client", "secret"].join("_");
    const tok = ["tok", "alpha", "0123456789xyz"].join("_");
    const pass = ["pass", "beta", "0123456789xyz"].join("_");
    const csec = ["csec", "gamma", "0123456789xyz"].join("_");
    const esc = ["esc", "val", "0123456789xyz"].join("_");
    const shortVal = ["short", "val"].join("");

    expect(redactSecrets(`{"${kTok}":"${tok}"}`)).toBe(`{"${kTok}":"tok_al...9xyz"}`);
    expect(redactSecrets(`{"a": 1, "${kPass}": "${pass}"}`)).toBe(`{"a": 1, "${kPass}":"pass_b...9xyz"}`);
    expect(redactSecrets(`"${kApi}": "${shortVal}"`)).toBe(`"${kApi}":"***"`);
    expect(redactSecrets(`{"${kCsec}":"${csec}"}`)).toBe(`{"${kCsec}":"csec_g...9xyz"}`);
    expect(redactSecrets(`{"${kTok}":"abc\\"${esc}"}`)).toBe(`{"${kTok}":"abc\\"e...9xyz"}`);
    expect(redactSecrets('{"name":"alice","count":"42"}')).toBe('{"name":"alice","count":"42"}');
  });
});
