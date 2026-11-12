import { describe, expect, it } from "vitest";
import type { FindingState } from "../api/client";
import { assetLabel, compareFindings, countBy, isProblem, STATE_META, STATES, stateMeta, timeAgo } from "./results";

describe("estados", () => {
  it("todo estado conhecido tem rótulo, ícone e explicação", () => {
    for (const s of STATES) {
      const m = STATE_META[s];
      expect(m.label.length).toBeGreaterThan(3);
      expect(m.icon).not.toBe("");
      expect(m.help.length).toBeGreaterThan(10);
    }
  });

  it("estado desconhecido NUNCA é exibido como aprovado", () => {
    const m = stateMeta("novo_estado_do_backend");
    expect(m.tone).not.toBe("ok");
    expect(m.label.toLowerCase()).not.toContain("aprovado");
    expect(m.label).toContain("novo_estado_do_backend");
    expect(stateMeta(undefined).tone).not.toBe("ok");
    expect(stateMeta(null).label).toContain("desconhecido");
  });

  it("apenas 'passed' tem tom de aprovação", () => {
    const ok = STATES.filter((s) => STATE_META[s].tone === "ok");
    expect(ok).toEqual(["passed"]);
  });

  it("só vulnerável e provável contam como problema", () => {
    const problemas = STATES.filter((s) => isProblem(s));
    expect(problemas).toEqual(["vulnerable", "likely"]);
  });
});

describe("ordenação", () => {
  it("ordena por estado (confirmada antes de provável) e depois por severidade", () => {
    const rows = [
      { severity: "LOW", state: "vulnerable" },
      { severity: "CRITICAL", state: "likely" },
      { severity: "HIGH", state: "vulnerable" },
      { severity: "CRITICAL", state: "vulnerable" },
    ] as { severity: "CRITICAL" | "HIGH" | "LOW"; state: FindingState }[];
    const sorted = [...rows].sort(compareFindings);
    expect(sorted.map((r) => `${r.state}:${r.severity}`)).toEqual([
      "vulnerable:CRITICAL", "vulnerable:HIGH", "vulnerable:LOW", "likely:CRITICAL",
    ]);
  });
});

describe("utilitários", () => {
  it("countBy conta sem perder itens", () => {
    expect(countBy(["a", "b", "a"], (x) => x)).toEqual({ a: 2, b: 1 });
  });

  it("assetLabel mostra método, caminho e parâmetro, ou 'Alvo (raiz)' sem caminho", () => {
    expect(assetLabel({ method: "PUT", path: "/users/x/email" })).toBe("PUT /users/x/email");
    expect(assetLabel({ method: "GET", path: "/api/preview", param: "url" })).toBe("GET /api/preview · url");
    expect(assetLabel(null)).toBe("Alvo (raiz)");
  });

  it("timeAgo", () => {
    const now = Date.parse("2026-10-22T12:00:00Z");
    expect(timeAgo("2026-10-22T11:59:40Z", now)).toBe("agora");
    expect(timeAgo("2026-10-22T11:30:00Z", now)).toBe("há 30 min");
    expect(timeAgo("2026-10-22T06:00:00Z", now)).toBe("há 6 h");
    expect(timeAgo("2026-10-20T12:00:00Z", now)).toBe("há 2 d");
  });
});
