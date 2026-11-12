/**
 * Contrato API -> interface. As fixtures foram geradas pelo PRÓPRIO backend (backend/scripts/dump_contract_fixture.py)
 * contra um alvo de laboratório. Os testes provam que a UI mostra exatamente o que a API devolve: nenhum campo se
 * perde, nenhuma classificação muda e nenhum estado desconhecido vira "aprovado".
 */
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { describe, expect, it } from "vitest";
import type { Dashboard, FindingWithContext, RoutesView, ScanDetail } from "../api/client";
import { Donut, StackedBar } from "../components/charts/Charts";
import FindingsTable from "../components/FindingsTable";
import { RouteStateBadge, SevBadge, StateBadge } from "../components/ui/Badge";
import { applyFilters } from "../lib/findingFilters";
import { filterRoutes } from "../lib/routeFilters";
import { assetLabel, isProblem, SEVERITY_LABEL, STATE_META, stateMeta } from "../lib/results";
import compare from "./fixtures/compare.json";
import dashboard from "./fixtures/dashboard.json";
import findings from "./fixtures/findings.json";
import routes from "./fixtures/routes.json";
import external from "./fixtures/scan-external.json";
import scan from "./fixtures/scan.json";

const S = scan as unknown as ScanDetail;
const EXT = external as unknown as ScanDetail;
const R = routes as unknown as RoutesView;
const D = dashboard as unknown as Dashboard;
const F = findings as unknown as FindingWithContext[];

const html = (node: React.ReactElement) => renderToStaticMarkup(<StaticRouter location="/">{node}</StaticRouter>);
const text = (markup: string) => markup.replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/\s+/g, " ");

describe("formato da resposta da API", () => {
  it("todo achado traz estado, confiança, severidade e metadados editoriais", () => {
    expect(S.findings.length).toBeGreaterThan(10);
    for (const f of S.findings) {
      expect(Object.keys(STATE_META)).toContain(f.state);
      expect(["confirmed", "indicative", "none"]).toContain(f.confidence);
      expect(Object.keys(SEVERITY_LABEL)).toContain(f.severity);
      expect(f.meta?.headline).toBeTruthy();
      expect(Array.isArray(f.meta?.references)).toBe(true);
    }
  });

  it("estado e confiança são coerentes: só vulnerável/provável têm confiança", () => {
    for (const f of S.findings) {
      if (f.state === "vulnerable") expect(f.confidence).toBe("confirmed");
      else if (f.state === "likely") expect(f.confidence).toBe("indicative");
      else expect(f.confidence).toBe("none");
    }
  });

  it("totais por estado do scan batem com a lista de achados", () => {
    const contados: Record<string, number> = {};
    S.findings.forEach((f) => (contados[f.state] = (contados[f.state] ?? 0) + 1));
    for (const [estado, n] of Object.entries(S.totals.states ?? {})) expect(contados[estado] ?? 0).toBe(n);
  });
});

describe("achados na interface", () => {
  const problems = S.findings.filter((f) => isProblem(f.state)) as FindingWithContext[];

  it("a tabela mostra exatamente os campos devolvidos para cada achado", () => {
    const markup = html(<FindingsTable findings={problems} />);
    const t = text(markup);
    for (const f of problems) {
      expect(t).toContain(f.id);
      expect(t).toContain(f.meta?.headline ?? f.title);
      expect(t).toContain(assetLabel(f.asset));
      expect(t).toContain(STATE_META[f.state].short);
      expect(markup).toContain(`/achados/${f.rowId}`);
    }
    expect((markup.match(/<tr>/g) ?? []).length).toBe(problems.length + 1); // + cabeçalho
  });

  it("severidade aparece sempre em texto, não só em cor", () => {
    for (const sev of Object.keys(SEVERITY_LABEL) as (keyof typeof SEVERITY_LABEL)[]) {
      expect(text(html(<SevBadge severity={sev} />))).toContain(SEVERITY_LABEL[sev]);
    }
  });

  it("o estado de cada achado é exibido com o rótulo correspondente (sem trocar a classificação)", () => {
    for (const f of S.findings) {
      const t = text(html(<StateBadge state={f.state} />));
      expect(t).toContain(STATE_META[f.state].label);
      if (f.state !== "passed") expect(t.toLowerCase()).not.toContain("aprovado");
    }
  });

  it("estado desconhecido enviado pelo backend aparece como desconhecido, nunca como aprovado", () => {
    const t = text(html(<StateBadge state="estado_futuro" />));
    expect(t.toLowerCase()).not.toContain("aprovado");
    expect(t).toContain("estado_futuro");
    expect(stateMeta("estado_futuro").tone).toBe("warn");
  });

  it("filtros do cliente só reduzem a lista — nunca alteram campos de um achado", () => {
    const antes = JSON.stringify(F);
    const f1 = applyFilters(F, { severidade: "CRITICAL" }, "severidade");
    const f2 = applyFilters(F, { estado: "likely", q: "rate" }, "ativo");
    expect(JSON.stringify(F)).toBe(antes);
    expect(f1.every((f) => f.severity === "CRITICAL")).toBe(true);
    expect(f2.every((f) => f.state === "likely")).toBe(true);
    expect(applyFilters(F, {}, "severidade")).toHaveLength(F.length);
  });
});

describe("rotas e verificações", () => {
  it("contadores são consistentes com a lista de rotas", () => {
    const c = R.counts;
    expect(c.routes).toBe(R.routes.length);
    expect(Object.values(c.byState).reduce((a, b) => a + b, 0)).toBe(c.routes);
    expect(c.tested + c.pending).toBe(c.known);
    expect(R.routes.filter((r) => r.known).length).toBe(c.known);
    expect(Object.values(c.checks).reduce((a, b) => (a ?? 0) + (b ?? 0), 0)).toBe(R.routes.reduce((n, r) => n + r.checks.length, 0));
  });

  it("rota descoberta e nunca chamada aparece como 'não testada', não como aprovada", () => {
    const pendente = R.routes.find((r) => r.path === "/createdb");
    expect(pendente?.state).toBe("not_tested");
    expect(text(html(<RouteStateBadge state="not_tested" />)).toLowerCase()).not.toContain("sem falha");
  });

  it("o estado da rota é o pior resultado entre suas verificações", () => {
    const rank = { vulnerable: 5, likely: 4, error: 3, inconclusive: 2, passed: 1 } as Record<string, number>;
    for (const r of R.routes) {
      const piores = r.checks.map((c) => rank[c.state] ?? 0);
      if (piores.some((p) => p > 0)) {
        const esperado = Object.entries(rank).find(([, v]) => v === Math.max(...piores))?.[0];
        expect(r.state).toBe(esperado);
      }
    }
  });

  it("filtro por estado devolve só rotas daquele estado", () => {
    const vuln = filterRoutes(R.routes, "vulnerable", "");
    expect(vuln.length).toBe(R.counts.byState.vulnerable);
    expect(vuln.every((r) => r.state === "vulnerable")).toBe(true);
  });

  it("verificações não executadas trazem o motivo", () => {
    expect(R.pendingChecks.every((c) => c.reason.length > 5)).toBe(true);
  });
});

describe("escopo e diferença entre modos (dados reais)", () => {
  it("scan externo declara o que não executou; o autenticado executa mais", () => {
    expect(EXT.scope?.mode).toBe("external");
    expect(S.scope?.mode).toBe("authenticated");
    expect((S.scope?.coveragePct ?? 0)).toBeGreaterThan(EXT.scope?.coveragePct ?? 100);
    expect(EXT.scope?.notRun.map((c) => c.id)).toContain("D-BOLA-01");
    expect(EXT.scope?.limitations.length).toBeGreaterThan(0);
  });

  it("verificações que exigem login não aparecem como aprovadas no scan externo", () => {
    const ids = EXT.findings.map((f) => f.id);
    expect(ids).not.toContain("D-BOLA-01");
    expect(ids).not.toContain("D-JWT-01");
  });

  it("comparação não conta 'não reavaliada' como corrigida", () => {
    const c = compare as { fixed?: { id: string }[]; notComparable?: { id: string }[] };
    expect(c.fixed?.map((f) => f.id)).toContain("D-BOLA-01");
    const naoComparaveis = new Set((c.notComparable ?? []).map((f) => f.id));
    expect((c.fixed ?? []).every((f) => !naoComparaveis.has(f.id))).toBe(true);
  });
});

describe("dashboard", () => {
  it("totais por severidade e por categoria somam o mesmo número de problemas", () => {
    const porSeveridade = Object.values(D.findings.bySeverity).reduce((a, b) => a + b, 0);
    const porCategoria = D.findings.byCategory.reduce((a, c) => a + c.vulnerable + c.likely, 0);
    expect(porSeveridade).toBe(porCategoria);
    expect(porSeveridade).toBe(D.findings.byState.vulnerable + D.findings.byState.likely);
  });

  it("gráficos exibem exatamente os números recebidos", () => {
    const segs = Object.entries(D.findings.bySeverity).map(([k, v]) => ({ key: k, label: SEVERITY_LABEL[k as keyof typeof SEVERITY_LABEL], value: v, tone: "crit" }));
    const t = text(html(<StackedBar segments={segs} label="Severidade" />));
    for (const s of segs) expect(t).toContain(`${s.label} ${s.value}`);
    const estados = Object.entries(D.findings.byState).map(([k, v]) => ({ key: k, label: STATE_META[k as keyof typeof STATE_META].short, value: v, tone: "na" }));
    const total = estados.reduce((n, s) => n + s.value, 0);
    const d = text(html(<Donut segments={estados} label="Estados" center={{ value: total, caption: "verificações" }} />));
    expect(d).toContain(String(total));
    for (const s of estados) expect(d).toContain(`${s.label} ${s.value}`);
  });

  it("sem histórico suficiente, a evolução é vazia e explica o motivo", () => {
    expect(D.trend.length === 0 || D.trend.length >= 2).toBe(true);
    if (D.trend.length === 0) expect(D.trendNote).toBeTruthy();
  });
});
