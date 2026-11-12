// Regressão de contraste: lê os tokens de cor de styles.css (tema claro e escuro) e confere WCAG 2.1 AA.
// Texto: >= 4.5:1 sobre as superfícies onde aparece. Componentes de interface (borda de campo): >= 3:1.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(__dirname, "../styles.css"), "utf-8");

function block(start: RegExp): string {
  const m = start.exec(css);
  if (!m) throw new Error("bloco de tokens não encontrado");
  let depth = 0;
  for (let i = css.indexOf("{", m.index); i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) return css.slice(css.indexOf("{", m.index) + 1, i);
  }
  throw new Error("bloco não fechado");
}

function tokens(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}

const light = tokens(block(/^:root\s*\{/m));
const darkBody = block(/@media \(prefers-color-scheme: dark\)\s*\{/);
const dark = { ...light, ...tokens(darkBody) };

type RGBA = [number, number, number, number];

function parse(value: string, theme: Record<string, string>): RGBA {
  const v = value.trim();
  const ref = /^var\(--([\w-]+)\)$/.exec(v);
  if (ref) return parse(theme[ref[1]], theme);
  let m = /^#([0-9a-f]{6})$/i.exec(v);
  if (m) return [0, 2, 4].map((i) => parseInt(m![1].slice(i, i + 2), 16)).concat(1) as RGBA;
  m = /^rgba?\(([^)]+)\)$/.exec(v);
  if (m) {
    const p = m[1].split(",").map((x) => parseFloat(x));
    return [p[0], p[1], p[2], p[3] ?? 1];
  }
  throw new Error(`cor não reconhecida: ${value}`);
}

function over(fg: RGBA, bg: RGBA): RGBA {
  const a = fg[3];
  return [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a), 1];
}

function lum([r, g, b]: RGBA): number {
  const f = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function ratio(a: RGBA, b: RGBA): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const SURFACES = ["bg", "panel", "panel-2", "bg-raised"];
const TEXT = ["ink", "ink-2", "muted", "faint", "accent", "ok"];
const SEVERITY = ["crit", "high", "med", "low", "na"];

for (const [name, theme] of [["claro", light], ["escuro", dark]] as const) {
  describe(`contraste — tema ${name}`, () => {
    const c = (token: string) => parse(`var(--${token})`, theme);

    for (const t of TEXT) {
      for (const s of SURFACES) {
        it(`${t} sobre ${s} >= 4.5:1`, () => {
          expect(ratio(over(c(t), c(s)), c(s))).toBeGreaterThanOrEqual(4.5);
        });
      }
    }

    for (const sev of SEVERITY) {
      it(`${sev} sobre o próprio fundo suave (badge) >= 4.5:1`, () => {
        for (const s of ["panel", "panel-2"]) {
          const bg = over(c(`${sev}-soft`), c(s));
          expect(ratio(c(sev), bg)).toBeGreaterThanOrEqual(4.5);
        }
      });
    }

    it("texto sobre o botão primário (on-accent sobre accent) >= 4.5:1", () => {
      expect(ratio(c("on-accent"), c("accent"))).toBeGreaterThanOrEqual(4.5);
    });

    for (const sev of ["crit", "high", "med", "low", "ok"]) {
      it(`cor de gráfico ${sev} sobre o painel >= 3:1 (WCAG 1.4.11)`, () => {
        expect(ratio(c(`chart-${sev}`), c("panel"))).toBeGreaterThanOrEqual(3);
      });
    }

    it("texto do botão de perigo (on-crit sobre crit) >= 4.5:1", () => {
      expect(ratio(c("on-crit"), c("crit"))).toBeGreaterThanOrEqual(4.5);
    });

    it("borda dos campos de formulário >= 3:1 (WCAG 1.4.11)", () => {
      expect(ratio(c("field-border"), c("bg-raised"))).toBeGreaterThanOrEqual(3);
    });
  });
}
