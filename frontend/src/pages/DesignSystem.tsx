import { useState } from "react";
import { SevBadge, StateBadge, StatusPill } from "../components/ui/Badge";
import Button from "../components/ui/Button";
import EmptyState from "../components/ui/EmptyState";
import { Field, FormActions, FormGrid } from "../components/ui/Form";
import Modal from "../components/ui/Modal";
import PageHeader from "../components/ui/PageHeader";
import StatTile from "../components/ui/StatTile";
import { StackedBar } from "../components/charts/Charts";
import { SEVERITIES, STATES } from "../lib/results";

const COLOR_TOKENS = ["bg", "panel", "panel-2", "border-strong", "ink", "muted", "faint", "accent", "ok", "crit", "high", "med", "low", "na"];
const SPACING = ["sp-1", "sp-2", "sp-3", "sp-4", "sp-5", "sp-6", "sp-7", "sp-8"];
const FONT_SIZES = ["fs-xs", "fs-sm", "fs-base", "fs-md", "fs-lg", "fs-xl"];

/** Catálogo vivo: mostra os componentes reais com os tokens reais — serve de referência e de teste visual. */
export default function DesignSystemPage() {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <PageHeader title="Design system" description="Tokens e componentes usados no Sentinela. Alterne o tema do sistema para ver claro e escuro. Documentação completa em docs/design-system.md." />

      <section className="panel" aria-labelledby="ds-colors">
        <h2 id="ds-colors">Cores (tokens)</h2>
        <div className="ds-swatches">
          {COLOR_TOKENS.map((t) => (
            <div key={t} className="ds-swatch">
              <span className="ds-chip" style={{ background: `var(--${t})` }} aria-hidden="true" />
              <code>--{t}</code>
            </div>
          ))}
        </div>
      </section>

      <section className="panel" aria-labelledby="ds-type">
        <h2 id="ds-type">Tipografia e espaçamento</h2>
        {FONT_SIZES.map((t) => (
          <p key={t} style={{ fontSize: `var(--${t})`, margin: "4px 0" }}>
            <code>--{t}</code> · Sentinela audita APIs
          </p>
        ))}
        <div className="ds-spacing">
          {SPACING.map((t) => (
            <div key={t} className="ds-space">
              <span style={{ width: `var(--${t})`, height: `var(--${t})` }} aria-hidden="true" />
              <code>--{t}</code>
            </div>
          ))}
        </div>
      </section>

      <section className="panel" aria-labelledby="ds-buttons">
        <h2 id="ds-buttons">Botões</h2>
        <div className="ds-row">
          <Button>Primário</Button>
          <Button variant="ghost">Secundário</Button>
          <Button variant="danger">Perigo</Button>
          <Button disabled>Desabilitado</Button>
          <Button loading loadingLabel="Salvando…">Carregando</Button>
          <Button size="sm">Pequeno</Button>
        </div>
      </section>

      <section className="panel" aria-labelledby="ds-badges">
        <h2 id="ds-badges">Etiquetas</h2>
        <div className="ds-row">{SEVERITIES.map((s) => <SevBadge key={s} severity={s} />)}</div>
        <div className="ds-row">{STATES.map((s) => <StateBadge key={s} state={s} short />)}</div>
        <div className="ds-row">
          <StatusPill tone="ok">ok</StatusPill>
          <StatusPill tone="warn">atenção</StatusPill>
          <StatusPill tone="fail">erro</StatusPill>
          <StatusPill tone="na">não aplicável</StatusPill>
        </div>
      </section>

      <section className="panel" aria-labelledby="ds-form">
        <h2 id="ds-form">Formulário</h2>
        <FormGrid>
          <Field label="Campo de texto" hint="Dica abaixo do campo, em até duas linhas.">
            <input placeholder="Exemplo" />
          </Field>
          <Field label="Seleção" optional>
            <select><option>Opção 1</option><option>Opção 2</option></select>
          </Field>
        </FormGrid>
        <FormActions>
          <Button variant="ghost">Cancelar</Button>
          <Button>Salvar</Button>
        </FormActions>
      </section>

      <section className="panel" aria-labelledby="ds-data">
        <h2 id="ds-data">Dados</h2>
        <div className="stat-row">
          <StatTile label="Indicador" value={12} hint="Texto de apoio" />
          <StatTile label="Com alerta" value={3} tone="crit" />
        </div>
        <StackedBar label="Exemplo" segments={[{ key: "a", label: "Crítica", value: 2, tone: "crit" }, { key: "b", label: "Alta", value: 3, tone: "high" }, { key: "c", label: "Média", value: 5, tone: "med" }]} />
      </section>

      <section className="panel" aria-labelledby="ds-feedback">
        <h2 id="ds-feedback">Feedback</h2>
        <div className="notice warn" role="note"><b>Aviso.</b> Texto de leitura com cautela.</div>
        <EmptyState icon="◎" title="Estado vazio" description="Diz o que é, por que está vazio e como começar." />
        <Button variant="ghost" onClick={() => setOpen(true)}>Abrir diálogo</Button>
        <Modal open={open} onClose={() => setOpen(false)} title="Diálogo de exemplo">
          <p>O foco entra aqui, Tab circula só dentro do diálogo, Esc fecha e o foco volta ao botão que abriu.</p>
          <FormActions><Button onClick={() => setOpen(false)}>Entendi</Button></FormActions>
        </Modal>
      </section>
    </div>
  );
}
