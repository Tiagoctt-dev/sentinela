import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "./AuthContext";

interface Item {
  key: string;
  label: string;
  hint: string;
  to: string;
}

const PAGES: Item[] = [
  { key: "p-dash", label: "Visão geral", hint: "Página", to: "/" },
  { key: "p-proj", label: "Projetos", hint: "Página", to: "/projetos" },
  { key: "p-scans", label: "Scans", hint: "Página", to: "/scans" },
  { key: "p-find", label: "Achados de segurança", hint: "Página", to: "/achados" },
  { key: "p-routes", label: "Rotas e verificações", hint: "Página", to: "/rotas" },
  { key: "p-pol", label: "Políticas", hint: "Página", to: "/politicas" },
  { key: "p-int", label: "Integrações", hint: "Página", to: "/integracoes" },
  { key: "p-set", label: "Configurações e minha conta", hint: "Página", to: "/configuracoes" },
];

const fold = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();

/** Busca global (Ctrl/⌘ + K): páginas, projetos, scans recentes e achados. Teclado completo: ↑ ↓ Enter Esc. */
export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [dynamic, setDynamic] = useState<Item[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    openerRef.current = document.activeElement as HTMLElement | null;
    setQ("");
    setActive(0);
    inputRef.current?.focus();
    let alive = true;
    Promise.all([api.listTargets().catch(() => []), api.listScans().catch(() => []), api.listFindings().catch(() => [])]).then(([targets, scans, findings]) => {
      if (!alive) return;
      setDynamic([
        ...targets.map((t) => ({ key: `t-${t.id}`, label: t.config.name || t.name, hint: "Projeto", to: `/scans?targetId=${t.id}` })),
        ...scans.slice(0, 15).map((s) => ({ key: `s-${s.id}`, label: `Scan de ${s.targetName}`, hint: new Date(s.createdAt).toLocaleString("pt-BR"), to: `/scans/${s.id}` })),
        ...findings.map((f) => ({ key: `f-${f.rowId}`, label: f.title, hint: `Achado · ${f.targetName}`, to: `/achados/${f.rowId}` })),
      ]);
    });
    return () => {
      alive = false;
      openerRef.current?.focus?.();
    };
  }, [open]);

  const items = useMemo(() => {
    const pages = isAdmin ? [...PAGES, { key: "p-usr", label: "Usuários", hint: "Página", to: "/usuarios" }, { key: "p-aud", label: "Auditoria", hint: "Página", to: "/auditoria" }] : PAGES;
    const all = [...pages, ...dynamic];
    const term = fold(q.trim());
    return (term ? all.filter((i) => fold(`${i.label} ${i.hint}`).includes(term)) : all).slice(0, 12);
  }, [q, dynamic, isAdmin]);

  useEffect(() => setActive(0), [q]);

  if (!open) return null;

  const go = (item: Item | undefined) => {
    if (!item) return;
    onClose();
    navigate(item.to);
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(items[active]);
    } else if (e.key === "Tab") {
      e.preventDefault(); // o foco fica no campo; a lista se navega pelas setas
    }
  };

  return (
    <div className="palette-backdrop" onClick={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Busca global" onClick={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <input
          ref={inputRef}
          type="search"
          className="palette-input"
          placeholder="Buscar página, projeto, scan ou achado…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={items[active] ? `pal-${items[active].key}` : undefined}
          aria-label="Buscar"
        />
        <ul id="palette-list" className="palette-list" role="listbox">
          {items.map((i, idx) => (
            <li key={i.key} id={`pal-${i.key}`} role="option" aria-selected={idx === active} className={idx === active ? "active" : ""} onMouseEnter={() => setActive(idx)} onClick={() => go(i)}>
              <span className="palette-label">{i.label}</span>
              <span className="palette-hint">{i.hint}</span>
            </li>
          ))}
          {items.length === 0 && <li className="palette-empty">Nada encontrado para “{q}”.</li>}
        </ul>
        <div className="palette-foot">↑↓ navegar · Enter abrir · Esc fechar</div>
      </div>
    </div>
  );
}
