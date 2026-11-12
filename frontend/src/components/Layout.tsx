import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "./AuthContext";
import CommandPalette from "./CommandPalette";
import { ScanRunProvider } from "./ScanRunContext";
import ThemeToggle from "./ThemeToggle";
import Icon from "./ui/Icon";
import { ToastProvider } from "./ui/ToastContext";

interface NavItem {
  to: string;
  label: string;
  icon: string;
  end?: boolean;
  count?: number | null;
}

const ROLE_LABEL = { admin: "Administrador", analyst: "Analista", viewer: "Somente leitura" } as const;

export default function Layout() {
  const [findingCount, setFindingCount] = useState<number | null>(null);
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const { user, isAdmin, logout } = useAuth();
  const location = useLocation();

  useEffect(() => {
    api.countFindings({ resolution: "open" }).then((r) => setFindingCount(r.count)).catch(() => setFindingCount(null));
  }, [location.pathname]);

  // Ao trocar de página, leva o foco ao conteúdo (leitores de tela anunciam a mudança; teclado não fica preso no menu).
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus({ preventScroll: true });
  }, [location.pathname]);

  useEffect(() => setNavOpen(false), [location.pathname]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setNavOpen(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [navOpen]);

  const groups: { title: string; items: NavItem[] }[] = [
    {
      title: "Análise",
      items: [
        { to: "/", label: "Visão geral", icon: "dashboard", end: true },
        { to: "/projetos", label: "Projetos", icon: "projects" },
        { to: "/scans", label: "Scans", icon: "scans" },
      ],
    },
    {
      title: "Resultados",
      items: [
        { to: "/achados", label: "Achados", icon: "findings", count: findingCount },
        { to: "/rotas", label: "Rotas e verificações", icon: "routes" },
      ],
    },
    {
      title: "Configuração",
      items: [
        { to: "/politicas", label: "Políticas", icon: "policies" },
        { to: "/integracoes", label: "Integrações", icon: "integrations" },
        ...(isAdmin
          ? [
              { to: "/usuarios", label: "Usuários", icon: "users" },
              { to: "/auditoria", label: "Auditoria", icon: "audit" },
            ]
          : []),
      ],
    },
  ];

  return (
    <ToastProvider>
      <ScanRunProvider>
        <div className="shell">
          <a className="skip-link" href="#conteudo" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>
            Ir para o conteúdo
          </a>
          <div className="topbar">
            <span className="hex" aria-hidden="true">⬢</span>
            <span className="name">Sentinela</span>
            <button className="hamburger" onClick={() => setNavOpen(true)} aria-label="Abrir menu" aria-expanded={navOpen} aria-controls="sidebar">
              <Icon name="menu" />
            </button>
          </div>

          <div className="shell-body">
            <div className={`sidebar-backdrop ${navOpen ? "open" : ""}`} onClick={() => setNavOpen(false)} />

            <aside id="sidebar" className={`sidebar ${navOpen ? "open" : ""}`} aria-label="Menu principal">
              <div className="sidebar-brand">
                <span className="hex" aria-hidden="true">⬢</span>
                <span className="name">Sentinela</span>
                <button className="sidebar-close" onClick={() => setNavOpen(false)} aria-label="Fechar menu">
                  <Icon name="close" />
                </button>
              </div>

              <button type="button" className="palette-trigger" onClick={() => setPaletteOpen(true)} aria-label="Buscar (Ctrl K)">
                <Icon name="search" />
                <span>Buscar…</span>
                <kbd>Ctrl K</kbd>
              </button>

              {groups.map((g) => (
                <div key={g.title} className="sidebar-group">
                  <div className="sidebar-section">{g.title}</div>
                  <nav className="sidebar-nav" aria-label={g.title}>
                    {g.items.map((item) => (
                      <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => (isActive ? "active" : "")}>
                        <Icon name={item.icon} />
                        <span className="nav-label">{item.label}</span>
                        {item.count != null && item.count > 0 && (
                          <span className="count" aria-label={`${item.count} em aberto`}>{item.count}</span>
                        )}
                      </NavLink>
                    ))}
                  </nav>
                </div>
              ))}

              <div className="sidebar-spacer" />

              <div className="sidebar-foot">
                <ThemeToggle />
                <NavLink to="/configuracoes" className={({ isActive }) => `sidebar-settings ${isActive ? "active" : ""}`}>
                  <Icon name="settings" /> Configurações
                </NavLink>
                <div className="sidebar-user">
                  <div className="min-0">
                    <div className="who">{user?.name}</div>
                    <div className="role">{ROLE_LABEL[user?.role ?? "viewer"]}</div>
                  </div>
                  {user?.id !== "local" && (
                    <button className="ghost sm" onClick={() => void logout()}>
                      Sair
                    </button>
                  )}
                </div>
              </div>
            </aside>

            <main className="main" id="conteudo" tabIndex={-1} ref={mainRef}>
              <Outlet />
            </main>
          </div>
        </div>
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      </ScanRunProvider>
    </ToastProvider>
  );
}
