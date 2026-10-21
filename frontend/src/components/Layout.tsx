import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "./AuthContext";
import { ScanRunProvider } from "./ScanRunContext";
import { ToastProvider } from "./ui/ToastContext";

export default function Layout() {
  const [scanCount, setScanCount] = useState<number | null>(null);
  const [findingCount, setFindingCount] = useState<number | null>(null);
  const [navOpen, setNavOpen] = useState(false);
  const { user, isAdmin, logout } = useAuth();

  useEffect(() => {
    api.getStats().then((s) => setScanCount(s.totalScans)).catch(() => {});
    api.listFindings({ resolution: "open" }).then((f) => setFindingCount(f.length)).catch(() => {});
  }, []);

  return (
    <ToastProvider>
      <ScanRunProvider>
        <div className="shell">
          <div className="topbar">
            <span className="hex">⬢</span>
            <span className="name">Sentinela</span>
            <button className="hamburger" onClick={() => setNavOpen(true)} aria-label="Abrir menu">
              ☰
            </button>
          </div>

          <div className="shell-body">
          <div className={`sidebar-backdrop ${navOpen ? "open" : ""}`} onClick={() => setNavOpen(false)} />

          <aside className={`sidebar ${navOpen ? "open" : ""}`}>
            <div className="sidebar-brand">
              <span className="hex">⬢</span>
              <span className="name">Sentinela</span>
            </div>

            <div className="sidebar-section">Fluxo de trabalho</div>
            <nav className="sidebar-nav" onClick={() => setNavOpen(false)}>
              <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
                <span className="step-num">1</span>
                <span className="nav-label">
                  Projetos
                </span>
              </NavLink>
              <NavLink to="/scans" className={({ isActive }) => (isActive ? "active" : "")}>
                <span className="step-num">2</span>
                <span className="nav-label">
                  Scans
                </span>
                {scanCount != null && <span className="count">{scanCount}</span>}
              </NavLink>
              <NavLink to="/achados" className={({ isActive }) => (isActive ? "active" : "")}>
                <span className="step-num">3</span>
                <span className="nav-label">
                  Achados
                </span>
                {findingCount != null && <span className="count">{findingCount}</span>}
              </NavLink>
            </nav>

            <div className="sidebar-section">Regras e conexões</div>
            <nav className="sidebar-nav" onClick={() => setNavOpen(false)}>
              <NavLink to="/politicas" className={({ isActive }) => (isActive ? "active" : "")}>
                <span className="nav-label">
                  Políticas
                </span>
              </NavLink>
              <NavLink to="/integracoes" className={({ isActive }) => (isActive ? "active" : "")}>
                <span className="nav-label">
                  Integrações
                </span>
              </NavLink>
            </nav>

            {isAdmin && (
              <>
                <div className="sidebar-section">Administração</div>
                <nav className="sidebar-nav" onClick={() => setNavOpen(false)}>
                  <NavLink to="/usuarios" className={({ isActive }) => (isActive ? "active" : "")}>
                    <span className="nav-label">
                      Usuários
                    </span>
                  </NavLink>
                  <NavLink to="/auditoria" className={({ isActive }) => (isActive ? "active" : "")}>
                    <span className="nav-label">
                      Auditoria
                    </span>
                  </NavLink>
                </nav>
              </>
            )}

            <div className="sidebar-spacer" />

            <div className="sidebar-foot">
              <div className="sidebar-user">
                <div style={{ minWidth: 0 }}>
                  <div className="who">{user?.name}</div>
                  <div className="role">{{ admin: "Administrador", analyst: "Analista", viewer: "Somente leitura" }[user?.role ?? "viewer"]}</div>
                </div>
                {user?.id !== "local" && (
                  <button className="ghost sm" onClick={logout}>
                    Sair
                  </button>
                )}
              </div>
              <NavLink to="/configuracoes" className="sidebar-settings" onClick={() => setNavOpen(false)}>
                Configurações
              </NavLink>
            </div>
          </aside>

          <main className="main">
            <Outlet />
          </main>
          </div>
        </div>
      </ScanRunProvider>
    </ToastProvider>
  );
}
