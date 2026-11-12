import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./components/AuthContext";
import Layout from "./components/Layout";
import AuditPage from "./pages/Audit";
import DashboardPage from "./pages/Dashboard";
import DesignSystemPage from "./pages/DesignSystem";
import FindingDetailPage from "./pages/FindingDetail";
import FindingsPage from "./pages/Findings";
import IntegrationsPage from "./pages/Integrations";
import PoliciesPage from "./pages/Policies";
import RoutesPage from "./pages/RoutesPage";
import ScanDetailPage from "./pages/ScanDetail";
import ScanListPage from "./pages/ScanList";
import SettingsPage from "./pages/Settings";
import TargetsPage from "./pages/Targets";
import UsersPage from "./pages/Users";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/projetos" element={<TargetsPage />} />
          <Route path="/scans" element={<ScanListPage />} />
          <Route path="/scans/:id" element={<ScanDetailPage tab="resumo" />} />
          <Route path="/scans/:id/achados" element={<ScanDetailPage tab="achados" />} />
          <Route path="/scans/:id/rotas" element={<ScanDetailPage tab="rotas" />} />
          <Route path="/achados" element={<FindingsPage />} />
          <Route path="/achados/:rowId" element={<FindingDetailPage />} />
          <Route path="/rotas" element={<RoutesPage />} />
          <Route path="/politicas" element={<PoliciesPage />} />
          <Route path="/integracoes" element={<IntegrationsPage />} />
          <Route path="/configuracoes" element={<SettingsPage />} />
          <Route path="/design" element={<DesignSystemPage />} />
          <Route path="/usuarios" element={<UsersPage />} />
          <Route path="/auditoria" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
