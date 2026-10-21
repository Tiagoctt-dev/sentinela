import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./components/AuthContext";
import Layout from "./components/Layout";
import AuditPage from "./pages/Audit";
import UsersPage from "./pages/Users";
import FindingDetailPage from "./pages/FindingDetail";
import FindingsPage from "./pages/Findings";
import IntegrationsPage from "./pages/Integrations";
import PoliciesPage from "./pages/Policies";
import ScanDetailPage from "./pages/ScanDetail";
import ScanListPage from "./pages/ScanList";
import SettingsPage from "./pages/Settings";
import TargetsPage from "./pages/Targets";

export default function App() {
  return (
    <AuthProvider>
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<TargetsPage />} />
        <Route path="/projetos" element={<Navigate to="/" replace />} />
        <Route path="/scans" element={<ScanListPage />} />
        <Route path="/achados" element={<FindingsPage />} />
        <Route path="/achados/:rowId" element={<FindingDetailPage />} />
        <Route path="/politicas" element={<PoliciesPage />} />
        <Route path="/integracoes" element={<IntegrationsPage />} />
        <Route path="/configuracoes" element={<SettingsPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/usuarios" element={<UsersPage />} />
        <Route path="/auditoria" element={<AuditPage />} />
      </Route>
    </Routes>
    </AuthProvider>
  );
}
