import type { RouteItem } from "../api/client";

export function filterRoutes(routes: RouteItem[], state: string, q: string): RouteItem[] {
  const needle = q.trim().toLowerCase();
  return routes.filter((r) => {
    if (state && r.state !== state) return false;
    if (needle && !`${r.method} ${r.path} ${r.checks.map((c) => `${c.checkId} ${c.title}`).join(" ")}`.toLowerCase().includes(needle)) return false;
    return true;
  });
}
