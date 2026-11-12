import { NavLink } from "react-router-dom";

export interface TabItem {
  to: string;
  label: string;
  count?: number | null;
  end?: boolean;
}

export default function TabLinks({ items, label }: { items: TabItem[]; label: string }) {
  return (
    <nav className="tab-links" aria-label={label}>
      {items.map((t) => (
        <NavLink key={t.to} to={t.to} end={t.end} className={({ isActive }) => (isActive ? "active" : "")}>
          {t.label}
          {t.count != null && <span className="tab-count">{t.count}</span>}
        </NavLink>
      ))}
    </nav>
  );
}
