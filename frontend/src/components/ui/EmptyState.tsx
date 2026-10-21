import { ReactNode } from "react";

interface EmptyStateProps {
  icon?: string;
  title: string;
  description?: string;
  action?: ReactNode;
}

export default function EmptyState({ icon = "◌", title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <div className="icon">{icon}</div>
      <div className="title">{title}</div>
      {description && <div className="desc">{description}</div>}
      {action && <div className="action">{action}</div>}
    </div>
  );
}
