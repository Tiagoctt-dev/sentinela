import { ReactNode } from "react";

// Padrão único de formulário: <Form> > <FormSection> > <FormGrid> > <Field>, terminando em <FormActions>.

export function Field({
  label, hint, optional, group, className = "", children,
}: {
  label: string;
  hint?: ReactNode;
  optional?: boolean;
  group?: boolean; // vários controles lado a lado (ex.: método + rota)
  className?: string;
  children: ReactNode;
}) {
  const head = (
    <span className="field-label">
      {label}
      {optional && <em>opcional</em>}
    </span>
  );
  const foot = hint ? <span className="field-hint">{hint}</span> : null;
  return group ? (
    <div className={`field ${className}`} role="group" aria-label={label}>
      {head}
      {children}
      {foot}
    </div>
  ) : (
    <label className={`field ${className}`}>
      {head}
      {children}
      {foot}
    </label>
  );
}

export function FormSection({ title, description, children }: { title?: string; description?: ReactNode; children: ReactNode }) {
  return (
    <fieldset className="form-section">
      {title && <legend>{title}</legend>}
      {description && <p className="form-section-desc">{description}</p>}
      {children}
    </fieldset>
  );
}

export function FormGrid({ children }: { children: ReactNode }) {
  return <div className="form-grid">{children}</div>;
}

export function FormActions({ children }: { children: ReactNode }) {
  return <div className="form-actions">{children}</div>;
}
