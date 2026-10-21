import { ReactNode } from "react";

export default function AccordionSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="accordion">
      <summary>{title}</summary>
      <div className="accordion-body">{children}</div>
    </details>
  );
}
