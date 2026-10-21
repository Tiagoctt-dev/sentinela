import { HTMLAttributes } from "react";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  tight?: boolean;
  interactive?: boolean;
}

export default function Card({ tight, interactive, className = "", children, ...rest }: CardProps) {
  const classes = ["card", tight ? "tight" : "", interactive ? "interactive" : "", className].filter(Boolean).join(" ");
  return (
    <div className={classes} {...rest}>
      {children}
    </div>
  );
}
