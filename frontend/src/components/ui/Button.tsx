import { ButtonHTMLAttributes } from "react";
import Spinner from "./Spinner";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "danger";
  size?: "md" | "sm";
  loading?: boolean;
  loadingLabel?: string;
}

export default function Button({
  variant = "primary",
  size = "md",
  loading = false,
  loadingLabel,
  disabled,
  className = "",
  children,
  ...rest
}: ButtonProps) {
  const classes = [
    "btn",
    variant === "ghost" ? "ghost" : "",
    variant === "danger" ? "danger" : "",
    size === "sm" ? "sm" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button className={classes} disabled={disabled || loading} {...rest}>
      {loading && <Spinner />}
      {loading ? loadingLabel || children : children}
    </button>
  );
}
