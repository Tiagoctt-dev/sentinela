export default function Spinner({ size = "sm" }: { size?: "sm" | "lg" }) {
  return <span className={`spinner ${size === "lg" ? "lg" : ""}`} aria-hidden="true" />;
}
