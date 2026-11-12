import { useEffect, useState } from "react";

type Theme = "system" | "light" | "dark";
const KEY = "sentinela.theme";
const LABEL: Record<Theme, string> = { system: "Automático", light: "Claro", dark: "Escuro" };
const ORDER: Theme[] = ["system", "light", "dark"];

function read(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function apply(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

/** Aplica o tema salvo assim que o app carrega (antes da primeira pintura da barra lateral). */
export function initTheme() {
  apply(read());
}

/** Alterna Automático → Claro → Escuro. "Automático" segue o sistema operacional. */
export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(read);

  useEffect(() => {
    apply(theme);
    try {
      if (theme === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, theme);
    } catch {
      /* armazenamento bloqueado: o tema vale só nesta sessão */
    }
  }, [theme]);

  const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length];
  return (
    <button
      type="button"
      className="btn ghost sm theme-toggle"
      onClick={() => setTheme(next)}
      aria-label={`Tema: ${LABEL[theme]}. Mudar para ${LABEL[next]}`}
      title={`Tema: ${LABEL[theme]} (clique para ${LABEL[next].toLowerCase()})`}
    >
      <span aria-hidden="true">{theme === "dark" ? "☾" : theme === "light" ? "☀" : "◐"}</span> {LABEL[theme]}
    </button>
  );
}
