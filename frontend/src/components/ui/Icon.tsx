// Ícones de traço (24x24), todos no mesmo estilo. Decorativos: o rótulo textual fica sempre ao lado.
const PATHS: Record<string, string> = {
  dashboard: "M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z",
  projects: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z",
  scans: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6-6",
  findings: "M12 3 4 6v5c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10V6l-8-3Zm0 6v4m0 3h.01",
  routes: "M6 4a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm12 12a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM8 6h5a4 4 0 0 1 0 8h-2a4 4 0 0 0 0 8h5",
  policies: "M9 4h6a1 1 0 0 1 1 1v1H8V5a1 1 0 0 1 1-1Zm-3 2h12v14H6V6Zm3 5h6m-6 3h6m-6 3h4",
  integrations: "M9 7V3m6 4V3M7 7h10v4a5 5 0 0 1-10 0V7Zm5 9v5",
  users: "M16 11a3 3 0 1 0-6 0 3 3 0 0 0 6 0ZM6 20c0-3 3-5 6-5s6 2 6 5",
  audit: "M5 4h14v16H5V4Zm3 4h8m-8 4h8m-8 4h5",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7-3a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.7a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.5A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.4-1c.6.5 1.3.9 2 1.2L10 21h4l.5-2.7c.7-.3 1.4-.7 2-1.2l2.4 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2Z",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm9 16-4-4",
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "M6 6l12 12M18 6 6 18",
};

export default function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={PATHS[name] ?? PATHS.dashboard} />
    </svg>
  );
}
