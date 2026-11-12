import { describe, expect, it } from "vitest";
import { friendlyMessage } from "../api/client";

describe("friendlyMessage", () => {
  it("usa o texto do servidor quando ele existe", () => {
    expect(friendlyMessage(400, "A validade deve ficar entre 1 e 730 dias.")).toBe("A validade deve ficar entre 1 e 730 dias.");
  });
  it("explica o que fazer quando o servidor não manda texto", () => {
    expect(friendlyMessage(401, "")).toMatch(/sessão expirou/i);
    expect(friendlyMessage(403, "")).toMatch(/permissão/i);
    expect(friendlyMessage(409, "")).toMatch(/em andamento/i);
    expect(friendlyMessage(429, "")).toMatch(/aguarde/i);
    expect(friendlyMessage(503, "")).toMatch(/tente de novo/i);
  });
  it("não exibe HTML de páginas de erro de proxy", () => {
    expect(friendlyMessage(502, "<html><body>Bad Gateway</body></html>")).not.toContain("<html>");
  });
});
