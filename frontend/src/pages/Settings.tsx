import { useState } from "react";
import { AiTestResult, api } from "../api/client";
import Button from "../components/ui/Button";
import { useToast } from "../components/ui/ToastContext";

export default function SettingsPage() {
  const toast = useToast();
  const [results, setResults] = useState<AiTestResult[] | null>(null);
  const [testing, setTesting] = useState(false);

  async function testAi() {
    setTesting(true);
    try {
      setResults(await api.testAi());
    } catch (e) {
      toast.error(e);
    } finally {
      setTesting(false);
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Configurações</h1>
          <div className="eyebrow">Chaves e variáveis ficam no arquivo backend/.env — nunca no navegador.</div>
        </div>
      </div>

      <div className="integration-card">
        <div className="integration-card-head">
          <div>
            <h3>Camada de IA (Gemini e Groq)</h3>
            <p>
              A IA escreve as recomendações de correção de cada achado. Se ela falhar, o scan continua normalmente e usa
              as recomendações estáticas.
            </p>
          </div>
          <Button onClick={testAi} loading={testing} loadingLabel="Testando…">
            Testar conexão com a IA
          </Button>
        </div>

        {results && (
          <div className="ai-test-list">
            {results.map((r) => (
              <div key={r.provider} className="ai-test-row">
                <span className={`pill ${r.ok ? "pill-ok" : r.configured ? "pill-fail" : "pill-na"}`}>
                  {r.ok ? "funcionando" : r.configured ? "com erro" : "não configurado"}
                </span>
                <div>
                  <b>{r.provider}</b>
                  {r.keyHint && <span className="muted small mono"> · chave {r.keyHint}</span>}
                  <div className="muted small">{r.message}</div>
                  {!r.ok && r.transient && (
                    <div className="small" style={{ color: "var(--high)", marginTop: 4 }}>
                      Erro temporário do provedor (sobrecarga/limite) — a chave está correta. Tente de novo em instantes;
                      o Sentinela já repete e troca de modelo automaticamente.
                    </div>
                  )}
                  {!r.ok && r.configured && !r.transient && (
                    <div className="small" style={{ color: "var(--crit)", marginTop: 4 }}>
                      Verifique a chave em backend/.env e reinicie o backend.
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <details className="accordion">
          <summary>Como configurar</summary>
          <div className="accordion-body">
            <p>
              Crie <code>backend/.env</code> (modelo em <code>.env.example</code>) com <code>GEMINI_API_KEY</code> e/ou{" "}
              <code>GROQ_API_KEY</code>. Depois de alterar, <b>reinicie o backend</b> — o arquivo só é lido na inicialização.
            </p>
            <p>
              Gemini: gere a chave em aistudio.google.com/apikey. Groq: console.groq.com/keys. O formato da chave não
              importa — use o botão acima pra confirmar que ela funciona.
            </p>
            <p>
              Erros “503 / sobrecarga” vêm do Google, não da sua chave: trocar de conta não resolve. O Sentinela tenta de
              novo e cai para outros modelos sozinho.
            </p>
          </div>
        </details>
      </div>
    </div>
  );
}
