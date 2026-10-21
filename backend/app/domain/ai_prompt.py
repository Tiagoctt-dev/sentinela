# Prompt e parsing compartilhados entre provedores de IA — o mesmo prompt vai
# pros dois (Gemini e Groq), pra comparação ser justa (mesma pergunta, duas
# "opiniões" independentes).

import json
import re

from .models import SEVERITY, Finding
from .owasp_api_top10 import owasp_context_text


def build_prompt(target: dict, result: dict, actionable: list[Finding]) -> str:
    linhas = "\n".join(
        f"- id: {f.id} | owasp: {f.owasp or '-'} | severidade: {SEVERITY[f.severity].label} | "
        f"status: {f.status} | título: {f.title} | observado: {f.detail}"
        for f in actionable
    )
    return f"""Você é um especialista em segurança de APIs de grau bancário (OAuth 2.0, OpenID Connect, FAPI, mTLS, DPoP, PKCE, OWASP API Security Top 10).

Use como base a taxonomia oficial do OWASP API Security Top 10 (2023):
{owasp_context_text()}

Analisei a API "{target.get('name')}" e obtive um score de conformidade de {result['overall']}/100 ({result['verdict']['label']}).

Achados que precisam de atenção (falhas e avisos) — cada um traz a categoria OWASP correspondente:
{linhas}

Gere recomendações técnicas, específicas e acionáveis, em português do Brasil.
Responda SOMENTE com um JSON válido, sem texto fora do JSON, neste formato:
{{
  "resumoExecutivo": "2 a 4 frases sobre a postura geral de segurança e o que priorizar",
  "recomendacoes": [
    {{
      "id": "<use exatamente um dos ids acima>",
      "prioridade": "alta | media | baixa",
      "risco": "por que isso é perigoso, de forma concreta (1-2 frases)",
      "acao": "o que fazer para corrigir, com passos concretos (1-3 frases)"
    }}
  ]
}}
Inclua uma entrada em "recomendacoes" para cada id listado. Não invente ids."""


def parse_json(text: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?", "", text.strip())
    cleaned = re.sub(r"```$", "", cleaned).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("resposta sem JSON")
    return json.loads(cleaned[start:end + 1])
