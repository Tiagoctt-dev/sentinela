# Importação de spec OpenAPI/Swagger enviada pelo usuário (JSON ou YAML), para projetos cuja spec não é
# publicada no próprio serviço. Valida o formato e limita tamanho e complexidade antes de guardar.

import json
from typing import Any

import yaml

MAX_BYTES = 2_000_000
MAX_NODES = 300_000
MAX_PATHS = 2_000


def _count_nodes(obj: Any, limit: int) -> int:
    stack, n = [obj], 0
    while stack:
        cur = stack.pop()
        n += 1
        if n > limit:
            return n
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return n


def parse_spec(text: str) -> dict:
    """Devolve a spec como dict ou levanta ValueError com uma mensagem em português."""
    if not text or not text.strip():
        raise ValueError("O arquivo está vazio.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"A spec excede {MAX_BYTES // 1_000_000} MB.")
    try:
        spec = json.loads(text)
    except ValueError:
        try:
            spec = yaml.safe_load(text)  # safe_load: sem execução de objetos
        except yaml.YAMLError as err:
            raise ValueError("Não foi possível ler o arquivo como JSON nem como YAML.") from err
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict) or not spec["paths"]:
        raise ValueError("Não parece uma spec OpenAPI/Swagger: falta a seção 'paths'.")
    if not (spec.get("openapi") or spec.get("swagger")):
        raise ValueError("Não parece uma spec OpenAPI/Swagger: falta o campo 'openapi' (ou 'swagger').")
    if len(spec["paths"]) > MAX_PATHS:
        raise ValueError(f"A spec tem mais de {MAX_PATHS} caminhos.")
    if _count_nodes(spec, MAX_NODES) > MAX_NODES:
        raise ValueError("A spec é complexa demais (possível expansão de referências YAML).")
    return spec


def summarize(spec: dict) -> dict:
    ops = sum(1 for item in spec["paths"].values() if isinstance(item, dict) for m in item if m.lower() in ("get", "post", "put", "patch", "delete"))
    return {"title": (spec.get("info") or {}).get("title"), "version": (spec.get("info") or {}).get("version"), "paths": len(spec["paths"]), "operations": ops}
