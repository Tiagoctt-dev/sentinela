# CLI fina para rodar um scan localmente sem subir a API/containers.
# Uso: python -m app.cli <target> [--url URL] [--no-static] [--no-dynamic] [--no-ai]

import argparse
import asyncio
import json
import sys

from .domain.pipeline import run_scan
from .targets import TargetNotFound, load_target_config


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinela")
    p.add_argument("target", nargs="?", default="cfo-pessoal")
    p.add_argument("--url")
    p.add_argument("--no-static", dest="static", action="store_false", default=True)
    p.add_argument("--no-dynamic", dest="dynamic", action="store_false", default=True)
    p.add_argument("--no-ai", dest="ai", action="store_false", default=True)
    p.add_argument("--fail-on", choices=["policy", "fail", "none"], default="fail",
                   help="Quando devolver exit code 2 (pipeline de CI): 'policy' = política reprovada; 'fail' = qualquer FALHA; 'none' = nunca")
    return p.parse_args(argv)


async def _main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        target = load_target_config(args.target)
    except TargetNotFound as err:
        print(str(err), file=sys.stderr)
        return 1
    if args.url:
        target["baseUrl"] = args.url

    try:
        result = await run_scan(target, static=args.static, dynamic=args.dynamic, ai=args.ai)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 1

    print(f"Alvo: {target.get('name')}  score: {result['overall']}/100 ({result['verdict']['label']})")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.fail_on == "policy":
        return 0 if result["policy"]["passed"] else 2
    if args.fail_on == "none":
        return 0
    return 2 if result["totals"].get("FAIL", 0) > 0 else 0


def main():
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))


if __name__ == "__main__":
    main()
