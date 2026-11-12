# Métricas operacionais no formato de texto do Prometheus, sem dependência externa.
# Contadores ficam em memória (reiniciam com o processo); os indicadores de estado vêm do banco a cada coleta.
#
# Acesso: GET /api/metrics com `Authorization: Bearer <SENTINELA_METRICS_TOKEN>` (para o coletor) ou sessão de administrador.

import threading
from collections import defaultdict

from sqlalchemy import func
from sqlalchemy.orm import Session

from .db.models import FindingModel, ScanRun, TargetModel, UserModel

_lock = threading.Lock()
_scans: dict[tuple[str, str], int] = defaultdict(int)   # (origem, resultado) -> total
_duration_sum = 0.0
_duration_count = 0
_requests: dict[tuple[str, int], int] = defaultdict(int)  # (classe de método, status) -> total


def record_scan(origin: str, result: str, seconds: float) -> None:
    global _duration_sum, _duration_count
    with _lock:
        _scans[(origin or "manual", result)] += 1
        _duration_sum += seconds
        _duration_count += 1


def record_request(method: str, status: int) -> None:
    with _lock:
        _requests[("write" if method in ("POST", "PUT", "PATCH", "DELETE") else "read", status)] += 1


def render(db: Session) -> str:
    out: list[str] = []

    def metric(name: str, kind: str, help_text: str, samples: list[tuple[str, float]]) -> None:
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.extend(f"{name}{labels} {value}" for labels, value in samples)

    with _lock:
        scans = dict(_scans)
        dsum, dcount = _duration_sum, _duration_count
        reqs = dict(_requests)

    metric("sentinela_scans_total", "counter", "Scans executados desde o início do processo.",
           [(f'{{origin="{o}",result="{r}"}}', n) for (o, r), n in sorted(scans.items())] or [("", 0)])
    metric("sentinela_scan_duration_seconds_sum", "counter", "Soma da duração dos scans.", [("", round(dsum, 3))])
    metric("sentinela_scan_duration_seconds_count", "counter", "Quantidade de scans medidos.", [("", dcount)])
    metric("sentinela_http_requests_total", "counter", "Requisições à API por tipo e status.",
           [(f'{{kind="{k}",status="{s}"}}', n) for (k, s), n in sorted(reqs.items())] or [("", 0)])

    metric("sentinela_projects", "gauge", "Projetos cadastrados.", [("", db.query(TargetModel).count())])
    metric("sentinela_users_active", "gauge", "Usuários ativos.", [("", db.query(UserModel).filter(UserModel.active.is_(True)).count())])
    metric("sentinela_scans_stored", "gauge", "Scans guardados no banco.", [("", db.query(ScanRun).count())])
    states = db.query(FindingModel.state, func.count(FindingModel.id)).group_by(FindingModel.state).all()
    metric("sentinela_findings_stored", "gauge", "Verificações guardadas, por estado.",
           [(f'{{state="{s or "desconhecido"}"}}', n) for s, n in sorted(states, key=lambda x: str(x[0]))] or [("", 0)])
    return "\n".join(out) + "\n"
