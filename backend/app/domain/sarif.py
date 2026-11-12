# Exporta um scan no formato SARIF 2.1.0 (padrão aceito por GitHub Code Scanning, Azure DevOps, SonarQube e
# outras ferramentas de pipeline). Entram só vulnerabilidades confirmadas e prováveis; o que não foi
# executado ou foi aprovado não vira "resultado".

from typing import Any

from .knowledge import knowledge_for

LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "1.0"}


def to_sarif(scan: dict[str, Any], app_url: str = "") -> dict[str, Any]:
    findings = [f for f in scan["findings"] if f["state"] in ("vulnerable", "likely")]
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        k = knowledge_for(f["id"]) or {}
        meta = f.get("meta") or {}
        if f["id"] not in rules:
            rules[f["id"]] = {
                "id": f["id"], "name": f["id"].replace("-", ""),
                "shortDescription": {"text": meta.get("headline") or f["title"]},
                "fullDescription": {"text": k.get("technical") or f["title"]},
                "help": {"text": f.get("recommendation") or "Ver a recomendação no Sentinela."},
                "properties": {
                    "tags": ["security", f.get("owasp") or "", f["category"]],
                    "security-severity": SECURITY_SEVERITY.get(f["severity"], "1.0"),
                },
            }
        asset = f.get("asset") or {}
        uri = asset.get("url") or (f"{asset.get('method', 'GET')} {asset['path']}" if asset.get("path") else scan["targetName"])
        results.append({
            "ruleId": f["id"],
            "level": LEVEL.get(f["severity"], "note"),
            "kind": "fail",
            "message": {"text": f"{meta.get('headline') or f['title']} — {f.get('detail') or ''}".strip(" —")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocations": [{"name": uri, "kind": "member"}],
            }],
            "partialFingerprints": {"sentinelaFinding": f"{scan['targetId']}:{f['id']}:{asset.get('method', '')}:{asset.get('path', '')}"},
            "properties": {
                "state": f["state"], "confidence": f["confidence"], "severity": f["severity"],
                "owasp": f.get("owasp"), "evidence": (f.get("evidence") or "")[:2000],
                "resolution": f.get("resolution"),
            },
            **({"suppressions": [{"kind": "external", "status": "accepted", "justification": f.get("resolutionNote") or ""}]}
               if f.get("resolution") == "risk_accepted" else {}),
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Sentinela", "informationUri": app_url or "https://localhost", "rules": list(rules.values())}},
            "automationDetails": {"id": f"sentinela/{scan['id']}"},
            "invocations": [{"executionSuccessful": True, "endTimeUtc": scan["createdAt"]}],
            "properties": {
                "target": scan["targetName"], "score": scan["overall"], "verdict": scan["verdict"],
                "coveragePct": (scan.get("scope") or {}).get("coveragePct"), "mode": (scan.get("scope") or {}).get("mode"),
            },
            "results": results,
        }],
    }
