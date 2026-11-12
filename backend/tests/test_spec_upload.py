import json

import pytest
from fastapi.testclient import TestClient

from app.domain.spec_upload import parse_spec, summarize
from app.main import app

SPEC = {"openapi": "3.0.0", "info": {"title": "Demo", "version": "1"}, "paths": {"/a": {"get": {}}, "/b/{id}": {"get": {}, "delete": {}}}}


def test_parse_json_and_yaml():
    assert parse_spec(json.dumps(SPEC))["paths"]
    yml = "openapi: 3.0.0\ninfo: {title: Y, version: '1'}\npaths:\n  /x:\n    get: {}\n"
    assert summarize(parse_spec(yml)) == {"title": "Y", "version": "1", "paths": 1, "operations": 1}


@pytest.mark.parametrize("text", ["", "   ", "{not json", '{"paths": {}}', '{"openapi": "3.0.0"}', "[1,2]"])
def test_parse_rejects_invalid(text):
    with pytest.raises(ValueError):
        parse_spec(text)


def test_parse_rejects_oversize():
    with pytest.raises(ValueError):
        parse_spec("x" * 2_100_000)


def test_upload_endpoint_roundtrip():
    with TestClient(app) as c:
        r = c.post("/api/auth/bootstrap", json={"name": "A", "email": "a@t.io", "password": "SenhaForte#2026"})
        h = {"Authorization": "Bearer " + r.json()["token"]}
        t = c.post("/api/targets", headers=h, json={"name": "spec-up", "baseUrl": "http://localhost:9"})
        assert t.status_code == 201, t.text
        tid = t.json()["id"]
        r = c.put(f"/api/targets/{tid}/openapi-spec", headers=h, content=json.dumps(SPEC))
        assert r.status_code == 200, r.text
        cfg = r.json()["config"]
        assert "openapiSpec" not in cfg and cfg["openapiSpecSummary"]["operations"] == 3
        assert c.put(f"/api/targets/{tid}/openapi-spec", headers=h, content="nada").status_code == 400
        assert c.delete(f"/api/targets/{tid}/openapi-spec", headers=h).status_code == 204
        assert "openapiSpecSummary" not in c.get(f"/api/targets/{tid}", headers=h).json()["config"]
