"""API contract tests for public Hancock endpoints."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

EXPECTED_ENDPOINTS = {
    "/health",
    "/metrics",
    "/v1/agents",
    "/v1/chat",
    "/v1/ask",
    "/v1/triage",
    "/v1/hunt",
    "/v1/respond",
    "/v1/code",
    "/v1/ciso",
    "/v1/sigma",
    "/v1/yara",
    "/v1/ioc",
    "/v1/geolocate",
    "/v1/predict-locations",
    "/v1/map-infrastructure",
    "/v1/webhook",
}

POST_INVALID_PAYLOADS = {
    "/v1/chat": {},
    "/v1/ask": {},
    "/v1/triage": {},
    "/v1/hunt": {},
    "/v1/respond": {},
    "/v1/code": {},
    "/v1/ciso": {},
    "/v1/sigma": {},
    "/v1/yara": {},
    "/v1/ioc": {},
    "/v1/geolocate": {},
    "/v1/predict-locations": {},
    "/v1/map-infrastructure": {},
    "/v1/webhook": {},
}


def _public_routes(flask_app) -> set[str]:
    return {
        rule.rule
        for rule in flask_app.url_map.iter_rules()
        if rule.rule.startswith("/v1/") or rule.rule in {"/health", "/metrics"}
    }


def _documented_paths() -> set[str]:
    openapi_text = Path("docs/openapi.yaml").read_text(encoding="utf-8")
    return set(re.findall(r"^\s{2}(/[^:]+):\s*$", openapi_text, flags=re.MULTILINE))


def _assert_error_schema(response) -> None:
    assert response.status_code in {400, 401}, (
        f"Expected 400/401 for invalid request, got {response.status_code}: {response.get_data(as_text=True)}"
    )
    payload = response.get_json()
    assert isinstance(payload, dict), "Error responses must be JSON objects"
    assert set(payload.keys()) == {"error"}, f"Unexpected error schema keys: {sorted(payload.keys())}"
    assert isinstance(payload["error"], str)
    assert payload["error"].strip()


def test_expected_routes_are_present(hancock_app):
    actual = _public_routes(hancock_app)
    missing = EXPECTED_ENDPOINTS - actual
    assert not missing, f"Expected endpoints missing from Flask routes: {sorted(missing)}"


@pytest.mark.parametrize("endpoint,payload", POST_INVALID_PAYLOADS.items())
def test_invalid_payloads_return_stable_error_schema(hancock_client, endpoint, payload):
    response = hancock_client.post(endpoint, json=payload)
    _assert_error_schema(response)


def test_health_strict_contract_snapshot(hancock_client):
    response = hancock_client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()

    required_keys = {"status", "agent", "model", "company", "modes", "endpoints"}
    assert required_keys.issubset(payload.keys())
    assert payload["status"] == "ok"
    assert isinstance(payload["modes"], list) and payload["modes"]
    assert isinstance(payload["endpoints"], list) and payload["endpoints"]

    endpoints = set(payload["endpoints"])
    for endpoint in EXPECTED_ENDPOINTS - {"/health"}:
        assert endpoint in endpoints, f"/health endpoints list missing: {endpoint}"


def test_docs_do_not_contain_obsolete_endpoints(hancock_app):
    documented = _documented_paths()
    implemented = _public_routes(hancock_app)

    undocumented_or_obsolete = documented - implemented
    assert not undocumented_or_obsolete, (
        "docs/openapi.yaml includes endpoints not implemented by app: "
        f"{sorted(undocumented_or_obsolete)}"
    )
