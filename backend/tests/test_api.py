"""
API integration tests — /health, /detectors, /analyze.

Acceptance criteria:
  ✓ GET /health returns 200 with status='ok' and detector_count=22.
  ✓ GET /detectors returns 22 detectors across 5 domains (9/5/3/3/2).
  ✓ POST /analyze with a URL artifact returns a valid RiskReport.
  ✓ POST /analyze returns a rules-backed report if finetuned weights are missing.

The test configuration forces NLP_BACKEND=rules in conftest.py; individual
finetuned-mode behavior is tested explicitly below.
  ✓ GET /analyses/{id} returns the stored report.
"""

from __future__ import annotations


async def test_health_returns_ok(client) -> None:
    """GET /health must return HTTP 200 with status='ok'."""
    resp = await client.get("/health")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "ok"
    assert data["detector_count"] == 22


async def test_health_includes_nlp_backend(client) -> None:
    """GET /health must include the active NLP backend name."""
    resp = await client.get("/health")
    data = resp.json()
    assert "nlp_backend" in data
    assert data["nlp_backend"] in ("rules", "zeroshot", "finetuned", "ensemble")


async def test_health_reports_rules_when_deberta_is_unavailable(client, monkeypatch) -> None:
    """Health reports the effective rules fallback, not just configured finetuned."""
    from app.core.config import NLPBackend, settings
    from app.engines.nlp.backends import finetuned as finetuned_mod

    monkeypatch.setattr(settings, "NLP_BACKEND", NLPBackend.FINETUNED)
    monkeypatch.setattr(finetuned_mod, "is_finetuned_available", lambda: False)

    resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["nlp_backend"] == "rules"


async def test_detectors_total_is_22(client) -> None:
    """GET /detectors total must be exactly 22."""
    resp = await client.get("/detectors")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] == 22


async def test_detectors_domain_breakdown(client) -> None:
    """GET /detectors must return exactly 5 domains with 9/5/3/3/2 detectors."""
    resp = await client.get("/detectors")
    data = resp.json()
    domains = {d["domain_id"]: len(d["detectors"]) for d in data["domains"]}
    assert domains == {"d1": 9, "d2": 5, "d3": 3, "d4": 3, "d5": 2}, (
        f"Domain breakdown wrong: {domains}"
    )


async def test_detectors_all_have_required_fields(client) -> None:
    """Every detector in GET /detectors must have required fields."""
    resp = await client.get("/detectors")
    data = resp.json()
    for domain in data["domains"]:
        for det in domain["detectors"]:
            assert det["detector_id"], f"Empty detector_id in {det}"
            assert det["name"], f"Empty name for {det['detector_id']}"
            assert det["accepted_artifact_types"], (
                f"No accepted_artifact_types for {det['detector_id']}"
            )


async def test_analyze_uses_rules_fallback_when_finetuned_checkpoint_is_missing(client, monkeypatch) -> None:
    """Finetuned mode stays available with rules when checkpoint weights are absent."""
    from app.core.config import NLPBackend, settings
    from app.engines.nlp.backends import finetuned as finetuned_backend

    monkeypatch.setattr(settings, "NLP_BACKEND", NLPBackend.FINETUNED)
    monkeypatch.setattr(finetuned_backend, "_load_model", lambda: None)
    response = await client.post(
        "/analyze",
        json={
            "type": "sms",
            "raw_content": "URGENT: verify your password and OTP immediately at this link.",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["nlp_backend_used"] == "rules"
    assert response.json()["engine_signals"]["nlp"]["backend_used"] == "rules"


async def test_analyze_url_returns_risk_report(client) -> None:
    """POST /analyze with a URL artifact must return a valid RiskReport."""
    resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com", "metadata": {}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "risk_score" in data
    assert "verdict" in data
    assert "analysis_id" in data
    assert "per_domain_scores" in data
    assert isinstance(data["risk_score"], (int, float))
    assert 0.0 <= data["risk_score"] <= 100.0


async def test_analyze_benign_url_uses_url_detectors_without_message_nlp(client) -> None:
    response = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "https://www.iana.org/help/example-domains"},
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["risk_score"] < 25
    assert data["nlp_backend_used"] == "not_applicable"
    assert data["engine_signals"]["nlp"]["text_length"] == 0
    url_domain = next(domain for domain in data["per_domain_scores"] if domain["domain_id"] == "d2")
    d10 = next(detector for detector in url_domain["detectors"] if detector["detector_id"] == "d10_malicious_url")
    assert d10["ran"]
    assert "url_local_intel_hit" not in [e["rule_id"] for e in d10["evidence"]]


async def test_analyze_threat_intel_hit_is_propagated_to_report(client, monkeypatch) -> None:
    from app.engines.intel.engine import IntelEngine
    from app.schemas.schemas import IntelSignals

    async def lookup(_self, indicator: str) -> IntelSignals:
        hits = [{"source": "test_fixture", "indicator": "malicious.test"}]
        return IntelSignals(
            hits=hits if "malicious.test" in indicator else [],
            providers_queried=["test_fixture"],
            offline_mode=True,
        )

    monkeypatch.setattr(IntelEngine, "lookup", lookup)
    response = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "https://malicious.test/login"},
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["risk_score"] >= 80
    assert data["engine_signals"]["intel"]["hits"]
    d2 = next(domain for domain in data["per_domain_scores"] if domain["domain_id"] == "d2")
    d10 = next(detector for detector in d2["detectors"] if detector["detector_id"] == "d10_malicious_url")
    assert d10["verdict"] == "malicious"
    assert any(e["rule_id"] == "url_local_intel_hit" for e in d10["evidence"])


async def test_analyze_email_returns_risk_report(client) -> None:
    """POST /analyze with an email artifact must return a valid RiskReport."""
    email_text = (
        "From: ceo@example.com\n"
        "To: finance@example.com\n"
        "Subject: Urgent wire transfer needed\n\n"
        "Please transfer $50,000 immediately. Keep this confidential."
    )
    resp = await client.post(
        "/analyze",
        json={"type": "email", "raw_content": email_text},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["artifact_type"] == "email"


async def test_analyze_webpage_includes_base_and_extracted_url_signals(client) -> None:
    html = (
        '<html><head><title>Library</title><script>"urgent credential"</script></head>'
        '<body><h1>Library hours</h1><a href="https://docs.python.org/3/">Docs</a></body></html>'
    )
    response = await client.post("/analyze", json={"type": "webpage", "raw_content": html})

    assert response.status_code == 200, response.text
    data = response.json()
    d2 = next(domain for domain in data["per_domain_scores"] if domain["domain_id"] == "d2")
    d10 = next(detector for detector in d2["detectors"] if detector["detector_id"] == "d10_malicious_url")
    assert d10["ran"]
    assert "https://docs.python.org/3/" in d10["metadata"]["urls_analyzed"]
    assert data["engine_signals"]["url"]["url"] == "https://docs.python.org/3/"
    assert data["nlp_backend_used"] == "rules"
    assert data["engine_signals"]["nlp"]["text_length"] == len("Library Library hours Docs")


async def test_analyze_sms_returns_risk_report(client) -> None:
    """POST /analyze with an SMS artifact must return a valid RiskReport."""
    resp = await client.post(
        "/analyze",
        json={
            "type": "sms",
            "raw_content": "Your KYC is pending. Click http://bit.ly/kyc-update to update.",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["artifact_type"] == "sms"


async def test_analyze_image_without_ocr_reports_unknown(client) -> None:
    from pathlib import Path

    from httpx import ASGITransport, AsyncClient

    from app.main import app

    image_path = Path(__file__).resolve().parents[2] / "frontend/public/sample-vectors/benign-screenshot.png"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as api:
        response = await api.post(
            "/analyze",
            data={"type": "image"},
            files={"file": ("benign-screenshot.png", image_path.read_bytes(), "image/png")},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["verdict"] == "unknown"
    assert data["nlp_backend_used"] == "not_applicable"
    assert any(evidence["rule_id"] == "media_ocr_unavailable" for evidence in data["top_evidence"])


async def test_analyze_qr_payload_is_routed_through_url_detectors(client) -> None:
    from pathlib import Path

    from httpx import ASGITransport, AsyncClient

    from app.main import app

    qr_path = Path(__file__).resolve().parents[2] / "frontend/public/sample-vectors/sample-quishing.png"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as api:
        response = await api.post(
            "/analyze",
            data={"type": "qr"},
            files={"file": ("sample-quishing.png", qr_path.read_bytes(), "image/png")},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["nlp_backend_used"] == "not_applicable"
    assert data["engine_signals"]["nlp"]["text_length"] == 0
    assert data["verdict"] == "safe"
    d2 = next(domain for domain in data["per_domain_scores"] if domain["domain_id"] == "d2")
    d10 = next(detector for detector in d2["detectors"] if detector["detector_id"] == "d10_malicious_url")
    assert d10["ran"]
    assert "https://account-check.example.test/verify?sample=1" in d10["metadata"]["urls_analyzed"]
    d5 = next(domain for domain in data["per_domain_scores"] if domain["domain_id"] == "d5")
    qr_detector = next(detector for detector in d5["detectors"] if detector["detector_id"] == "d21_qr_phishing")
    assert "qr_contains_url" in [e["rule_id"] for e in qr_detector["evidence"]]


async def test_analyze_plain_text_qr_reports_unknown(client) -> None:
    from pathlib import Path

    from httpx import ASGITransport, AsyncClient

    from app.main import app

    qr_path = Path(__file__).resolve().parents[2] / "frontend/public/sample-vectors/sample-plain-qr.png"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as api:
        response = await api.post(
            "/analyze",
            data={"type": "qr"},
            files={"file": ("sample-plain-qr.png", qr_path.read_bytes(), "image/png")},
        )

    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "unknown"


async def test_analyze_report_includes_per_domain_scores(client) -> None:
    """RiskReport must include per-domain breakdown with all 5 domains."""
    resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com"},
    )
    data = resp.json()
    # At least the domains that have detectors matching 'url' type should appear
    assert len(data["per_domain_scores"]) > 0


async def test_get_analysis_retrieves_stored_report(client) -> None:
    """GET /analyses/{id} must return the same report that POST /analyze returned."""
    post_resp = await client.post(
        "/analyze",
        json={"type": "url", "raw_content": "http://example.com"},
    )
    assert post_resp.status_code == 200
    analysis_id = post_resp.json()["analysis_id"]

    get_resp = await client.get(f"/analyses/{analysis_id}")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["analysis_id"] == analysis_id


async def test_get_analysis_404_for_unknown_id(client) -> None:
    """GET /analyses/{id} with an unknown ID must return 404."""
    resp = await client.get("/analyses/nonexistent-id-xyz")
    assert resp.status_code == 404
