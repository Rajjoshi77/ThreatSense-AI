import pytest

from app.core.context import AnalysisContext
from app.detectors.d5_media.d21_qr_phishing import QRPhishingDetector
from app.engines.intel.engine import IntelEngine
from app.engines.media.engine import MediaEngine
from app.engines.url.engine import URLEngine
from app.schemas.schemas import Artifact, ArtifactType, IntelSignals, Verdict


@pytest.mark.asyncio
async def test_media_engine_no_bytes():
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.QR)
    payloads = await engine.decode_qr(artifact)
    assert payloads == []

@pytest.mark.asyncio
async def test_media_engine_ocr_no_bytes():
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.IMAGE)
    text = await engine.extract_text_ocr(artifact)
    assert text == ""


class QRPayloadEngine:
    def __init__(
        self,
        payloads: list[str] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.payloads = payloads or []
        self.failure = failure

    async def decode_qr(self, _artifact: Artifact) -> list[str]:
        if self.failure:
            raise self.failure
        return self.payloads


@pytest.mark.asyncio
async def test_qr_detector_does_not_flag_benign_url_presence() -> None:
    artifact = Artifact(type=ArtifactType.QR)
    ctx = AnalysisContext(
        artifact=artifact,
        media_engine=QRPayloadEngine(["https://www.iana.org/help/example-domains"]),
        url_engine=URLEngine(),
        intel_provider=IntelEngine(),
    )

    result = await QRPhishingDetector().detect(artifact, ctx)

    assert result.score < 0.20
    assert result.verdict == Verdict.SAFE


@pytest.mark.asyncio
async def test_qr_detector_flags_combined_suspicious_url_signals() -> None:
    url = "https://account-check.example.test/verify?sample=1"
    artifact = Artifact(type=ArtifactType.QR)
    ctx = AnalysisContext(
        artifact=artifact,
        media_engine=QRPayloadEngine([url]),
        url_engine=URLEngine(),
        intel_provider=IntelEngine(),
    )

    result = await QRPhishingDetector().detect(artifact, ctx)

    assert result.verdict == Verdict.SUSPICIOUS
    assert result.score >= 0.35
    assert any(item.rule_id == "qr_combined_url_signals" for item in result.evidence)


@pytest.mark.asyncio
async def test_qr_detector_analyzes_readable_text_payload() -> None:
    from app.engines.nlp.backends.rules import RulesBackend

    payload = "Verify your password and one-time code now to avoid account suspension."
    artifact = Artifact(type=ArtifactType.QR)
    ctx = AnalysisContext(
        artifact=artifact,
        media_engine=QRPayloadEngine([payload]),
        nlp_engine=type("NLPStub", (), {"analyze": RulesBackend().analyze})(),
    )

    result = await QRPhishingDetector().detect(artifact, ctx)

    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS}
    assert any(item.rule_id == "qr_text_credential_request" for item in result.evidence)


@pytest.mark.asyncio
async def test_qr_detector_checks_local_threat_intelligence() -> None:
    class TestIntelProvider:
        async def lookup(self, indicator: str) -> IntelSignals:
            hits = [{"source": "test_fixture", "indicator": indicator}]
            return IntelSignals(
                hits=hits if "phishing-example-test.xyz" in indicator else [],
                providers_queried=["test_fixture"],
                offline_mode=True,
            )

    artifact = Artifact(type=ArtifactType.QR)
    ctx = AnalysisContext(
        artifact=artifact,
        media_engine=QRPayloadEngine(["https://phishing-example-test.xyz/login"]),
        url_engine=URLEngine(),
        intel_provider=TestIntelProvider(),
    )

    result = await QRPhishingDetector().detect(artifact, ctx)

    assert result.verdict == Verdict.MALICIOUS
    assert any(e.rule_id == "qr_local_intel_hit" for e in result.evidence)


@pytest.mark.asyncio
async def test_qr_detector_returns_unknown_for_undecoded_image() -> None:
    artifact = Artifact(type=ArtifactType.QR)
    ctx = AnalysisContext(artifact=artifact, media_engine=QRPayloadEngine())

    result = await QRPhishingDetector().detect(artifact, ctx)

    assert result.verdict == Verdict.UNKNOWN
    assert result.evidence[0].rule_id == "qr_not_decoded"


@pytest.mark.asyncio
async def test_qr_decode_failure_is_reported_as_unknown() -> None:
    artifact = Artifact(type=ArtifactType.QR, raw_bytes=b"not-really-an-image")
    media_engine = QRPayloadEngine(failure=RuntimeError("decoder unavailable"))
    ctx = AnalysisContext(artifact=artifact, media_engine=media_engine)

    payloads = await ctx.get_media_qr_payloads()
    result = await QRPhishingDetector().detect(artifact, ctx)

    assert payloads == []
    assert result.verdict == Verdict.UNKNOWN
    assert "QR decoding was unavailable" in result.evidence[0].description
    assert "decoder unavailable" in result.evidence[0].description
    assert ctx.get_engine_call_count("media:qr") == 1


@pytest.mark.asyncio
async def test_image_without_ocr_is_not_reported_safe() -> None:
    from app.detectors.d5_media.d22_screenshot_scam import ScreenshotScamDetector

    artifact = Artifact(type=ArtifactType.IMAGE, raw_bytes=b"image bytes")
    ctx = AnalysisContext(artifact=artifact)

    result = await ScreenshotScamDetector().detect(artifact, ctx)

    assert result.verdict == Verdict.UNKNOWN
    assert result.evidence[0].rule_id == "media_ocr_unavailable"
# A 1x1 white pixel PNG
WHITE_PIXEL = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
    "0000000c4944415408d763f8cfc000000301010018dd8d6a0000000049454e44ae"
    "426082"
)

@pytest.mark.asyncio
async def test_media_engine_empty_image(monkeypatch):
    from app.engines.media import engine as media_module

    monkeypatch.setattr(media_module, "_decode_qr_sync", lambda _image: [])
    monkeypatch.setattr(media_module, "_ocr_sync", lambda _image: "")
    engine = MediaEngine()
    artifact = Artifact(type=ArtifactType.QR, raw_bytes=WHITE_PIXEL)
    assert await engine.decode_qr(artifact) == []
    assert await engine.extract_text_ocr(artifact) == ""
