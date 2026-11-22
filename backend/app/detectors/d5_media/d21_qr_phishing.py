"""Detector 21 — QR Code Phishing (Domain 5: Multimedia & Image-Based Threats)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import tldextract

from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import (
    Artifact,
    ArtifactType,
    DetectionResult,
    Evidence,
    EvidenceSeverity,
    Verdict,
)

if TYPE_CHECKING:
    from app.core.context import AnalysisContext

_SUSPICIOUS_TLDS = frozenset({"xyz", "tk", "ml", "ga", "cf", "top", "gq", "pw", "cc", "click", "link"})
_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "rb.gy", "cutt.ly", "buff.ly", "v.gd", "shorturl.at", "tiny.cc", "t.ly",
})
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_TLD = tldextract.TLDExtract(cache_dir=None)


def _registered_domain(hostname: str) -> str:
    """Return the public-suffix-aware registered domain for a QR URL host."""
    return _TLD(hostname).registered_domain.lower()


@register_detector
class QRPhishingDetector(BaseDetector):
    """Detects QR-code phishing (quishing): decodes QR image, analyses embedded URL."""

    detector_id = "d21_qr_phishing"
    name = "QR Code Phishing (Quishing)"
    domain = "Multimedia & Image-Based Threats"
    domain_id = "d5"
    accepted_artifact_types = [ArtifactType.QR, ArtifactType.IMAGE]
    required_engines = ["media", "url"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        payloads = await ctx.get_media_qr_payloads()

        if not payloads:
            failure = ctx.get_failures().get("media:qr")
            description = (
                f"QR decoding was unavailable: {failure}"
                if failure
                else "No QR payload was decoded; this does not establish that the image is safe"
            )
            return self._result(
                artifact,
                0.0,
                Verdict.UNKNOWN,
                [Evidence(
                    source_engine="media",
                    severity=EvidenceSeverity.INFO,
                    description=description,
                    rule_id="qr_not_decoded",
                )],
                signals=["media.qr_decode"],
            )

        scores: list[float] = []
        evidence: list[Evidence] = []
        decoded_urls = 0
        decode_failure = ctx.get_failures().get("media:qr")

        for payload in payloads[:5]:
            value = payload.strip()
            if not _URL_RE.match(value):
                continue

            parsed = urlparse(value)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            registered_domain = _registered_domain(hostname)
            tld = registered_domain.rsplit(".", 1)[-1] if registered_domain else ""
            decoded_urls += 1
            url_risks: list[float] = []

            evidence.append(Evidence(
                source_engine="media",
                severity=EvidenceSeverity.INFO,
                description=f"QR code contains a URL destination: '{value[:80]}'",
                matched_text=value[:80],
                rule_id="qr_contains_url",
            ))

            if tld in _SUSPICIOUS_TLDS and registered_domain:
                url_risks.append(0.35)
                evidence.append(Evidence(
                    source_engine="media",
                    severity=EvidenceSeverity.HIGH,
                    description=f"QR URL uses the higher-risk .{tld} suffix",
                    rule_id="qr_suspicious_tld",
                ))

            if registered_domain in _SHORTENERS:
                url_risks.append(0.20)
                evidence.append(Evidence(
                    source_engine="media",
                    severity=EvidenceSeverity.MEDIUM,
                    description="QR URL uses a link shortener; its final destination was not resolved",
                    rule_id="qr_shortener",
                ))

            intel = await ctx.get_intel_signals(value)
            if not intel.hits and hostname:
                intel = await ctx.get_intel_signals(hostname)
            if intel.hits:
                url_risks.append(1.0)
                evidence.append(Evidence(
                    source_engine="intel",
                    severity=EvidenceSeverity.CRITICAL,
                    description="QR destination matches a local known-threat indicator",
                    matched_text=value[:100],
                    rule_id="qr_local_intel_hit",
                    metadata={"hits": intel.hits},
                ))

            url_sig = await ctx.get_url_signals(value)
            structural_score = float(url_sig.risk_score or 0.0)
            if structural_score >= 0.55:
                url_risks.append(min(0.7, structural_score))
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.HIGH,
                    description=f"QR destination has elevated structural URL risk ({structural_score:.2f})",
                    rule_id="qr_url_structural_risk",
                ))
            elif structural_score >= 0.35:
                url_risks.append(0.15)
                evidence.append(Evidence(
                    source_engine="url",
                    severity=EvidenceSeverity.LOW,
                    description=f"QR destination has some URL risk indicators ({structural_score:.2f})",
                    rule_id="qr_url_structural_signals",
                ))

            scores.append(max(url_risks, default=0.0))

        if decoded_urls == 0:
            verdict = Verdict.UNKNOWN
            score = 0.0
            evidence.append(Evidence(
                source_engine="media",
                severity=EvidenceSeverity.INFO,
                description="Decoded QR payload contains no URL; other payload types were not assessed as threat content",
                rule_id="qr_non_url_payload",
            ))
        else:
            # Score the most concerning URL rather than adding URL-presence points.
            score = max(scores, default=0.0)
            verdict = (Verdict.MALICIOUS if score >= 0.70
                       else Verdict.LIKELY_MALICIOUS if score >= 0.45
                       else Verdict.SUSPICIOUS if score >= 0.20
                       else Verdict.SAFE)
            if decode_failure:
                verdict = Verdict.UNKNOWN
                evidence.append(Evidence(
                    source_engine="media",
                    severity=EvidenceSeverity.INFO,
                    description=f"Additional QR decoding attempt failed: {decode_failure}",
                    rule_id="qr_partial_decode_failure",
                ))

        return self._result(artifact, score, verdict, evidence, signals=["media.qr_decode", "url.risk_score"])
