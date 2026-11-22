"""
THREAT-SENSE AI — AnalysisContext.

The AnalysisContext is the shared state for one analysis run.  It:

1.  Holds the Artifact being analysed.
2.  Holds references to all engine instances.
3.  Lazily computes and caches each engine's output so that even when 9
    detectors in Domain 1 all call ``get_nlp_signals()``, the NLP backend
    runs EXACTLY ONCE per artifact.
4.  Tracks per-engine invocation counts (used by the unit tests to prove
    the caching guarantee).
5.  Records which engines failed so the aggregator can lower confidence and
    report skipped components.

Thread/async safety
-------------------
Each ``_get_or_compute()`` call uses a per-key ``asyncio.Lock`` (double-
checked locking pattern) to prevent concurrent coroutines from computing
the same engine result twice on the first call.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict
from collections.abc import Callable, Coroutine
from typing import Any

from app.schemas.schemas import (
    Artifact,
    EmailSignals,
    EngineSignals,
    IntelSignals,
    NLPSignals,
    URLSignals,
    WebSignals,
)

logger = logging.getLogger(__name__)


class AnalysisContext:
    """Per-artifact shared engine cache.

    Args:
        artifact:       The artifact being analysed.
        nlp_engine:     Optional NLPEngine instance.
        url_engine:     Optional URLEngine instance.
        web_engine:     Optional WebEngine instance.
        email_engine:   Optional EmailEngine instance.
        media_engine:   Optional MediaEngine instance.
        intel_provider: Optional IntelProvider instance.
    """

    def __init__(
        self,
        artifact: Artifact,
        nlp_engine: Any | None = None,
        url_engine: Any | None = None,
        web_engine: Any | None = None,
        email_engine: Any | None = None,
        media_engine: Any | None = None,
        intel_provider: Any | None = None,
    ) -> None:
        self._artifact = artifact
        self._nlp_engine = nlp_engine
        self._url_engine = url_engine
        self._web_engine = web_engine
        self._email_engine = email_engine
        self._media_engine = media_engine
        self._intel_provider = intel_provider

        # Cached results: engine_key → signal object
        self._cache: dict[str, Any] = {}
        # Invocation counter: engine_key → number of times the backend was called
        # (always 0 or 1 for a correctly-working cache)
        self._call_counts: dict[str, int] = defaultdict(int)
        # Per-key locks for double-checked locking
        self._locks: dict[str, asyncio.Lock] = {}
        # Engines that failed (key → error message)
        self._failures: dict[str, str] = {}

    # ── Public artifact access ────────────────────────────────────────────────

    @property
    def artifact(self) -> Artifact:
        """The artifact under analysis."""
        return self._artifact

    # ── Engine accessors (lazy, cached) ──────────────────────────────────────

    async def get_nlp_signals(self, text: str | None = None) -> NLPSignals:
        """Return cached NLP signals for artifact text or an extracted text payload."""
        if text is None:
            return await self._get_or_compute("nlp", self._compute_nlp)
        import hashlib

        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        return await self._get_or_compute(
            f"nlp:text:{digest}", lambda: self._compute_nlp(text)
        )

    async def get_url_signals(self, url: str | None = None) -> URLSignals:
        """Return URL feature signals (cached per-artifact URL)."""
        key = f"url:{url or self._artifact.raw_content}"
        return await self._get_or_compute(key, lambda: self._compute_url(url))

    async def get_web_signals(self) -> WebSignals:
        """Return DOM/HTML signals (cached)."""
        return await self._get_or_compute("web", self._compute_web)

    async def get_email_signals(self) -> EmailSignals:
        """Return email header/auth signals (cached)."""
        return await self._get_or_compute("email", self._compute_email)

    async def get_intel_signals(self, indicator: str | None = None) -> IntelSignals:
        """Return threat-intel hits (cached per indicator)."""
        key = f"intel:{indicator or self._artifact.raw_content}"
        return await self._get_or_compute(key, lambda: self._compute_intel(indicator))

    async def get_media_qr_payloads(self) -> list[str]:
        """Return decoded QR payloads (cached)."""
        return await self._get_or_compute("media:qr", self._compute_media_qr)

    async def get_media_ocr_text(self) -> str:
        """Return extracted text from image (cached)."""
        return await self._get_or_compute("media:ocr", self._compute_media_ocr)

    # ── Diagnostics ──────────────────────────────────────────────────────────

    def get_engine_call_count(self, engine_key: str) -> int:
        """Return how many times an engine's backend was actually invoked.

        A correctly-working cache will always return 0 (not run) or 1 (run
        once).  Values > 1 indicate a caching bug.
        """
        return self._call_counts.get(engine_key, 0)

    def get_failures(self) -> dict[str, str]:
        """Return {engine_key: error_message} for engines that failed."""
        return dict(self._failures)

    def get_engine_signals_snapshot(self) -> EngineSignals:
        """Build an EngineSignals object from whatever is currently cached."""
        nlp = self._cache.get("nlp") or next(
            (value for key, value in self._cache.items() if key.startswith("nlp:text:")),
            None,
        )
        from app.schemas.schemas import ArtifactType

        if nlp is None and (
            self._artifact.type in (ArtifactType.URL, ArtifactType.QR, ArtifactType.IMAGE)
            or (self._artifact.type == ArtifactType.FILE and not self._artifact.raw_content.strip())
        ):
            nlp = NLPSignals(backend_used="not_applicable", text_length=0)
        intel_signals = [
            value
            for key, value in self._cache.items()
            if key.startswith("intel:") and isinstance(value, IntelSignals)
        ]
        intel = IntelSignals(
            hits=[hit for signals in intel_signals for hit in signals.hits],
            providers_queried=list(dict.fromkeys(
                provider for signals in intel_signals for provider in signals.providers_queried
            )),
            providers_failed=list(dict.fromkeys(
                provider for signals in intel_signals for provider in signals.providers_failed
            )),
            offline_mode=all(signals.offline_mode for signals in intel_signals),
        ) if intel_signals else None
        return EngineSignals(
            nlp=nlp,
            url=next(
                (v for k, v in self._cache.items() if k.startswith("url:") and isinstance(v, URLSignals)),
                self._cache.get("url"),
            ),
            web=self._cache.get("web"),
            email=self._cache.get("email"),
            intel=intel,
        )

    # ── Core caching primitive ────────────────────────────────────────────────

    async def _get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Coroutine[Any, Any, Any]],
    ) -> Any:
        """Return a cached value, computing it at most once (thread-safe)."""
        if key in self._cache:
            return self._cache[key]

        # Initialise lock on first access (safe outside async critical section)
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()

        async with self._locks[key]:
            # Double-check after acquiring the lock
            if key in self._cache:
                return self._cache[key]

            self._call_counts[key] += 1
            try:
                result = await compute_fn()
            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}"
                logger.error("Engine %r failed: %s", key, error_msg)
                self._failures[key] = error_msg
                # Return a safe empty default so callers don't crash
                result = self._empty_default(key)

            self._cache[key] = result
            return result

    # ── Private compute helpers (stubs; filled in by later stages) ────────────

    async def _compute_nlp(self, text: str | None = None) -> NLPSignals:
        if self._nlp_engine is None:
            return NLPSignals()

        from app.schemas.schemas import ArtifactType

        artifact = self._artifact
        explicit_text = text is not None
        if not explicit_text and artifact.type in (ArtifactType.URL, ArtifactType.QR, ArtifactType.IMAGE):
            return NLPSignals(backend_used="not_applicable", text_length=0)

        text = artifact.raw_content or "" if text is None else text
        if not explicit_text and artifact.type == ArtifactType.WEBPAGE and re.match(r"^\s*<", text):
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(text[:500 * 1024], "html.parser")
                for element in soup(("script", "style", "noscript", "template")):
                    element.decompose()
                text = soup.get_text(separator=" ", strip=True)
            except Exception as exc:
                logger.warning("Could not extract visible webpage text for NLP: %s", exc)
                text = ""

        # URL destinations are scored by the URL detectors, not as message prose.
        text = re.sub(r"https?://[^\s<>]+", " ", text, flags=re.IGNORECASE)
        return await self._nlp_engine.analyze(text)

    async def _compute_url(self, url: str | None) -> URLSignals:
        if self._url_engine is None:
            return URLSignals()
        target = url or self._artifact.raw_content
        return await self._url_engine.analyze(target)

    async def _compute_web(self) -> WebSignals:
        if self._web_engine is None:
            return WebSignals()
        return await self._web_engine.analyze(self._artifact)

    async def _compute_email(self) -> EmailSignals:
        if self._email_engine is None:
            return EmailSignals()
        return await self._email_engine.analyze(self._artifact)

    async def _compute_intel(self, indicator: str | None) -> IntelSignals:
        if self._intel_provider is None:
            return IntelSignals(offline_mode=True)
        target = indicator or self._artifact.raw_content
        return await self._intel_provider.lookup(target)

    async def _compute_media_qr(self) -> list[str]:
        if self._media_engine is None:
            return []
        return await self._media_engine.decode_qr(self._artifact)

    async def _compute_media_ocr(self) -> str:
        if self._media_engine is None:
            return ""
        return await self._media_engine.extract_text_ocr(self._artifact)

    @staticmethod
    def _empty_default(key: str) -> Any:
        """Return a typed empty default for a given engine key on failure."""
        if key == "nlp":
            return NLPSignals()
        if key.startswith("url:") or key == "url":
            return URLSignals()
        if key == "web":
            return WebSignals()
        if key == "email":
            return EmailSignals()
        if key.startswith("intel:"):
            return IntelSignals(offline_mode=True)
        if key == "media:qr":
            return []
        if key == "media:ocr":
            return ""
        return None
