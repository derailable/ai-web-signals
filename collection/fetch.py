#!/usr/bin/env python3
"""
Fetch and deterministically parse AI-related web readiness endpoints.

Input:
    data/input/cloudflare-radar_top-100-domains_20260710.csv

Outputs:
    data/raw/fetches.jsonl.gz       Audit artifact with bounded response bodies.
    data/processed/domains.parquet  Primary analysis artifact for R.
    data/processed/domains.csv      Convenience inspection artifact.
    data/raw/run_summary.json       Operational run summary.

Example:
    uv run python collection/fetch.py --resume
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import difflib
import gzip
import hashlib
import html
import ipaddress
import json
import logging
import random
import re
import socket
import ssl
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from markdown_it import MarkdownIt

# ---------------------------------------------------------------------------
# Configuration and constants
# ---------------------------------------------------------------------------

VERSION = "0.1.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_PATH = (
    REPO_ROOT / "data/input/cloudflare-radar_top-100-domains_20260710.csv"
)
DEFAULT_RAW_PATH = REPO_ROOT / "data/raw/fetches.jsonl.gz"
DEFAULT_PARQUET_PATH = REPO_ROOT / "data/processed/domains.parquet"
DEFAULT_CSV_PATH = REPO_ROOT / "data/processed/domains.csv"
DEFAULT_SUMMARY_PATH = REPO_ROOT / "data/raw/run_summary.json"
DEFAULT_USER_AGENT = "AIWebReadinessStudy/0.1"
DEFAULT_CONCURRENCY = 30
DEFAULT_DOMAIN_CONCURRENCY = 3
DEFAULT_LOG_EVERY = 100
DEFAULT_PROGRESS_SECONDS = 30.0

HOMEPAGE_LIMIT = 1 * 1024 * 1024
ROBOTS_LIMIT = 2 * 1024 * 1024
LLMS_LIMIT = 5 * 1024 * 1024
LLMS_FULL_LIMIT = 10 * 1024 * 1024

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
RETRY_DELAYS = (1.0, 3.0)
TEXTUAL_CONTENT_TYPES = {
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
}
SOFT_404_PATTERNS = (
    r"\b404\b",
    r"\bpage not found\b",
    r"\bnot found\b",
    r"\bdoes not exist\b",
    r"\bmissing page\b",
    r"\bpage is missing\b",
    r"\bwe couldn't find\b",
    r"\bwe could not find\b",
)
UNRELATED_HTML_PATH_PARTS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/",
    "/oauth",
    "/authorize",
    "/account",
    "/404",
    "/404.html",
    "/04.html",
    "/not-found",
    "/notfound",
)
UNRELATED_HTML_TEXT_PATTERNS = (
    r"\bsign in to your account\b",
    r"\bsign in\b",
    r"\blog in\b",
    r"\blogin\b",
    r"\bauthentication required\b",
    r"\baccess denied\b",
    r"\bforbidden\b",
)
MARKDOWN_FEATURE_PATTERNS = {
    "heading": re.compile(r"(?m)^\s{0,3}#{1,6}\s+\S"),
    "link": re.compile(r"\[[^\]]+\]\([^)]+\)"),
    "list": re.compile(r"(?m)^\s*(?:[-+*]|\d+[.)])\s+\S"),
    "blockquote": re.compile(r"(?m)^\s*>\s+\S"),
    "code_fence": re.compile(r"(?m)^\s*(```|~~~)"),
}

AI_AGENTS: dict[str, dict[str, str]] = {
    "gptbot": {"provider": "openai", "purpose": "training"},
    "oai-searchbot": {"provider": "openai", "purpose": "search"},
    "chatgpt-user": {"provider": "openai", "purpose": "user_retrieval"},
    "claudebot": {"provider": "anthropic", "purpose": "training_or_crawling"},
    "claude-searchbot": {"provider": "anthropic", "purpose": "search"},
    "google-extended": {"provider": "google", "purpose": "ai_training_control"},
    "ccbot": {"provider": "common_crawl", "purpose": "dataset_collection"},
    "perplexitybot": {"provider": "perplexity", "purpose": "search"},
}

POLICY_VALUES = {
    "explicit_disallow",
    "explicit_allow",
    "explicit_partial",
    "wildcard_disallow",
    "wildcard_allow",
    "wildcard_partial",
    "unspecified",
    "robots_missing",
    "robots_unparseable",
}

MD = MarkdownIt("commonmark")


@dataclass(frozen=True)
class DomainInput:
    domain: str
    source_position: int
    source_row: int
    source_domain_value: str
    source_rank: int | None
    source_fields: dict[str, str]


@dataclass(frozen=True)
class FetchSpec:
    name: str
    max_bytes: int


@dataclass
class RunStats:
    processed: int = 0
    homepage_reachable: int = 0
    robots_candidates: int = 0
    llms_candidates: int = 0
    llms_full_candidates: int = 0
    domains_with_errors: int = 0

    def update(self, record: Mapping[str, Any]) -> None:
        self.processed += 1
        if record.get("homepage", {}).get("reachable"):
            self.homepage_reachable += 1
        if record.get("robots", {}).get("parsed", {}).get("candidate_exists"):
            self.robots_candidates += 1
        if record.get("llms_txt", {}).get("parsed", {}).get("candidate_exists"):
            self.llms_candidates += 1
        if record.get("llms_full_txt", {}).get("parsed", {}).get("candidate_exists"):
            self.llms_full_candidates += 1
        if count_record_errors(record) > 0:
            self.domains_with_errors += 1


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_type_base(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def is_html_content_type(content_type: str | None) -> bool:
    return content_type in {"text/html", "application/xhtml+xml"}


def is_textual_content_type(content_type: str | None) -> bool:
    if content_type is None:
        return False
    return content_type.startswith("text/") or content_type in TEXTUAL_CONTENT_TYPES


def looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return control / max(len(sample), 1) < 0.02


def normalize_domain(raw: str) -> tuple[str | None, str | None]:
    value = raw.strip().lower().rstrip(".")
    if not value:
        return None, "empty domain"
    if "://" in value:
        return None, "contains a URL scheme"
    if any(ch in value for ch in "/?#"):
        return None, "contains a URL path, query, or fragment"
    if any(ch.isspace() for ch in value):
        return None, "contains whitespace"
    if ":" in value:
        return None, "contains a port or colon"
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "invalid internationalized domain"
    if len(value) > 253:
        return None, "domain is too long"
    labels = value.split(".")
    if len(labels) < 2:
        return None, "domain has no dot"
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if not all(label_re.fullmatch(label) for label in labels):
        return None, "contains an invalid DNS label"
    try:
        ipaddress.ip_address(value)
        return None, "IP addresses are not accepted"
    except ValueError:
        pass
    return value, None


def identify_domain_column(fieldnames: Sequence[str]) -> str:
    lower_to_original = {name.strip().lower(): name for name in fieldnames}
    for candidate in ("domain", "hostname", "host"):
        if candidate in lower_to_original:
            return lower_to_original[candidate]

    domain_like = [
        original
        for lowered, original in lower_to_original.items()
        if "domain" in lowered
    ]
    if len(domain_like) == 1:
        return domain_like[0]

    raise ValueError(
        "Could not identify a domain column in input CSV. "
        f"Available columns: {', '.join(fieldnames)}"
    )


def identify_rank_column(fieldnames: Sequence[str]) -> str | None:
    lower_to_original = {name.strip().lower(): name for name in fieldnames}
    for candidate in ("rank", "ranking"):
        if candidate in lower_to_original:
            return lower_to_original[candidate]
    return None


def parse_optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return int(stripped)
    except ValueError:
        return None


def load_domains(
    path: Path,
    limit: int | None,
    domain_column: str | None = None,
) -> tuple[list[DomainInput], list[dict[str, Any]], int, str, str | None]:
    domains: list[DomainInput] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header row.")
        fieldnames = list(reader.fieldnames)
        actual_domain_column = domain_column or identify_domain_column(fieldnames)
        if actual_domain_column not in fieldnames:
            raise ValueError(
                f"Input CSV is missing requested domain column: {actual_domain_column}"
            )
        rank_column = identify_rank_column(fieldnames)

        input_rows = 0
        for source_position, row in enumerate(reader, start=1):
            input_rows += 1
            source_row = source_position + 1
            original = row.get(actual_domain_column, "")
            normalized, reason = normalize_domain(original or "")
            if reason:
                skipped.append(
                    {"row": source_row, "domain": original, "reason": reason}
                )
                continue
            assert normalized is not None
            if normalized in seen:
                skipped.append(
                    {
                        "row": source_row,
                        "domain": original,
                        "reason": f"duplicate after normalization: {normalized}",
                    }
                )
                continue
            seen.add(normalized)
            source_fields = {
                str(key): (value or "").strip() for key, value in row.items()
            }
            source_rank = (
                parse_optional_int(row.get(rank_column)) if rank_column else None
            )
            domains.append(
                DomainInput(
                    domain=normalized,
                    source_position=source_position,
                    source_row=source_row,
                    source_domain_value=(original or "").strip(),
                    source_rank=source_rank,
                    source_fields=source_fields,
                )
            )
            if limit is not None and len(domains) >= limit:
                break

    return domains, skipped, input_rows, actual_domain_column, rank_column


def decode_body(
    data: bytes, content_type_header: str | None
) -> tuple[str | None, str | None]:
    if not data:
        return "", None
    if not looks_textual(data):
        return None, "unexpected_binary"

    charset = None
    if content_type_header:
        match = re.search(
            r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type_header, re.I
        )
        if match:
            charset = match.group(1).strip().lower()

    encodings = [charset] if charset else []
    encodings.extend(["utf-8", "windows-1252", "latin-1"])
    attempted: set[str] = set()
    for encoding in encodings:
        if not encoding or encoding in attempted:
            continue
        attempted.add(encoding)
        try:
            return data.decode(encoding), None
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace"), "decode_error"


def extract_html_title(text: str | None) -> str | None:
    if not text:
        return None
    soup = BeautifulSoup(text, "html.parser")
    if soup.title and soup.title.string:
        title = re.sub(r"\s+", " ", soup.title.string).strip()
        return title or None
    return None


def extract_visible_html_text(text: str | None) -> str:
    if not text:
        return ""
    soup = BeautifulSoup(text, "html.parser")
    for element in soup(["script", "style", "noscript", "template", "svg"]):
        element.decompose()
    visible = html.unescape(soup.get_text(" ", strip=True))
    return re.sub(r"\s+", " ", visible).strip().lower()


def normalized_plain_text(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", html.unescape(text)).strip().lower()


def looks_like_html_document(text: str | None) -> bool:
    if not text:
        return False
    sample = text[:5000].lower()
    return any(
        marker in sample for marker in ("<!doctype html", "<html", "<head", "<body")
    )


def text_similarity(a: str, b: str) -> float:
    if len(a) < 200 or len(b) < 200:
        return 0.0
    # Cap work for pathological pages while retaining enough text for comparison.
    a = a[:200_000]
    b = b[:200_000]
    return difflib.SequenceMatcher(None, a, b, autojunk=True).ratio()


def count_record_errors(record: Mapping[str, Any]) -> int:
    count = 0
    for key in ("homepage", "robots", "llms_txt", "llms_full_txt"):
        endpoint = record.get(key, {})
        if endpoint.get("error_type"):
            count += 1
    if record.get("domain_error"):
        count += 1
    return count


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def classify_httpx_error(exc: BaseException) -> tuple[str, str]:
    message = str(exc).strip() or exc.__class__.__name__
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout", message
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout", message
    if isinstance(exc, httpx.PoolTimeout):
        return "connect_timeout", message
    if isinstance(exc, httpx.TooManyRedirects):
        return "redirect_error", message
    if isinstance(exc, httpx.InvalidURL):
        return "invalid_url", message
    if isinstance(exc, httpx.ConnectError):
        cause = exc.__cause__
        chain = repr(exc).lower()
        if isinstance(cause, ssl.SSLError) or "certificate" in chain or "tls" in chain:
            return "tls_error", message
        if isinstance(cause, socket.gaierror) or "name or service not known" in chain:
            return "dns_error", message
        return "connect_error", message
    if isinstance(exc, httpx.TransportError):
        return "connect_error", message
    return "unknown_error", message


def should_retry_exception(exc: BaseException) -> bool:
    if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout)):
        return True
    if isinstance(exc, httpx.ConnectError):
        error_type, _ = classify_httpx_error(exc)
        return error_type in {"dns_error", "connect_error"}
    return False


async def read_limited(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        if not chunk:
            continue
        remaining = limit - total
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    await response.aclose()
    return b"".join(chunks), truncated


async def fetch_response(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    url: str,
    spec: FetchSpec,
) -> dict[str, Any]:
    attempts = 0
    last_error_type: str | None = None
    last_error_message: str | None = None

    while attempts <= len(RETRY_DELAYS):
        attempts += 1
        started = time.perf_counter()
        try:
            retry_delay: float | None = None
            async with semaphore:
                request = client.build_request("GET", url)
                response = await client.send(request, stream=True)
                status_code = response.status_code
                if status_code in RETRYABLE_STATUS_CODES and attempts <= len(
                    RETRY_DELAYS
                ):
                    await response.aclose()
                    retry_delay = RETRY_DELAYS[attempts - 1] + random.uniform(0.0, 0.3)
                    body = b""
                    truncated = False
                else:
                    body, truncated = await read_limited(response, spec.max_bytes)

            if retry_delay is not None:
                await asyncio.sleep(retry_delay)
                continue

            elapsed_ms = round((time.perf_counter() - started) * 1000)
            content_type_header = response.headers.get("content-type")
            content_type = content_type_base(content_type_header)
            body_text, decode_error = decode_body(body, content_type_header)
            error_type = decode_error
            error_message = (
                "Response body could not be decoded cleanly."
                if decode_error == "decode_error"
                else "Response appears to be binary."
                if decode_error == "unexpected_binary"
                else None
            )

            return {
                "requested_url": url,
                "final_url": str(response.url),
                "final_host": response.url.host,
                "final_scheme": response.url.scheme,
                "status_code": status_code,
                "content_type": content_type,
                "content_type_header": content_type_header,
                "content_length": _parse_int(response.headers.get("content-length")),
                "elapsed_ms": elapsed_ms,
                "redirect_count": len(response.history),
                "redirect_chain": [str(item.url) for item in response.history],
                "bytes_read": len(body),
                "body_sha256": sha256_hex(body),
                "body_text": body_text,
                "body_truncated": truncated,
                "attempts": attempts,
                "error_type": error_type,
                "error_message": error_message,
            }
        except httpx.HTTPError as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            error_type, error_message = classify_httpx_error(exc)
            last_error_type, last_error_message = error_type, error_message
            if attempts <= len(RETRY_DELAYS) and should_retry_exception(exc):
                delay = RETRY_DELAYS[attempts - 1] + random.uniform(0.0, 0.3)
                await asyncio.sleep(delay)
                continue
            return {
                "requested_url": url,
                "final_url": None,
                "final_host": None,
                "final_scheme": None,
                "status_code": None,
                "content_type": None,
                "content_type_header": None,
                "content_length": None,
                "elapsed_ms": elapsed_ms,
                "redirect_count": 0,
                "redirect_chain": [],
                "bytes_read": 0,
                "body_sha256": None,
                "body_text": None,
                "body_truncated": False,
                "attempts": attempts,
                "error_type": error_type,
                "error_message": error_message,
            }

    raise RuntimeError(
        f"Unreachable retry state: {last_error_type}: {last_error_message}"
    )


async def fetch_homepage(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    domain: str,
) -> dict[str, Any]:
    https_url = f"https://{domain}/"
    result = await fetch_response(
        client, semaphore, https_url, FetchSpec("homepage", HOMEPAGE_LIMIT)
    )
    if result.get("status_code") is not None:
        result["used_http_fallback"] = False
        result["reachable"] = True
        return result

    if result.get("error_type") in {
        "dns_error",
        "connect_timeout",
        "connect_error",
        "tls_error",
    }:
        http_url = f"http://{domain}/"
        fallback = await fetch_response(
            client, semaphore, http_url, FetchSpec("homepage", HOMEPAGE_LIMIT)
        )
        fallback["used_http_fallback"] = True
        fallback["https_error_type"] = result.get("error_type")
        fallback["https_error_message"] = result.get("error_message")
        fallback["reachable"] = fallback.get("status_code") is not None
        return fallback

    result["used_http_fallback"] = False
    result["reachable"] = False
    return result


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# llms.txt parsing and fallback detection
# ---------------------------------------------------------------------------


def detect_homepage_fallback(
    homepage: Mapping[str, Any],
    endpoint: Mapping[str, Any],
) -> tuple[bool, list[str], float | None]:
    reasons: list[str] = []
    similarity: float | None = None

    homepage_url = homepage.get("final_url")
    endpoint_url = endpoint.get("final_url")
    if homepage_url and endpoint_url and homepage_url == endpoint_url:
        reasons.append("same_final_url")

    homepage_hash = homepage.get("body_sha256")
    endpoint_hash = endpoint.get("body_sha256")
    if homepage_hash and endpoint_hash and homepage_hash == endpoint_hash:
        reasons.append("same_body_hash")

    homepage_type = homepage.get("content_type")
    endpoint_type = endpoint.get("content_type")
    both_html = is_html_content_type(homepage_type) and is_html_content_type(
        endpoint_type
    )

    if both_html:
        homepage_title = extract_html_title(homepage.get("body_text"))
        endpoint_title = extract_html_title(endpoint.get("body_text"))
        if (
            homepage_title
            and endpoint_title
            and homepage_title.casefold() == endpoint_title.casefold()
        ):
            reasons.append("same_html_title")

        homepage_visible = extract_visible_html_text(homepage.get("body_text"))
        endpoint_visible = extract_visible_html_text(endpoint.get("body_text"))
        similarity = text_similarity(homepage_visible, endpoint_visible)
        if similarity >= 0.90:
            reasons.append("html_visible_text_similarity")

    return bool(reasons), reasons, similarity


def detect_soft_404(
    endpoint: Mapping[str, Any], homepage_fallback: bool
) -> tuple[bool, list[str]]:
    if endpoint.get("status_code") != 200:
        return False, []
    if homepage_fallback:
        return False, []
    if not is_html_content_type(endpoint.get("content_type")):
        return False, []

    title = extract_html_title(endpoint.get("body_text")) or ""
    visible = extract_visible_html_text(endpoint.get("body_text"))
    haystack = f"{title}\n{visible[:20_000]}".lower()
    matches = [pattern for pattern in SOFT_404_PATTERNS if re.search(pattern, haystack)]
    return bool(matches), matches


def detect_unrelated_html_response(
    endpoint: Mapping[str, Any],
    markdown_like: bool,
) -> tuple[bool, list[str]]:
    status = endpoint.get("status_code")
    if status is None or not (200 <= status < 300):
        return False, []
    if not is_html_content_type(endpoint.get("content_type")):
        return False, []
    body_text = endpoint.get("body_text")
    if not isinstance(body_text, str) or not body_text.strip():
        return False, []
    if not looks_like_html_document(body_text):
        return False, []
    if markdown_like:
        return False, []

    reasons: list[str] = []
    final_url = endpoint.get("final_url") or ""
    parsed_url = urlparse(final_url)
    final_path = parsed_url.path.lower()
    if any(part in final_path for part in UNRELATED_HTML_PATH_PARTS):
        reasons.append("unrelated_final_url_path")

    title = extract_html_title(body_text) or ""
    visible = extract_visible_html_text(body_text)
    haystack = f"{title}\n{visible[:20_000]}".lower()
    if any(re.search(pattern, haystack) for pattern in UNRELATED_HTML_TEXT_PATTERNS):
        reasons.append("unrelated_html_text")

    return bool(reasons), reasons


def extract_markdown_links(text: str) -> list[str]:
    links: list[str] = []
    try:
        tokens = MD.parse(text)
    except Exception:
        return links

    for token in tokens:
        if token.type != "inline" or not token.children:
            continue
        for child in token.children:
            if child.type == "link_open":
                href = child.attrGet("href")
                if href:
                    links.append(href.strip())
    return links


def extract_markdown_headings(text: str) -> list[tuple[int, str]]:
    headings: list[tuple[int, str]] = []
    try:
        tokens = MD.parse(text)
    except Exception:
        return headings

    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        level = int(token.tag[1]) if token.tag.startswith("h") else 0
        if index + 1 < len(tokens) and tokens[index + 1].type == "inline":
            value = tokens[index + 1].content.strip()
            if value:
                headings.append((level, value))
    return headings


def classify_link(
    raw_url: str,
    base_url: str,
    endpoint_host: str | None,
) -> tuple[str, str | None]:
    try:
        resolved = urljoin(base_url, raw_url)
        parsed = urlparse(resolved)
    except ValueError:
        return "invalid", None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "invalid", resolved
    if endpoint_host and parsed.hostname.casefold() == endpoint_host.casefold():
        if raw_url.startswith(("/", "./", "../", "#")) or not urlparse(raw_url).scheme:
            return "relative", resolved
        return "same_host", resolved
    return "external", resolved


def parse_llms_text(
    endpoint: Mapping[str, Any],
    homepage: Mapping[str, Any],
) -> dict[str, Any]:
    status = endpoint.get("status_code")
    body_text = endpoint.get("body_text")
    content_type = endpoint.get("content_type")
    body_nonempty = bool(body_text and body_text.strip())
    textual = is_textual_content_type(content_type) or (
        content_type is None and body_nonempty
    )
    text = body_text if body_text is not None else ""

    fallback, fallback_reasons, similarity = detect_homepage_fallback(
        homepage, endpoint
    )
    soft_404, soft_404_matches = detect_soft_404(endpoint, fallback)
    markdown_features = {
        name: bool(pattern.search(text))
        for name, pattern in MARKDOWN_FEATURE_PATTERNS.items()
    }
    markdown_like = bool(textual and body_nonempty and any(markdown_features.values()))
    unrelated, unrelated_reasons = detect_unrelated_html_response(
        endpoint, markdown_like
    )
    candidate_exists = bool(
        status is not None
        and 200 <= status < 300
        and textual
        and body_nonempty
        and not fallback
        and not soft_404
        and not unrelated
    )

    headings = extract_markdown_headings(text) if candidate_exists else []
    links = extract_markdown_links(text) if candidate_exists else []

    title = None
    for level, heading in headings:
        if level == 1:
            title = heading
            break
    if title is None and headings:
        title = headings[0][1]

    endpoint_url = endpoint.get("final_url") or endpoint.get("requested_url") or ""
    endpoint_host = urlparse(endpoint_url).hostname
    link_classes = Counter()
    resolved_links: list[dict[str, str | None]] = []
    for raw_url in links:
        classification, resolved = classify_link(raw_url, endpoint_url, endpoint_host)
        link_classes[classification] += 1
        resolved_links.append(
            {
                "raw_url": raw_url,
                "resolved_url": resolved,
                "classification": classification,
            }
        )

    llms_full_reference = any(
        (item.get("resolved_url") or "").lower().endswith("/llms-full.txt")
        or "llms-full.txt" in (item.get("raw_url") or "").lower()
        for item in resolved_links
    )

    words = (
        re.findall(r"\b[\w'-]+\b", text, flags=re.UNICODE) if candidate_exists else []
    )
    return {
        "candidate_exists": candidate_exists,
        "valid_text": textual and body_text is not None,
        "probable_homepage_fallback": fallback,
        "homepage_fallback_reasons": fallback_reasons,
        "homepage_text_similarity": similarity,
        "probable_soft_404": soft_404,
        "soft_404_matches": soft_404_matches,
        "probable_unrelated_response": unrelated,
        "unrelated_response_reasons": unrelated_reasons,
        "markdown_like": markdown_like,
        "markdown_features": markdown_features,
        "title": title,
        "word_count": len(words),
        "line_count": len(text.splitlines()) if candidate_exists else 0,
        "heading_count": len(headings),
        "link_count": len(links),
        "same_host_link_count": link_classes["same_host"],
        "relative_link_count": link_classes["relative"],
        "first_party_link_count": link_classes["same_host"] + link_classes["relative"],
        "external_link_count": link_classes["external"],
        "invalid_link_count": link_classes["invalid"],
        "llms_full_reference": llms_full_reference,
        "headings": [{"level": level, "text": value} for level, value in headings],
        "links": resolved_links,
    }


# ---------------------------------------------------------------------------
# robots.txt parsing
# ---------------------------------------------------------------------------


def parse_robots_groups(text: str) -> tuple[list[dict[str, Any]], list[str], bool]:
    groups: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    current_agents: list[str] = []
    current_rules: list[dict[str, str]] = []
    parseable = False

    def flush_group() -> None:
        nonlocal current_agents, current_rules
        if current_agents:
            groups.append(
                {
                    "agents": list(dict.fromkeys(current_agents)),
                    "rules": list(current_rules),
                }
            )
        current_agents = []
        current_rules = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if current_agents and current_rules:
                flush_group()
            continue
        if line.startswith("#"):
            continue

        no_comment = line.split("#", 1)[0].strip()
        if not no_comment or ":" not in no_comment:
            continue
        key, value = no_comment.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            parseable = True
            if current_agents and current_rules:
                flush_group()
            current_agents.append(value.lower())
        elif key in {"allow", "disallow"}:
            parseable = True
            if current_agents:
                current_rules.append({"directive": key, "path": value})
        elif key == "sitemap":
            parseable = True
            if value:
                sitemaps.append(value)

    flush_group()
    return groups, sitemaps, parseable


def classify_rules(rules: Sequence[Mapping[str, str]], prefix: str) -> str:
    allows = [r.get("path", "") for r in rules if r.get("directive") == "allow"]
    disallows = [r.get("path", "") for r in rules if r.get("directive") == "disallow"]

    root_disallow = "/" in disallows
    empty_disallow = "" in disallows
    nonempty_disallows = [path for path in disallows if path]
    nonempty_allows = [path for path in allows if path]

    if root_disallow and nonempty_allows:
        return f"{prefix}_partial"
    if root_disallow:
        return f"{prefix}_disallow"
    if nonempty_disallows:
        return f"{prefix}_partial"
    if nonempty_allows or empty_disallow or not rules:
        return f"{prefix}_allow"
    return f"{prefix}_allow"


def classify_agent_policy(
    groups: Sequence[Mapping[str, Any]],
    agent: str,
) -> str:
    exact_rules: list[Mapping[str, str]] = []
    wildcard_rules: list[Mapping[str, str]] = []

    for group in groups:
        agents = [str(item).lower() for item in group.get("agents", [])]
        rules = group.get("rules", [])
        if agent.lower() in agents:
            exact_rules.extend(rules)
        if "*" in agents:
            wildcard_rules.extend(rules)

    if exact_rules:
        return classify_rules(exact_rules, "explicit")
    if wildcard_rules:
        return classify_rules(wildcard_rules, "wildcard")
    return "unspecified"


def parse_robots_text(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    status = endpoint.get("status_code")
    body_text = endpoint.get("body_text")
    content_type = endpoint.get("content_type")
    textual = is_textual_content_type(content_type) or (
        content_type is None and isinstance(body_text, str)
    )
    body_nonempty = bool(body_text and body_text.strip())
    candidate_exists = bool(
        status is not None and 200 <= status < 300 and textual and body_nonempty
    )

    policies: dict[str, str] = {}
    if not candidate_exists:
        missing_policy = (
            "robots_missing"
            if status is None or status in {404, 410} or not body_nonempty
            else "robots_unparseable"
        )
        policies = {agent: missing_policy for agent in AI_AGENTS}
        return {
            "candidate_exists": False,
            "valid_text": textual and body_text is not None,
            "line_count": 0,
            "user_agent_count": 0,
            "user_agents": [],
            "sitemap_count": 0,
            "sitemaps": [],
            "groups": [],
            "parseable": False,
            "policies": policies,
            "explicit_agent_mentions": [],
        }

    groups, sitemaps, parseable = parse_robots_groups(body_text or "")
    all_agents = sorted(
        {
            agent
            for group in groups
            for agent in group.get("agents", [])
            if isinstance(agent, str)
        }
    )
    explicit_mentions = sorted(agent for agent in AI_AGENTS if agent in all_agents)

    if not parseable:
        policies = {agent: "robots_unparseable" for agent in AI_AGENTS}
    else:
        policies = {agent: classify_agent_policy(groups, agent) for agent in AI_AGENTS}

    return {
        "candidate_exists": candidate_exists,
        "valid_text": textual and body_text is not None,
        "line_count": len((body_text or "").splitlines()),
        "user_agent_count": len(all_agents),
        "user_agents": all_agents,
        "sitemap_count": len(sitemaps),
        "sitemaps": sitemaps,
        "groups": groups,
        "parseable": parseable,
        "policies": policies,
        "explicit_agent_mentions": explicit_mentions,
    }


# ---------------------------------------------------------------------------
# Domain orchestration
# ---------------------------------------------------------------------------


def blank_endpoint(
    url: str | None, error_type: str, error_message: str
) -> dict[str, Any]:
    return {
        "requested_url": url,
        "final_url": None,
        "final_host": None,
        "final_scheme": None,
        "status_code": None,
        "content_type": None,
        "content_type_header": None,
        "content_length": None,
        "elapsed_ms": 0,
        "redirect_count": 0,
        "redirect_chain": [],
        "bytes_read": 0,
        "body_sha256": None,
        "body_text": None,
        "body_truncated": False,
        "attempts": 0,
        "error_type": error_type,
        "error_message": error_message,
    }


async def process_domain(
    item: DomainInput,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    per_domain_concurrency: int,
) -> dict[str, Any]:
    fetched_at = utc_now_iso()
    record: dict[str, Any] = {
        "schema_version": 2,
        "input_domain": item.domain,
        "domain": item.domain,
        "source_position": item.source_position,
        "source_rank": item.source_rank,
        "source_row": item.source_row,
        "source_domain_value": item.source_domain_value,
        "source_fields": item.source_fields,
        "fetched_at": fetched_at,
        "domain_error": None,
    }

    try:
        homepage = await fetch_homepage(client, semaphore, item.domain)
        record["homepage"] = homepage

        final_host = homepage.get("final_host")
        final_scheme = homepage.get("final_scheme")
        if not final_host or not final_scheme:
            message = "Homepage did not resolve to a final scheme and host."
            record["robots"] = blank_endpoint(None, "not_attempted", message)
            record["llms_txt"] = blank_endpoint(None, "not_attempted", message)
            record["llms_full_txt"] = blank_endpoint(None, "not_attempted", message)
            record["robots"]["parsed"] = parse_robots_text(record["robots"])
            record["llms_txt"]["parsed"] = parse_llms_text(record["llms_txt"], homepage)
            record["llms_full_txt"]["parsed"] = parse_llms_text(
                record["llms_full_txt"], homepage
            )
            record["collection_complete"] = True
            record["collection_error_count"] = count_record_errors(record)
            return record

        base = f"{final_scheme}://{final_host}"

        endpoint_specs = {
            "robots": (f"{base}/robots.txt", FetchSpec("robots", ROBOTS_LIMIT)),
            "llms_txt": (f"{base}/llms.txt", FetchSpec("llms_txt", LLMS_LIMIT)),
            "llms_full_txt": (
                f"{base}/llms-full.txt",
                FetchSpec("llms_full_txt", LLMS_FULL_LIMIT),
            ),
        }

        domain_semaphore = asyncio.Semaphore(max(1, per_domain_concurrency))

        async def fetch_one(url: str, spec: FetchSpec) -> dict[str, Any]:
            async with domain_semaphore:
                return await fetch_response(client, semaphore, url, spec)

        robots, llms_txt, llms_full_txt = await asyncio.gather(
            *(fetch_one(url, spec) for url, spec in endpoint_specs.values())
        )

        robots["parsed"] = parse_robots_text(robots)
        llms_txt["parsed"] = parse_llms_text(llms_txt, homepage)
        llms_full_txt["parsed"] = parse_llms_text(llms_full_txt, homepage)

        record["robots"] = robots
        record["llms_txt"] = llms_txt
        record["llms_full_txt"] = llms_full_txt
        record["collection_complete"] = True
        record["collection_error_count"] = count_record_errors(record)
        return record

    except Exception as exc:
        error_type, error_message = classify_httpx_error(exc)
        record["domain_error"] = {
            "error_type": error_type,
            "error_message": error_message,
        }
        record.setdefault(
            "homepage",
            blank_endpoint(f"https://{item.domain}/", error_type, error_message),
        )
        final_host = record["homepage"].get("final_host") or item.domain
        final_scheme = record["homepage"].get("final_scheme") or "https"
        record.setdefault(
            "robots",
            blank_endpoint(
                f"{final_scheme}://{final_host}/robots.txt",
                "domain_processing_error",
                error_message,
            ),
        )
        record.setdefault(
            "llms_txt",
            blank_endpoint(
                f"{final_scheme}://{final_host}/llms.txt",
                "domain_processing_error",
                error_message,
            ),
        )
        record.setdefault(
            "llms_full_txt",
            blank_endpoint(
                f"{final_scheme}://{final_host}/llms-full.txt",
                "domain_processing_error",
                error_message,
            ),
        )
        record["robots"]["parsed"] = parse_robots_text(record["robots"])
        record["llms_txt"]["parsed"] = parse_llms_text(
            record["llms_txt"], record["homepage"]
        )
        record["llms_full_txt"]["parsed"] = parse_llms_text(
            record["llms_full_txt"], record["homepage"]
        )
        record["collection_complete"] = False
        record["collection_error_count"] = count_record_errors(record)
        return record


# ---------------------------------------------------------------------------
# JSONL, flattening, and exports
# ---------------------------------------------------------------------------


def open_jsonl_text(path: Path, mode: str):
    if path.suffix == ".gz":
        return gzip.open(path, mode + "t", encoding="utf-8")
    return path.open(mode, encoding="utf-8")


def append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_jsonl_text(path, "a") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        handle.write("\n")
        handle.flush()


def iter_jsonl(
    path: Path, ignore_malformed_final_line: bool = True
) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with open_jsonl_text(path, "r") as handle:
        malformed_line: tuple[int, str] | None = None
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if malformed_line is not None:
                previous_line_number, previous_line = malformed_line
                raise json.JSONDecodeError(
                    "Malformed JSONL line before end of file",
                    previous_line,
                    0,
                ) from ValueError(f"line {previous_line_number}")
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if ignore_malformed_final_line:
                    malformed_line = (line_number, line)
                    continue
                raise
            if isinstance(value, dict):
                yield value
        if malformed_line is not None:
            logging.warning(
                "Ignoring malformed final JSONL line %s in %s",
                malformed_line[0],
                path,
            )


def completed_domains_from_jsonl(path: Path) -> set[str]:
    return {
        str(record.get("domain")) for record in iter_jsonl(path) if record.get("domain")
    }


def safe_get(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def endpoint_candidate_value(endpoint: Mapping[str, Any]) -> bool | None:
    if endpoint.get("status_code") is None:
        return None
    return bool(safe_get(endpoint, "parsed", "candidate_exists", default=False))


def parsed_if_response(endpoint: Mapping[str, Any], field: str) -> Any:
    if endpoint.get("status_code") is None:
        return None
    if endpoint.get("body_text") is None:
        return None
    if not safe_get(endpoint, "parsed", "valid_text", default=False):
        return None
    return safe_get(endpoint, "parsed", field)


def flatten_record(record: Mapping[str, Any]) -> dict[str, Any]:
    homepage = record.get("homepage", {})
    robots = record.get("robots", {})
    llms = record.get("llms_txt", {})
    llms_full = record.get("llms_full_txt", {})
    policies = safe_get(robots, "parsed", "policies", default={}) or {}
    source_fields = record.get("source_fields", {})
    if not isinstance(source_fields, Mapping):
        source_fields = {}

    flat = {
        "source_position": record.get("source_position"),
        "source_rank": record.get("source_rank"),
        "source_categories": source_fields.get("categories"),
        "source_domain_value": record.get("source_domain_value"),
        "input_domain": record.get("input_domain", record.get("domain")),
        "domain": record.get("domain"),
        "fetched_at": record.get("fetched_at"),
        "homepage_requested_url": homepage.get("requested_url"),
        "homepage_final_url": homepage.get("final_url"),
        "homepage_final_host": homepage.get("final_host"),
        "homepage_status": homepage.get("status_code"),
        "homepage_reachable": homepage.get(
            "reachable", homepage.get("status_code") is not None
        ),
        "homepage_error_type": homepage.get("error_type"),
        "homepage_error_message": homepage.get("error_message"),
        "homepage_redirect_count": homepage.get("redirect_count"),
        "homepage_used_http_fallback": homepage.get("used_http_fallback"),
        "robots_requested_url": robots.get("requested_url"),
        "robots_status": robots.get("status_code"),
        "robots_candidate_exists": endpoint_candidate_value(robots),
        "robots_content_type": robots.get("content_type"),
        "robots_line_count": parsed_if_response(robots, "line_count"),
        "robots_user_agent_count": parsed_if_response(robots, "user_agent_count"),
        "robots_sitemap_count": parsed_if_response(robots, "sitemap_count"),
        "robots_error_type": robots.get("error_type"),
        "robots_error_message": robots.get("error_message"),
        "llms_txt_requested_url": llms.get("requested_url"),
        "llms_txt_final_url": llms.get("final_url"),
        "llms_txt_status": llms.get("status_code"),
        "llms_txt_candidate_exists": endpoint_candidate_value(llms),
        "llms_txt_probable_homepage_fallback": safe_get(
            llms, "parsed", "probable_homepage_fallback"
        ),
        "llms_txt_probable_soft_404": safe_get(llms, "parsed", "probable_soft_404"),
        "llms_txt_probable_unrelated_response": safe_get(
            llms, "parsed", "probable_unrelated_response"
        ),
        "llms_txt_content_type": llms.get("content_type"),
        "llms_txt_markdown_like": parsed_if_response(llms, "markdown_like"),
        "llms_txt_title": parsed_if_response(llms, "title"),
        "llms_txt_word_count": parsed_if_response(llms, "word_count"),
        "llms_txt_line_count": parsed_if_response(llms, "line_count"),
        "llms_txt_heading_count": parsed_if_response(llms, "heading_count"),
        "llms_txt_link_count": parsed_if_response(llms, "link_count"),
        "llms_txt_same_host_link_count": parsed_if_response(
            llms, "same_host_link_count"
        ),
        "llms_txt_relative_link_count": parsed_if_response(llms, "relative_link_count"),
        "llms_txt_external_link_count": parsed_if_response(llms, "external_link_count"),
        "llms_txt_invalid_link_count": parsed_if_response(llms, "invalid_link_count"),
        "llms_txt_llms_full_reference": safe_get(llms, "parsed", "llms_full_reference"),
        "llms_txt_error_type": llms.get("error_type"),
        "llms_txt_error_message": llms.get("error_message"),
        "llms_full_requested_url": llms_full.get("requested_url"),
        "llms_full_final_url": llms_full.get("final_url"),
        "llms_full_status": llms_full.get("status_code"),
        "llms_full_candidate_exists": endpoint_candidate_value(llms_full),
        "llms_full_probable_homepage_fallback": safe_get(
            llms_full, "parsed", "probable_homepage_fallback"
        ),
        "llms_full_probable_soft_404": safe_get(
            llms_full, "parsed", "probable_soft_404"
        ),
        "llms_full_probable_unrelated_response": safe_get(
            llms_full, "parsed", "probable_unrelated_response"
        ),
        "llms_full_content_type": llms_full.get("content_type"),
        "llms_full_markdown_like": parsed_if_response(llms_full, "markdown_like"),
        "llms_full_word_count": parsed_if_response(llms_full, "word_count"),
        "llms_full_heading_count": parsed_if_response(llms_full, "heading_count"),
        "llms_full_link_count": parsed_if_response(llms_full, "link_count"),
        "llms_full_error_type": llms_full.get("error_type"),
        "llms_full_error_message": llms_full.get("error_message"),
        "collection_complete": record.get("collection_complete", False),
        "collection_error_count": record.get(
            "collection_error_count", count_record_errors(record)
        ),
    }

    for agent in AI_AGENTS:
        flat[f"{agent.replace('-', '_')}_policy"] = policies.get(
            agent, "robots_unparseable"
        )
    return flat


def refresh_record_parsing(record: Mapping[str, Any]) -> dict[str, Any]:
    refreshed = dict(record)
    homepage = refreshed.get("homepage", {})
    if not isinstance(homepage, Mapping):
        homepage = {}

    robots = dict(refreshed.get("robots", {}) or {})
    llms = dict(refreshed.get("llms_txt", {}) or {})
    llms_full = dict(refreshed.get("llms_full_txt", {}) or {})

    robots["parsed"] = parse_robots_text(robots)
    llms["parsed"] = parse_llms_text(llms, homepage)
    llms_full["parsed"] = parse_llms_text(llms_full, homepage)

    refreshed["robots"] = robots
    refreshed["llms_txt"] = llms
    refreshed["llms_full_txt"] = llms_full
    refreshed["collection_error_count"] = count_record_errors(refreshed)
    return refreshed


def ordered_fieldnames(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    if not rows:
        return []
    keys: list[str] = list(rows[0].keys())
    seen = set(keys)
    for row in rows[1:]:
        for key in row:
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ordered_fieldnames(rows)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_utc_timestamp(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def write_parquet(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "pyarrow is required to write Parquet. Install dependencies with `uv sync`."
        ) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ordered_fieldnames(rows)
    int_columns = {
        name
        for name in fieldnames
        if name.endswith("_count")
        or name.endswith("_status")
        or name in {"source_position", "source_rank"}
    }
    bool_columns = {
        name
        for name in fieldnames
        if name.endswith("_exists")
        or name.endswith("_reachable")
        or name.endswith("_fallback")
        or name.endswith("_soft_404")
        or name.endswith("_unrelated_response")
        or name.endswith("_like")
        or name.endswith("_reference")
        or name == "collection_complete"
    }

    arrays = []
    fields = []
    for name in fieldnames:
        values = [row.get(name) for row in rows]
        if name == "fetched_at":
            array = pa.array(
                [parse_utc_timestamp(value) for value in values],
                type=pa.timestamp("ms", tz="UTC"),
            )
            field_type = array.type
        elif name in int_columns:
            array = pa.array(values, type=pa.int64())
            field_type = array.type
        elif name in bool_columns:
            array = pa.array(values, type=pa.bool_())
            field_type = array.type
        else:
            array = pa.array(values, type=pa.string())
            field_type = array.type
        arrays.append(array)
        fields.append(pa.field(name, field_type))

    table = pa.Table.from_arrays(arrays, schema=pa.schema(fields))
    pq.write_table(table, path, compression="zstd")


def rebuild_outputs_from_jsonl(
    raw_path: Path,
    parquet_path: Path,
    csv_path: Path | None,
) -> list[dict[str, Any]]:
    rows = [
        flatten_record(refresh_record_parsing(record))
        for record in iter_jsonl(raw_path)
    ]
    if not rows:
        logging.warning("No records found in %s. Skipping tabular outputs.", raw_path)
        return []
    write_parquet(parquet_path, rows)
    if csv_path is not None:
        write_csv(csv_path, rows)
    return rows


def write_run_summary(
    path: Path,
    *,
    input_rows: int,
    unique_input_domains: int,
    skipped_rows: Sequence[Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
    started_at: str,
    finished_at: str,
    elapsed_seconds: float,
    raw_path: Path,
) -> None:
    summary = {
        "schema_version": 1,
        "input_rows": input_rows,
        "unique_input_domains": unique_input_domains,
        "skipped_input_rows": len(skipped_rows),
        "processed_domains": len(rows),
        "homepage_reachable": sum(bool(row.get("homepage_reachable")) for row in rows),
        "robots_candidates": sum(
            bool(row.get("robots_candidate_exists")) for row in rows
        ),
        "llms_txt_candidates": sum(
            bool(row.get("llms_txt_candidate_exists")) for row in rows
        ),
        "llms_full_candidates": sum(
            bool(row.get("llms_full_candidate_exists")) for row in rows
        ),
        "domains_with_errors": sum(
            int(row.get("collection_error_count") or 0) > 0 for row in rows
        ),
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "raw_results_path": str(raw_path),
        "skipped_rows": list(skipped_rows),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


async def async_main(args: argparse.Namespace) -> int:
    started_perf = time.perf_counter()
    started_at = utc_now_iso()

    raw_path = args.raw_output
    parquet_path = args.processed_output
    csv_path = args.csv_output
    summary_path = args.summary_output
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    domains, skipped, input_rows, domain_column, rank_column = load_domains(
        args.input,
        args.limit,
        args.domain_column,
    )

    if skipped:
        logging.warning("Skipped %s input rows.", len(skipped))

    completed: set[str] = set()
    if args.resume and raw_path.exists():
        completed = completed_domains_from_jsonl(raw_path)
        logging.info("Resume enabled. Found %s completed domains.", len(completed))
    elif raw_path.exists() and not args.resume:
        if not args.overwrite:
            raise FileExistsError(
                f"{raw_path} already exists. Use --resume or --overwrite."
            )
        raw_path.unlink()

    pending = [item for item in domains if item.domain not in completed]
    logging.info(
        "Accepted %s unique domains. Pending %s. Concurrency %s.",
        len(domains),
        len(pending),
        args.concurrency,
    )

    timeout = httpx.Timeout(
        connect=args.connect_timeout,
        read=args.read_timeout,
        write=args.write_timeout,
        pool=args.pool_timeout,
    )
    limits = httpx.Limits(
        max_connections=max(args.concurrency * 2, 50),
        max_keepalive_connections=max(args.concurrency, 20),
    )
    semaphore = asyncio.Semaphore(args.concurrency)
    stats = RunStats()
    last_progress_at = time.monotonic()

    async with httpx.AsyncClient(
        follow_redirects=True,
        http2=True,
        verify=True,
        timeout=timeout,
        limits=limits,
        headers={
            "User-Agent": args.user_agent,
            "Accept": "*/*",
        },
    ) as client:
        queue: asyncio.Queue[DomainInput | None] = asyncio.Queue()
        result_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        for item in pending:
            queue.put_nowait(item)

        worker_count = min(args.domain_workers, len(pending)) if pending else 0
        for _ in range(worker_count):
            queue.put_nowait(None)

        async def worker() -> None:
            while True:
                item = await queue.get()
                try:
                    if item is None:
                        return
                    record = await process_domain(
                        item,
                        client,
                        semaphore,
                        args.per_domain_concurrency,
                    )
                    await result_queue.put(record)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

        for index in range(len(pending)):
            record = await result_queue.get()
            append_jsonl(raw_path, record)
            stats.update(record)
            result_queue.task_done()

            now = time.monotonic()
            if (
                stats.processed % args.log_every == 0
                or now - last_progress_at >= args.progress_seconds
                or index + 1 == len(pending)
            ):
                total_done = len(completed) + stats.processed
                logging.info(
                    "Processed %s / %s domains | homepage reachable: %s | "
                    "robots candidates: %s | llms.txt candidates: %s | errors: %s",
                    total_done,
                    len(domains),
                    stats.homepage_reachable,
                    stats.robots_candidates,
                    stats.llms_candidates,
                    stats.domains_with_errors,
                )
                last_progress_at = now

        await queue.join()
        await asyncio.gather(*workers)

    rows = rebuild_outputs_from_jsonl(raw_path, parquet_path, csv_path)
    finished_at = utc_now_iso()
    elapsed = time.perf_counter() - started_perf
    write_run_summary(
        summary_path,
        input_rows=input_rows,
        unique_input_domains=len(domains),
        skipped_rows=skipped,
        rows=rows,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_seconds=elapsed,
        raw_path=raw_path,
    )

    if skipped:
        logging.warning("Skipped rows:")
        for item in skipped:
            logging.warning(
                "  row=%s domain=%r reason=%s",
                item["row"],
                item["domain"],
                item["reason"],
            )

    logging.info("Wrote %s", raw_path)
    logging.info("Wrote %s", parquet_path)
    if csv_path is not None:
        logging.info("Wrote %s", csv_path)
    logging.info("Wrote %s", summary_path)
    logging.info(
        "Input columns: domain=%s rank=%s",
        domain_column,
        rank_column or "(none)",
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch and parse robots.txt, llms.txt, and llms-full.txt."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Input CSV path.",
    )
    parser.add_argument(
        "--raw-output",
        type=Path,
        default=DEFAULT_RAW_PATH,
        help="Raw compressed JSONL output path.",
    )
    parser.add_argument(
        "--processed-output",
        type=Path,
        default=DEFAULT_PARQUET_PATH,
        help="Processed Parquet output path.",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=DEFAULT_CSV_PATH,
        help="Optional processed CSV output path.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=DEFAULT_SUMMARY_PATH,
        help="Operational run summary path.",
    )
    parser.add_argument("--domain-column", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--domain-workers", type=int, default=30)
    parser.add_argument(
        "--per-domain-concurrency", type=int, default=DEFAULT_DOMAIN_CONCURRENCY
    )
    parser.add_argument("--log-every", type=int, default=DEFAULT_LOG_EVERY)
    parser.add_argument(
        "--progress-seconds", type=float, default=DEFAULT_PROGRESS_SECONDS
    )
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--read-timeout", type=float, default=10.0)
    parser.add_argument("--write-timeout", type=float, default=5.0)
    parser.add_argument("--pool-timeout", type=float, default=5.0)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.domain_workers < 1:
        parser.error("--domain-workers must be at least 1")
    if args.per_domain_concurrency < 1:
        parser.error("--per-domain-concurrency must be at least 1")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.resume and args.overwrite:
        parser.error("--resume and --overwrite cannot be used together")

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        logging.warning("Interrupted. Completed JSONL records remain resumable.")
        return 130
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
