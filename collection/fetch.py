#!/usr/bin/env python3
"""
Fetch compact V1 AI web readiness signals.

The collector writes one flat row per normalized domain. Response bodies are
bounded parsing inputs only; they are not persisted by default.

Default outputs:
    data/raw/domains_checkpoint.jsonl  Compact append-only resume checkpoint.
    data/processed/domains.parquet     Primary analysis artifact for R.
    data/raw/run_summary.json          Operational run summary.

Examples:
    uv run python collection/fetch.py data/input/domains.csv --overwrite
    uv run python collection/fetch.py data/input/domains.csv --resume
    uv run python collection/fetch.py data/input/domains.csv --csv-output /tmp/domains.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import email.utils
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence, TextIO
from urllib.parse import urljoin, urlparse

import httpx

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError as exc:  # pragma: no cover - exercised by CLI users.
    raise RuntimeError(
        "pyarrow is required. Install dependencies with `uv sync`."
    ) from exc


VERSION = "1.1.0"
SCHEMA_VERSION = 5
CHECKPOINT_SCHEMA_VERSION = 2
AI_POLICY_SET_VERSION = 2
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHECKPOINT_PATH = REPO_ROOT / "data/raw/domains_checkpoint.jsonl"
DEFAULT_PARQUET_PATH = REPO_ROOT / "data/processed/domains.parquet"
DEFAULT_SUMMARY_PATH = REPO_ROOT / "data/raw/run_summary.json"
DEFAULT_CSV_PATH = REPO_ROOT / "data/processed/domains.csv"
DEFAULT_INPUT_MANIFEST_PATH = REPO_ROOT / "data/input/manifest.json"
DEFAULT_USER_AGENT = (
    f"AIWebSignals/{VERSION} (+https://github.com/TypeError/ai-web-signals)"
)
DEFAULT_CONCURRENCY = 30
DEFAULT_DOMAIN_WORKERS = 30
DEFAULT_BATCH_SIZE = 500
DEFAULT_LOG_EVERY = 100
DEFAULT_PROGRESS_SECONDS = 30.0
DEFAULT_SKIPPED_SAMPLE_SIZE = 20
DEFAULT_REDIRECT_LIMIT = 10

LLMS_SAMPLE_LIMIT = 256 * 1024
ROBOTS_SAMPLE_LIMIT = 512 * 1024
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
RETRY_DELAYS = (1.0, 3.0)
MAX_RETRY_AFTER_SECONDS = 30.0
PROJECT_NAME = "ai-web-signals"
SOURCE_NAME = "Cloudflare Radar Domain Rankings"
SOURCE_ORGANIZATION = "Cloudflare, Inc."
SOURCE_URL = "https://radar.cloudflare.com/domains"
SOURCE_HOME_URL = "https://radar.cloudflare.com"
SOURCE_LICENSE = "CC BY-NC 4.0"
SOURCE_LICENSE_URL = "https://creativecommons.org/licenses/by-nc/4.0/"
SOURCE_LICENSE_REFERENCE_URL = "https://developers.cloudflare.com/radar/"

# AI-specific robots.txt tokens only. Some entries, such as Google-Extended
# and Applebot-Extended, are data-use controls rather than independent crawlers.
TRACKED_AI_TOKENS = {
    "gptbot": "gptbot_directive",
    "claudebot": "claudebot_directive",
    "google-extended": "google_extended_directive",
    "applebot-extended": "applebot_extended_directive",
    "meta-externalagent": "meta_externalagent_directive",
    "oai-searchbot": "oai_searchbot_directive",
    "claude-searchbot": "claude_searchbot_directive",
    "perplexitybot": "perplexitybot_directive",
}
AI_POLICY_GROUPS = {
    "model_development": [
        "GPTBot",
        "ClaudeBot",
        "Google-Extended",
        "Applebot-Extended",
        "Meta-ExternalAgent",
    ],
    "ai_search": ["OAI-SearchBot", "Claude-SearchBot", "PerplexityBot"],
}
DIRECTIVE_VALUES = {
    "allow",
    "partial_allow",
    "partial_disallow",
    "disallow",
    "none",
    "error",
}
DIRECTIVE_SOURCE_VALUES = {"explicit", "wildcard", "none", "error"}
ERROR_VALUES = {
    "dns_error",
    "connect_timeout",
    "read_timeout",
    "pool_timeout",
    "connect_error",
    "tls_error",
    "redirect_error",
    "unsafe_redirect",
    "unexpected_binary",
    "decode_error",
    "parse_error",
    "invalid_url",
    "private_address",
    "internal_error",
}
LLMS_OUTCOME_VALUES = {
    "present",
    "not_found",
    "empty",
    "html_response",
    "non_text",
    "http_error",
    "network_error",
}
ROBOTS_OUTCOME_VALUES = LLMS_OUTCOME_VALUES | {"parse_error"}
OUTCOME_VALUES = ROBOTS_OUTCOME_VALUES
TEXTUAL_CONTENT_TYPES = {
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
}
HTML_ERROR_PATTERNS = (
    r"\b404\b",
    r"\bnot found\b",
    r"\bpage not found\b",
    r"\bsign in\b",
    r"\blog in\b",
    r"\blogin\b",
    r"\bauthentication required\b",
    r"\baccess denied\b",
    r"\bforbidden\b",
)


@dataclass(frozen=True)
class DomainInput:
    domain: str
    rank: int | None
    categories: str | None
    source_row: int


@dataclass(frozen=True)
class EndpointResult:
    requested_url: str
    final_url: str | None
    status: int | None
    content_type: str | None
    content_length: int | None
    bytes_read: int
    body_sample: bytes
    truncated: bool
    error: str | None


@dataclass
class RequestStats:
    attempts: int = 0
    retries: int = 0
    redirects_followed: int = 0
    http_fallbacks: int = 0
    response_bytes_read: int = 0

    def to_json(self) -> dict[str, int]:
        return {
            "attempts": self.attempts,
            "retries": self.retries,
            "redirects_followed": self.redirects_followed,
            "http_fallbacks": self.http_fallbacks,
            "response_bytes_read": self.response_bytes_read,
        }


class HostSafetyCache:
    """Coalesce and cache per-host DNS safety checks for the current run."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[str | None]] = {}

    async def check(self, host: str) -> str | None:
        key = host.lower().rstrip(".")
        task = self._tasks.get(key)
        if task is None:
            task = asyncio.create_task(asyncio.to_thread(resolve_host_safety_sync, key))
            self._tasks[key] = task
        try:
            return await asyncio.shield(task)
        except BaseException:
            if self._tasks.get(key) is task:
                self._tasks.pop(key, None)
            raise


class SummaryCounters:
    def __init__(self) -> None:
        self.processed_domains = 0
        self.llms_txt_present = 0
        self.robots_txt_present = 0
        self.collection_complete_true = 0
        self.collection_complete_false = 0
        self.domains_with_endpoint_errors = 0
        self.domains_with_internal_failures = 0
        self.llms_txt_has_h1 = 0
        self.llms_txt_references_llms_full = 0
        self.truncated_endpoint_responses = 0
        self.llms_txt_outcome_counts = Counter(
            {value: 0 for value in sorted(LLMS_OUTCOME_VALUES)}
        )
        self.robots_txt_outcome_counts = Counter(
            {value: 0 for value in sorted(ROBOTS_OUTCOME_VALUES)}
        )
        self.llms_txt_error_counts = Counter(
            {value: 0 for value in sorted(ERROR_VALUES)}
        )
        self.robots_txt_error_counts = Counter(
            {value: 0 for value in sorted(ERROR_VALUES)}
        )
        self.directive_counts = {
            column: Counter({value: 0 for value in sorted(DIRECTIVE_VALUES)})
            for column in TRACKED_AI_TOKENS.values()
        }
        self.directive_source_counts = {
            column.replace("_directive", "_directive_source"): Counter(
                {value: 0 for value in sorted(DIRECTIVE_SOURCE_VALUES)}
            )
            for column in TRACKED_AI_TOKENS.values()
        }

    def update(self, row: Mapping[str, Any]) -> None:
        self.processed_domains += 1
        if row.get("llms_txt_present"):
            self.llms_txt_present += 1
        if row.get("robots_txt_present"):
            self.robots_txt_present += 1
        if row.get("collection_complete"):
            self.collection_complete_true += 1
        else:
            self.collection_complete_false += 1
            self.domains_with_internal_failures += 1
        if row.get("llms_txt_has_h1"):
            self.llms_txt_has_h1 += 1
        if row.get("llms_txt_references_llms_full"):
            self.llms_txt_references_llms_full += 1
        if row.get("llms_txt_truncated"):
            self.truncated_endpoint_responses += 1
        if row.get("robots_txt_truncated"):
            self.truncated_endpoint_responses += 1
        self.llms_txt_outcome_counts[
            str(row.get("llms_txt_outcome") or "http_error")
        ] += 1
        self.robots_txt_outcome_counts[
            str(row.get("robots_txt_outcome") or "http_error")
        ] += 1
        llms_error = row.get("llms_txt_error")
        robots_error = row.get("robots_txt_error")
        if llms_error is not None and llms_error in ERROR_VALUES:
            self.llms_txt_error_counts[str(llms_error)] += 1
        if robots_error is not None and robots_error in ERROR_VALUES:
            self.robots_txt_error_counts[str(robots_error)] += 1
        if (
            any(value is not None for value in (llms_error, robots_error))
            or row.get("llms_txt_outcome") in {"http_error", "network_error"}
            or row.get("robots_txt_outcome")
            in {
                "http_error",
                "network_error",
                "parse_error",
            }
        ):
            self.domains_with_endpoint_errors += 1
        for column in TRACKED_AI_TOKENS.values():
            value = str(row.get(column) or "error")
            self.directive_counts[column][value] += 1
            source_column = column.replace("_directive", "_directive_source")
            source = str(row.get(source_column) or "error")
            self.directive_source_counts[source_column][source] += 1

    def to_json(self) -> dict[str, Any]:
        return {
            "processed_domains": self.processed_domains,
            "llms_txt_present": self.llms_txt_present,
            "robots_txt_present": self.robots_txt_present,
            "collection_complete_true": self.collection_complete_true,
            "collection_complete_false": self.collection_complete_false,
            "domains_with_endpoint_errors": self.domains_with_endpoint_errors,
            "domains_with_internal_failures": self.domains_with_internal_failures,
            "llms_txt_has_h1": self.llms_txt_has_h1,
            "llms_txt_references_llms_full": self.llms_txt_references_llms_full,
            "truncated_endpoint_responses": self.truncated_endpoint_responses,
            "llms_txt_outcome_counts": dict(self.llms_txt_outcome_counts),
            "robots_txt_outcome_counts": dict(self.robots_txt_outcome_counts),
            "llms_txt_error_counts": dict(self.llms_txt_error_counts),
            "robots_txt_error_counts": dict(self.robots_txt_error_counts),
            "directive_counts": {
                column: dict(counter)
                for column, counter in self.directive_counts.items()
            },
            "directive_source_counts": {
                column: dict(counter)
                for column, counter in self.directive_source_counts.items()
            },
        }


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def content_type_base(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


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


def identify_categories_column(fieldnames: Sequence[str]) -> str | None:
    lower_to_original = {name.strip().lower(): name for name in fieldnames}
    for candidate in ("categories", "category"):
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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def load_input_manifest(path: Path = DEFAULT_INPUT_MANIFEST_PATH) -> dict[str, Any]:
    if not path.exists():
        return {"datasets": []}
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, Mapping):
        raise ValueError(f"Input manifest must be a JSON object: {path}")
    datasets = value.get("datasets", [])
    if not isinstance(datasets, list):
        raise ValueError(f"Input manifest must contain a datasets list: {path}")
    return dict(value)


def source_metadata_for_input(
    input_path: Path, input_digest: str, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    filename = input_path.name
    datasets = manifest.get("datasets", [])
    if isinstance(datasets, list):
        for entry in datasets:
            if isinstance(entry, Mapping) and entry.get("filename") == filename:
                result = dict(entry)
                result.setdefault("sha256", input_digest)
                return result
    return {
        "filename": filename,
        "source_name": SOURCE_NAME,
        "source_organization": SOURCE_ORGANIZATION,
        "source_url": SOURCE_URL,
        "source_home_url": SOURCE_HOME_URL,
        "downloaded_at": None,
        "coverage_start": None,
        "coverage_end": None,
        "domain_count": None,
        "ranking_scope": "unknown",
        "ordering": "unknown",
        "known_source_columns": None,
        "stored_unchanged_after_download": "unknown",
        "license": SOURCE_LICENSE,
        "license_url": SOURCE_LICENSE_URL,
        "sha256": input_digest,
        "notes": "No manifest entry was found for this input file.",
    }


def parquet_metadata_bytes(metadata: Mapping[str, Any]) -> dict[bytes, bytes]:
    return {
        key.encode("utf-8"): json.dumps(value, sort_keys=True).encode("utf-8")
        for key, value in metadata.items()
    }


def load_domains(
    path: Path,
    limit: int | None,
    domain_column: str | None = None,
    skipped_sample_size: int = DEFAULT_SKIPPED_SAMPLE_SIZE,
) -> tuple[
    list[DomainInput],
    int,
    int,
    int,
    int,
    Counter[str],
    list[dict[str, Any]],
    str,
    str | None,
    str | None,
]:
    domains: list[DomainInput] = []
    skipped_sample: list[dict[str, Any]] = []
    skipped_count = 0
    duplicate_count = 0
    skip_reasons: Counter[str] = Counter()
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
        categories_column = identify_categories_column(fieldnames)

        input_rows = 0
        for source_position, row in enumerate(reader, start=1):
            input_rows += 1
            source_row = source_position + 1
            original = row.get(actual_domain_column, "")
            normalized, reason = normalize_domain(original or "")
            if reason:
                skipped_count += 1
                skip_reasons[reason] += 1
                if len(skipped_sample) < skipped_sample_size:
                    skipped_sample.append(
                        {"row": source_row, "domain": original, "reason": reason}
                    )
                continue
            assert normalized is not None
            if normalized in seen:
                skipped_count += 1
                duplicate_count += 1
                reason = "duplicate after normalization"
                skip_reasons[reason] += 1
                if len(skipped_sample) < skipped_sample_size:
                    skipped_sample.append(
                        {
                            "row": source_row,
                            "domain": original,
                            "reason": f"{reason}: {normalized}",
                        }
                    )
                continue
            seen.add(normalized)
            rank = parse_optional_int(row.get(rank_column)) if rank_column else None
            categories = (
                (row.get(categories_column) or "").strip() if categories_column else ""
            )
            domains.append(
                DomainInput(
                    domain=normalized,
                    rank=rank,
                    categories=categories or None,
                    source_row=source_row,
                )
            )
            if limit is not None and len(domains) >= limit:
                break

    return (
        domains,
        input_rows,
        len(seen),
        skipped_count,
        duplicate_count,
        skip_reasons,
        skipped_sample,
        actual_domain_column,
        rank_column,
        categories_column,
    )


def open_jsonl_text(path: Path, mode: str) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, mode + "t", encoding="utf-8")  # type: ignore[return-value]
    return path.open(mode, encoding="utf-8")


def write_jsonl_record(handle: TextIO, record: Mapping[str, Any]) -> None:
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


def completed_domains_from_checkpoint(path: Path) -> set[str]:
    return {
        str(record.get("domain"))
        for record in iter_jsonl(path)
        if isinstance(record.get("domain"), str)
    }


def classify_httpx_error(exc: Exception) -> str:
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, httpx.PoolTimeout):
        return "pool_timeout"
    if isinstance(exc, httpx.TooManyRedirects):
        return "redirect_error"
    if isinstance(exc, httpx.InvalidURL):
        return "invalid_url"
    if isinstance(exc, httpx.ConnectError):
        cause = exc.__cause__
        chain = repr(exc).lower()
        if isinstance(cause, ssl.SSLError) or "certificate" in chain or "tls" in chain:
            return "tls_error"
        if isinstance(cause, socket.gaierror) or "name or service not known" in chain:
            return "dns_error"
        return "connect_error"
    if isinstance(exc, httpx.TransportError):
        return "connect_error"
    return "connect_error"


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.isdigit():
        return min(float(stripped), MAX_RETRY_AFTER_SECONDS)
    try:
        parsed = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = (parsed - datetime.now(timezone.utc)).total_seconds()
    if seconds <= 0:
        return 0.0
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def should_retry_exception(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.PoolTimeout,
            httpx.ConnectError,
        ),
    )


def should_try_http_fallback(error: str | None) -> bool:
    return error in {"connect_timeout", "connect_error", "tls_error"}


def is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def validate_literal_ip(host: str) -> str | None:
    value = host.strip("[]")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return "private_address" if is_forbidden_ip(address) else None


def resolve_host_safety_sync(host: str) -> str | None:
    literal_error = validate_literal_ip(host)
    if literal_error is not None:
        return literal_error
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "dns_error"
    for result in results:
        address_text = result[4][0]
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            return "dns_error"
        if is_forbidden_ip(address):
            return "private_address"
    return None


async def validate_request_url(url: str, safety_cache: HostSafetyCache) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "invalid_url"
    if parsed.username is not None or parsed.password is not None:
        return "invalid_url"
    return await safety_cache.check(parsed.hostname)


async def read_limited(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
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
    finally:
        await response.aclose()
    return b"".join(chunks), truncated


async def fetch_once(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    request_stats: RequestStats,
    url: str,
    limit: int,
) -> EndpointResult:
    attempts = 0
    while attempts <= len(RETRY_DELAYS):
        attempts += 1
        current_url = url
        redirects = 0
        try:
            retry_delay: float | None = None
            while True:
                safety_error = await validate_request_url(current_url, safety_cache)
                if safety_error is not None:
                    return EndpointResult(
                        requested_url=url,
                        final_url=current_url,
                        status=None,
                        content_type=None,
                        content_length=None,
                        bytes_read=0,
                        body_sample=b"",
                        truncated=False,
                        error=safety_error,
                    )

                async with semaphore:
                    request = client.build_request("GET", current_url)
                    request_stats.attempts += 1
                    response = await client.send(request, stream=True)
                    status_code = response.status_code
                    if 300 <= status_code < 400 and response.headers.get("location"):
                        location = response.headers["location"]
                        await response.aclose()
                        redirects += 1
                        request_stats.redirects_followed += 1
                        if redirects > DEFAULT_REDIRECT_LIMIT:
                            return EndpointResult(
                                requested_url=url,
                                final_url=current_url,
                                status=status_code,
                                content_type=None,
                                content_length=None,
                                bytes_read=0,
                                body_sample=b"",
                                truncated=False,
                                error="redirect_error",
                            )
                        next_url = urljoin(current_url, location)
                        parsed_next = urlparse(next_url)
                        if parsed_next.scheme not in {"http", "https"}:
                            return EndpointResult(
                                requested_url=url,
                                final_url=next_url,
                                status=status_code,
                                content_type=None,
                                content_length=None,
                                bytes_read=0,
                                body_sample=b"",
                                truncated=False,
                                error="unsafe_redirect",
                            )
                        current_url = next_url
                        continue

                    if status_code in RETRYABLE_STATUS_CODES and attempts <= len(
                        RETRY_DELAYS
                    ):
                        retry_after = parse_retry_after(
                            response.headers.get("retry-after")
                        )
                        await response.aclose()
                        request_stats.retries += 1
                        retry_delay = (
                            retry_after
                            if retry_after is not None
                            else RETRY_DELAYS[attempts - 1] + random.uniform(0.0, 0.3)
                        )
                    else:
                        body, truncated = await read_limited(response, limit)
                        request_stats.response_bytes_read += len(body)
                        return EndpointResult(
                            requested_url=url,
                            final_url=str(response.url),
                            status=status_code,
                            content_type=content_type_base(
                                response.headers.get("content-type")
                            ),
                            content_length=_parse_int(
                                response.headers.get("content-length")
                            ),
                            bytes_read=len(body),
                            body_sample=body,
                            truncated=truncated,
                            error=None,
                        )
                if retry_delay is not None:
                    break
            if retry_delay is not None:
                await asyncio.sleep(retry_delay)
                continue
        except httpx.HTTPError as exc:
            error = classify_httpx_error(exc)
            if attempts <= len(RETRY_DELAYS) and should_retry_exception(exc):
                request_stats.retries += 1
                delay = RETRY_DELAYS[attempts - 1] + random.uniform(0.0, 0.3)
                await asyncio.sleep(delay)
                continue
            return EndpointResult(
                requested_url=url,
                final_url=None,
                status=None,
                content_type=None,
                content_length=None,
                bytes_read=0,
                body_sample=b"",
                truncated=False,
                error=error,
            )
    raise RuntimeError("unreachable retry state")


async def fetch_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    request_stats: RequestStats,
    domain: str,
    path: str,
    limit: int,
) -> EndpointResult:
    https_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        request_stats,
        f"https://{domain}{path}",
        limit,
    )
    if https_result.status is not None or not should_try_http_fallback(
        https_result.error
    ):
        return https_result
    request_stats.http_fallbacks += 1
    http_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        request_stats,
        f"http://{domain}{path}",
        limit,
    )
    return replace(http_result, requested_url=https_result.requested_url)


def looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / max(len(sample), 1) < 0.02


def decode_text_sample(
    data: bytes, content_type_header: str | None = None
) -> str | None:
    if not data:
        return ""
    if not looks_textual(data):
        return None
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
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def is_textual_content_type(content_type: str | None) -> bool:
    if content_type is None:
        return False
    return content_type.startswith("text/") or content_type in TEXTUAL_CONTENT_TYPES


def looks_like_html(text: str) -> bool:
    sample = text[:8192].lower()
    if any(
        marker in sample for marker in ("<!doctype html", "<html", "<head", "<body")
    ):
        return True
    if re.search(r"<(?:title|div|span|script|style|meta|form|nav|footer)\b", sample):
        return True
    if re.search(r"</(?:html|head|body|div|span|script|style|form)>", sample):
        return True
    return False


def looks_like_html_error(text: str) -> bool:
    sample = re.sub(r"\s+", " ", text[:20_000]).lower()
    if not looks_like_html(text):
        return False
    return any(re.search(pattern, sample) for pattern in HTML_ERROR_PATTERNS)


def is_success_status(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def controlled_error(value: str | None) -> str | None:
    if value is None:
        return None
    if value in ERROR_VALUES:
        return value
    raise ValueError(f"Unexpected endpoint error code: {value}")


HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+\S")
H1_RE = re.compile(r"(?m)^\s{0,3}#\s+\S")
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\([^) \n]+(?:\s+\"[^\"]*\")?\)")
AUTOLINK_RE = re.compile(r"<https?://[^>\s]+>")


def count_markdown_headings(text: str) -> int:
    return len(HEADING_RE.findall(text))


def count_markdown_links(text: str) -> int:
    return len(MARKDOWN_LINK_RE.findall(text)) + len(AUTOLINK_RE.findall(text))


def has_markdown_h1(text: str) -> bool:
    return bool(H1_RE.search(text))


def evaluate_llms_txt(result: EndpointResult) -> dict[str, Any]:
    base = {
        "llms_txt_url": result.requested_url,
        "llms_txt_final_url": result.final_url,
        "llms_txt_status": result.status,
        "llms_txt_bytes_read": result.bytes_read,
        "llms_txt_content_type": result.content_type,
        "llms_txt_truncated": result.truncated,
        "llms_txt_has_h1": False,
        "llms_txt_heading_count": 0,
        "llms_txt_link_count": 0,
        "llms_txt_references_llms_full": False,
    }
    if result.error:
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "network_error",
            "llms_txt_error": result.error,
        }
    if result.status in {404, 410}:
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "not_found",
            "llms_txt_error": None,
        }
    if not is_success_status(result.status):
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "http_error",
            "llms_txt_error": None,
        }
    if not result.body_sample:
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "empty",
            "llms_txt_error": None,
        }

    text = decode_text_sample(result.body_sample)
    if text is None:
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "non_text",
            "llms_txt_error": "unexpected_binary",
        }
    if not text.strip():
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "empty",
            "llms_txt_error": None,
        }
    if looks_like_html(text) or looks_like_html_error(text):
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "html_response",
            "llms_txt_error": None,
        }
    if not is_textual_content_type(result.content_type) and not looks_textual(
        result.body_sample
    ):
        return {
            **base,
            "llms_txt_present": False,
            "llms_txt_outcome": "non_text",
            "llms_txt_error": "unexpected_binary",
        }
    heading_count = count_markdown_headings(text)
    link_count = count_markdown_links(text)
    return {
        **base,
        "llms_txt_present": True,
        "llms_txt_outcome": "present",
        "llms_txt_has_h1": has_markdown_h1(text),
        "llms_txt_heading_count": heading_count,
        "llms_txt_link_count": link_count,
        "llms_txt_references_llms_full": "llms-full.txt" in text.lower(),
        "llms_txt_error": None,
    }


def strip_robots_comment(line: str) -> str:
    escaped = False
    for index, char in enumerate(line):
        if char == "\\" and not escaped:
            escaped = True
            continue
        if char == "#" and not escaped:
            return line[:index]
        escaped = False
    return line


ROBOTS_RECOGNIZED_FIELDS = {
    "user-agent",
    "allow",
    "disallow",
    "sitemap",
    "crawl-delay",
    "host",
    "clean-param",
    "request-rate",
    "visit-time",
}


def parse_robots_groups(text: str) -> tuple[list[dict[str, Any]], bool]:
    groups: list[dict[str, Any]] = []
    current_agents: list[str] = []
    current_rules: list[dict[str, str]] = []
    saw_recognized_field = False

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
        line = strip_robots_comment(raw_line).strip()
        if not line:
            if current_agents:
                flush_group()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in ROBOTS_RECOGNIZED_FIELDS:
            saw_recognized_field = True
        if key == "user-agent":
            if current_agents and current_rules:
                flush_group()
            if value:
                current_agents.append(value.lower())
        elif key in {"allow", "disallow"} and current_agents:
            current_rules.append({"directive": key, "path": value})

    flush_group()
    return groups, saw_recognized_field


def classify_rules(rules: Sequence[Mapping[str, str]]) -> str:
    allows = [
        str(rule.get("path", "")) for rule in rules if rule.get("directive") == "allow"
    ]
    disallows = [
        str(rule.get("path", ""))
        for rule in rules
        if rule.get("directive") == "disallow"
    ]
    nonempty_allows = [path for path in allows if path]
    nonempty_disallows = [path for path in disallows if path]
    root_disallow = "/" in nonempty_disallows

    if root_disallow and nonempty_allows:
        return "partial_allow"
    if root_disallow:
        return "disallow"
    if nonempty_disallows and nonempty_allows:
        return "partial_allow"
    if nonempty_disallows:
        return "partial_disallow"
    if nonempty_allows:
        return "allow"
    if disallows:
        return "allow"
    return "allow"


def classify_agent_policy(
    groups: Sequence[Mapping[str, Any]], agent: str
) -> tuple[str, str]:
    exact_groups: list[Mapping[str, Any]] = []
    wildcard_groups: list[Mapping[str, Any]] = []
    target = agent.lower()
    for group in groups:
        agents = [str(item).lower() for item in group.get("agents", [])]
        if target in agents:
            exact_groups.append(group)
        elif "*" in agents:
            wildcard_groups.append(group)

    selected_groups = exact_groups or wildcard_groups
    if not selected_groups:
        return "none", "none"
    rules = [rule for group in selected_groups for rule in group.get("rules", [])]
    source = "explicit" if exact_groups else "wildcard"
    return classify_rules(rules), source


def policy_defaults(directive: str, source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for column in TRACKED_AI_TOKENS.values():
        values[column] = directive
        values[column.replace("_directive", "_directive_source")] = source
    return values


def evaluate_robots_txt(result: EndpointResult) -> dict[str, Any]:
    base = {
        "robots_txt_url": result.requested_url,
        "robots_txt_final_url": result.final_url,
        "robots_txt_status": result.status,
        "robots_txt_bytes_read": result.bytes_read,
        "robots_txt_content_type": result.content_type,
        "robots_txt_truncated": result.truncated,
    }
    error_policies = policy_defaults("error", "error")
    no_policies = policy_defaults("none", "none")
    if result.error:
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "network_error",
            "robots_txt_error": result.error,
            **error_policies,
        }
    if result.status in {404, 410}:
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "not_found",
            "robots_txt_error": None,
            **no_policies,
        }
    if not is_success_status(result.status):
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "http_error",
            "robots_txt_error": None,
            **error_policies,
        }
    if not result.body_sample:
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "empty",
            "robots_txt_error": None,
            **no_policies,
        }
    text = decode_text_sample(result.body_sample)
    if text is None:
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "non_text",
            "robots_txt_error": "unexpected_binary",
            **error_policies,
        }
    if not text.strip():
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "empty",
            "robots_txt_error": None,
            **no_policies,
        }
    if looks_like_html(text):
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "html_response",
            "robots_txt_error": None,
            **error_policies,
        }
    groups, recognized = parse_robots_groups(text)
    if not recognized:
        return {
            **base,
            "robots_txt_present": False,
            "robots_txt_outcome": "parse_error",
            "robots_txt_error": "parse_error",
            **error_policies,
        }
    policies: dict[str, str] = {}
    for agent, column in TRACKED_AI_TOKENS.items():
        directive, source = classify_agent_policy(groups, agent)
        policies[column] = directive
        policies[column.replace("_directive", "_directive_source")] = source
    return {
        **base,
        "robots_txt_present": True,
        "robots_txt_outcome": "present",
        "robots_txt_error": None,
        **policies,
    }


def compact_row(
    item: DomainInput,
    llms_result: EndpointResult,
    robots_result: EndpointResult,
    collection_complete: bool = True,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rank": item.rank,
        "domain": item.domain,
        "categories": item.categories,
        **evaluate_llms_txt(llms_result),
        **evaluate_robots_txt(robots_result),
        "collection_complete": collection_complete,
    }
    row["llms_txt_error"] = controlled_error(row.get("llms_txt_error"))
    row["robots_txt_error"] = controlled_error(row.get("robots_txt_error"))
    validate_compact_row(row)
    return row


def failed_endpoint(domain: str, path: str, error: str) -> EndpointResult:
    return EndpointResult(
        requested_url=f"https://{domain}{path}",
        final_url=None,
        status=None,
        content_type=None,
        content_length=None,
        bytes_read=0,
        body_sample=b"",
        truncated=False,
        error=error,
    )


async def process_domain(
    item: DomainInput,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    request_stats: RequestStats,
) -> dict[str, Any]:
    results = await asyncio.gather(
        fetch_endpoint(
            client,
            semaphore,
            safety_cache,
            request_stats,
            item.domain,
            "/llms.txt",
            LLMS_SAMPLE_LIMIT,
        ),
        fetch_endpoint(
            client,
            semaphore,
            safety_cache,
            request_stats,
            item.domain,
            "/robots.txt",
            ROBOTS_SAMPLE_LIMIT,
        ),
        return_exceptions=True,
    )

    endpoint_results: list[EndpointResult] = []
    collection_complete = True
    for path, value in zip(("/llms.txt", "/robots.txt"), results, strict=True):
        if isinstance(value, Exception):
            collection_complete = False
            logging.debug(
                "Endpoint processing failed for %s%s: %r",
                item.domain,
                path,
                value,
            )
            endpoint_results.append(
                failed_endpoint(item.domain, path, "internal_error")
            )
        else:
            endpoint_results.append(value)

    return compact_row(
        item,
        endpoint_results[0],
        endpoint_results[1],
        collection_complete,
    )


DICTIONARY_STRING_TYPE = pa.dictionary(pa.int8(), pa.string())


def ai_policy_schema_fields() -> list[pa.Field]:
    fields: list[pa.Field] = []
    for column in TRACKED_AI_TOKENS.values():
        fields.extend(
            [
                pa.field(column, DICTIONARY_STRING_TYPE, nullable=False),
                pa.field(
                    column.replace("_directive", "_directive_source"),
                    DICTIONARY_STRING_TYPE,
                    nullable=False,
                ),
            ]
        )
    return fields


PARQUET_SCHEMA = pa.schema(
    [
        pa.field("rank", pa.int32()),
        pa.field("domain", pa.string(), nullable=False),
        pa.field("categories", pa.string()),
        pa.field("llms_txt_url", pa.string()),
        pa.field("llms_txt_final_url", pa.string()),
        pa.field("llms_txt_status", pa.int16()),
        pa.field("llms_txt_present", pa.bool_(), nullable=False),
        pa.field("llms_txt_bytes_read", pa.int64(), nullable=False),
        pa.field("llms_txt_content_type", pa.string()),
        pa.field("llms_txt_outcome", DICTIONARY_STRING_TYPE, nullable=False),
        pa.field("llms_txt_truncated", pa.bool_(), nullable=False),
        pa.field("llms_txt_has_h1", pa.bool_(), nullable=False),
        pa.field("llms_txt_heading_count", pa.int32(), nullable=False),
        pa.field("llms_txt_link_count", pa.int32(), nullable=False),
        pa.field("llms_txt_references_llms_full", pa.bool_(), nullable=False),
        pa.field("llms_txt_error", DICTIONARY_STRING_TYPE),
        pa.field("robots_txt_url", pa.string()),
        pa.field("robots_txt_final_url", pa.string()),
        pa.field("robots_txt_status", pa.int16()),
        pa.field("robots_txt_present", pa.bool_(), nullable=False),
        pa.field("robots_txt_bytes_read", pa.int64(), nullable=False),
        pa.field("robots_txt_content_type", pa.string()),
        pa.field("robots_txt_outcome", DICTIONARY_STRING_TYPE, nullable=False),
        pa.field("robots_txt_truncated", pa.bool_(), nullable=False),
        pa.field("robots_txt_error", DICTIONARY_STRING_TYPE),
        *ai_policy_schema_fields(),
        pa.field("collection_complete", pa.bool_(), nullable=False),
    ]
)
PARQUET_COLUMNS = PARQUET_SCHEMA.names
AI_POLICY_COLUMNS = [
    column for column in PARQUET_COLUMNS if column.endswith("_directive")
]
AI_POLICY_SOURCE_COLUMNS = [
    column for column in PARQUET_COLUMNS if column.endswith("_directive_source")
]
LEGACY_REJECTED_COLUMNS = {
    "source_rank",
    "source_position",
    "source_categories",
    "source_domain_value",
    "input_domain",
    "fetched_at",
    "homepage",
    "homepage_requested_url",
    "homepage_final_url",
    "homepage_reachable",
    "llms_full_txt",
    "llms_full_requested_url",
    "llms_full_final_url",
    "llms_txt_markdown_like",
    "gptbot_policy",
    "oai_searchbot_policy",
    "chatgpt_user_policy",
    "claudebot_policy",
    "claude_searchbot_policy",
    "google_extended_policy",
    "ccbot_policy",
    "perplexitybot_policy",
}


def validate_compact_row(row: Mapping[str, Any]) -> None:
    keys = set(row)
    legacy = sorted(keys & LEGACY_REJECTED_COLUMNS)
    if legacy:
        raise ValueError(
            "The existing checkpoint uses an incompatible schema. "
            f"Legacy fields found: {', '.join(legacy)}. "
            "Start a clean run with --overwrite."
        )
    missing = [name for name in PARQUET_COLUMNS if name not in keys]
    extra = sorted(keys - set(PARQUET_COLUMNS))
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing fields: {', '.join(missing)}")
        if extra:
            detail.append(f"extra fields: {', '.join(extra)}")
        raise ValueError(
            "The existing checkpoint uses an incompatible schema. "
            + "; ".join(detail)
            + ". Start a clean run with --overwrite."
        )
    if not isinstance(row.get("domain"), str) or not row.get("domain"):
        raise ValueError("Output row has missing domain.")
    for column in ("llms_txt_outcome", "robots_txt_outcome"):
        allowed = (
            LLMS_OUTCOME_VALUES
            if column == "llms_txt_outcome"
            else ROBOTS_OUTCOME_VALUES
        )
        if row.get(column) not in allowed:
            raise ValueError(
                f"Invalid controlled value for {column}: {row.get(column)!r}"
            )
    for column in ("llms_txt_error", "robots_txt_error"):
        value = row.get(column)
        if value is not None and value not in ERROR_VALUES:
            raise ValueError(f"Invalid controlled value for {column}: {value!r}")
    for column in AI_POLICY_COLUMNS:
        if row.get(column) not in DIRECTIVE_VALUES:
            raise ValueError(
                f"Invalid controlled value for {column}: {row.get(column)!r}"
            )
    for column in AI_POLICY_SOURCE_COLUMNS:
        if row.get(column) not in DIRECTIVE_SOURCE_VALUES:
            raise ValueError(
                f"Invalid controlled value for {column}: {row.get(column)!r}"
            )
    for column in (
        "llms_txt_present",
        "llms_txt_truncated",
        "llms_txt_has_h1",
        "llms_txt_references_llms_full",
        "robots_txt_present",
        "robots_txt_truncated",
        "collection_complete",
    ):
        if not isinstance(row.get(column), bool):
            raise ValueError(f"Output row field must be boolean: {column}")
    for column in (
        "llms_txt_bytes_read",
        "llms_txt_heading_count",
        "llms_txt_link_count",
        "robots_txt_bytes_read",
    ):
        value = row.get(column)
        if not isinstance(value, int) or value < 0:
            raise ValueError(
                f"Output row field must be a non-negative integer: {column}"
            )
    if row.get("llms_txt_present") != (row.get("llms_txt_outcome") == "present"):
        raise ValueError("llms_txt_present must match llms_txt_outcome == 'present'.")
    if row.get("robots_txt_present") != (row.get("robots_txt_outcome") == "present"):
        raise ValueError(
            "robots_txt_present must match robots_txt_outcome == 'present'."
        )


def normalize_row_for_output(row: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {name: row.get(name) for name in PARQUET_COLUMNS}
    validate_compact_row(normalized)
    return normalized


def table_from_rows(
    rows: Sequence[Mapping[str, Any]], schema: pa.Schema = PARQUET_SCHEMA
) -> pa.Table:
    normalized_rows = [normalize_row_for_output(row) for row in rows]
    columns = {
        field.name: pa.array(
            [row[field.name] for row in normalized_rows],
            type=field.type,
        )
        for field in schema
    }
    return pa.table(columns, schema=schema)


def schema_without_metadata(schema: pa.Schema) -> pa.Schema:
    return pa.schema([schema.field(index) for index in range(len(schema))])


def validate_parquet_file(
    path: Path,
    *,
    expected_rows: int,
    expected_metadata: Mapping[str, Any] | None = None,
) -> None:
    parquet_file = pq.ParquetFile(path)
    actual_schema = schema_without_metadata(parquet_file.schema_arrow)
    if not actual_schema.equals(PARQUET_SCHEMA, check_metadata=False):
        raise ValueError("Temporary Parquet schema does not match the V1 contract.")
    metadata = parquet_file.metadata
    if metadata.num_columns != len(PARQUET_COLUMNS):
        raise ValueError("Temporary Parquet has the wrong column count.")
    if metadata.num_rows != expected_rows:
        raise ValueError(
            f"Temporary Parquet has {metadata.num_rows} rows; expected {expected_rows}."
        )
    if expected_rows and metadata.num_row_groups < 1:
        raise ValueError("Temporary Parquet has no row groups.")
    if expected_metadata:
        file_metadata = parquet_file.schema_arrow.metadata or {}
        for key, value in expected_metadata.items():
            raw = file_metadata.get(key.encode("utf-8"))
            if raw is None:
                raise ValueError(f"Temporary Parquet is missing metadata key: {key}")
            if json.loads(raw.decode("utf-8")) != value:
                raise ValueError(f"Temporary Parquet metadata mismatch for {key}.")

    columns = parquet_file.schema_arrow.names
    if columns != PARQUET_COLUMNS:
        raise ValueError("Temporary Parquet columns are not in the expected order.")
    validation_columns = [
        "domain",
        "llms_txt_outcome",
        "robots_txt_outcome",
        "llms_txt_error",
        "robots_txt_error",
        *AI_POLICY_COLUMNS,
        *AI_POLICY_SOURCE_COLUMNS,
    ]
    table = pq.read_table(path, columns=validation_columns)
    domains = table.column("domain").to_pylist()
    if any(domain is None for domain in domains):
        raise ValueError("Temporary Parquet contains a null domain.")
    if len(domains) != len(set(domains)):
        raise ValueError("Temporary Parquet contains duplicate domains.")
    for forbidden in LEGACY_REJECTED_COLUMNS:
        if forbidden in columns:
            raise ValueError(f"Temporary Parquet contains legacy column: {forbidden}")
    for column, allowed in (
        ("llms_txt_outcome", LLMS_OUTCOME_VALUES),
        ("robots_txt_outcome", ROBOTS_OUTCOME_VALUES),
        ("llms_txt_error", ERROR_VALUES),
        ("robots_txt_error", ERROR_VALUES),
    ):
        values = set(table.column(column).to_pylist()) - {None}
        invalid = values - allowed
        if invalid:
            raise ValueError(
                f"Invalid controlled values in {column}: {sorted(invalid)}"
            )
    for column in AI_POLICY_COLUMNS:
        values = set(table.column(column).to_pylist()) - {None}
        invalid = values - DIRECTIVE_VALUES
        if invalid:
            raise ValueError(f"Invalid directive values in {column}: {sorted(invalid)}")
    for column in AI_POLICY_SOURCE_COLUMNS:
        values = set(table.column(column).to_pylist()) - {None}
        invalid = values - DIRECTIVE_SOURCE_VALUES
        if invalid:
            raise ValueError(
                f"Invalid directive-source values in {column}: {sorted(invalid)}"
            )


def iter_unique_checkpoint_rows(path: Path) -> Iterator[dict[str, Any]]:
    seen: set[str] = set()
    for raw in iter_jsonl(path):
        validate_compact_row(raw)
        domain = raw.get("domain")
        if not isinstance(domain, str) or not domain or domain in seen:
            continue
        seen.add(domain)
        yield {name: raw[name] for name in PARQUET_COLUMNS}


def write_parquet_from_checkpoint(
    checkpoint_path: Path,
    parquet_path: Path,
    batch_size: int,
    metadata: Mapping[str, Any] | None = None,
) -> tuple[int, SummaryCounters]:
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = parquet_path.with_name(f".{parquet_path.name}.tmp")
    if tmp_path.exists():
        tmp_path.unlink()
    schema = (
        PARQUET_SCHEMA.with_metadata(parquet_metadata_bytes(metadata))
        if metadata
        else PARQUET_SCHEMA
    )

    row_count = 0
    batch: list[dict[str, Any]] = []
    counters = SummaryCounters()
    writer: pq.ParquetWriter | None = None
    success = False
    try:
        writer = pq.ParquetWriter(
            tmp_path,
            schema,
            compression="zstd",
            use_dictionary=True,
        )
        for row in iter_unique_checkpoint_rows(checkpoint_path):
            batch.append(row)
            counters.update(row)
            row_count += 1
            if len(batch) >= batch_size:
                writer.write_table(
                    table_from_rows(batch, schema), row_group_size=batch_size
                )
                batch.clear()
        if batch:
            writer.write_table(
                table_from_rows(batch, schema), row_group_size=batch_size
            )
            batch.clear()
        success = True
    finally:
        if writer is not None:
            writer.close()
        if not success and tmp_path.exists():
            tmp_path.unlink()

    try:
        validate_parquet_file(
            tmp_path, expected_rows=row_count, expected_metadata=metadata
        )
    except Exception:
        logging.exception("Temporary Parquet validation failed: %s", tmp_path)
        raise
    os.replace(tmp_path, parquet_path)
    return row_count, counters


def write_csv_from_checkpoint(checkpoint_path: Path, csv_path: Path) -> int:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = csv_path.with_name(f".{csv_path.name}.tmp")
    count = 0
    with tmp_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=PARQUET_COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()
        for row in iter_unique_checkpoint_rows(checkpoint_path):
            writer.writerow(row)
            count += 1
    os.replace(tmp_path, csv_path)
    return count


def output_metadata_path(output_path: Path) -> Path:
    return output_path.with_name(f"{output_path.name}.metadata.json")


def checkpoint_metadata_path(checkpoint_path: Path) -> Path:
    return checkpoint_path.with_name(f"{checkpoint_path.name}.metadata.json")


def checkpoint_metadata(
    *,
    input_path: Path,
    input_digest: str,
    started_at: str,
) -> dict[str, Any]:
    return {
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "output_schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "input_filename": input_path.name,
        "input_sha256": input_digest,
        "ai_policy_set_version": AI_POLICY_SET_VERSION,
        "ai_policy_tokens": list(TRACKED_AI_TOKENS.keys()),
        "columns": PARQUET_COLUMNS,
        "created_at": started_at,
    }


def validate_checkpoint_compatibility(
    checkpoint_path: Path,
    metadata_path: Path,
    *,
    input_digest: str,
) -> dict[str, Any]:
    if not checkpoint_path.exists():
        raise FileNotFoundError(f"checkpoint does not exist: {checkpoint_path}")
    if not metadata_path.exists():
        raise ValueError(
            "The existing checkpoint uses an incompatible schema. "
            "Checkpoint metadata is missing. Start a clean run with --overwrite."
        )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = {
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "output_schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "input_sha256": input_digest,
        "ai_policy_set_version": AI_POLICY_SET_VERSION,
        "ai_policy_tokens": list(TRACKED_AI_TOKENS.keys()),
        "columns": PARQUET_COLUMNS,
    }
    mismatches = [key for key, value in expected.items() if metadata.get(key) != value]
    if mismatches:
        raise ValueError(
            "The existing checkpoint uses an incompatible schema. "
            f"Mismatched metadata: {', '.join(mismatches)}. "
            "Start a clean run with --overwrite."
        )
    for _row in iter_unique_checkpoint_rows(checkpoint_path):
        pass
    return metadata


def write_output_metadata_sidecar(path: Path, metadata: Mapping[str, Any]) -> None:
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


def build_processed_metadata(
    *,
    input_path: Path,
    input_digest: str,
    source_dataset: Mapping[str, Any],
    started_at: str,
    finished_at: str,
    output_path: Path,
    output_row_count: int,
    counters: SummaryCounters,
    concurrency: int,
    domain_workers: int,
    timeout_config: Mapping[str, float],
    request_stats: RequestStats,
) -> dict[str, Any]:
    return {
        "project": {
            "name": PROJECT_NAME,
            "repository": "https://github.com/TypeError/ai-web-signals",
            "collector_version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "git_commit": git_commit(),
        },
        "source_dataset": {
            **dict(source_dataset),
            "input_filename": input_path.name,
            "input_sha256": input_digest,
        },
        "collection": {
            "started_at": started_at,
            "finished_at": finished_at,
            "concurrency": concurrency,
            "domain_workers": domain_workers,
            "timeout_config": dict(timeout_config),
            "request_stats": request_stats.to_json(),
            "endpoint_requests_per_domain_base": 2,
            "endpoints": ["/llms.txt", "/robots.txt"],
            "response_size_limits": {
                "llms_txt_bytes": LLMS_SAMPLE_LIMIT,
                "robots_txt_bytes": ROBOTS_SAMPLE_LIMIT,
            },
            "retry_status_codes": sorted(RETRYABLE_STATUS_CODES),
            "retry_delays_seconds": list(RETRY_DELAYS),
            "redirect_limit": DEFAULT_REDIRECT_LIMIT,
            "http_fallback_policy": (
                "HTTPS is attempted first. HTTP fallback is used only after "
                "connect_timeout, connect_error, or tls_error. DNS failures and "
                "ordinary HTTP responses do not trigger fallback."
            ),
        },
        "processing": {
            "script": "collection/fetch.py",
            "processed_at": finished_at,
            "output_filename": output_path.name,
            "output_row_count": output_row_count,
            "normalization": [
                "Domain values are lowercased, stripped, converted to ASCII IDNA, and deduplicated.",
                "Rank and categories are preserved when present in the source CSV.",
                "HTTP response bodies are reduced to compact scalar observations and discarded.",
            ],
            "ordering": "Rows are written in collection completion order; use rank or source metadata for analysis ordering.",
        },
        "schema": {
            "columns": PARQUET_COLUMNS,
            "controlled_vocabularies": {
                "llms_txt_outcome": sorted(LLMS_OUTCOME_VALUES),
                "robots_txt_outcome": sorted(ROBOTS_OUTCOME_VALUES),
                "ai_policy_directive": sorted(DIRECTIVE_VALUES),
                "ai_policy_directive_source": sorted(DIRECTIVE_SOURCE_VALUES),
            },
            "ai_policy_set_version": AI_POLICY_SET_VERSION,
            "ai_policy_groups": AI_POLICY_GROUPS,
        },
        "summary_counts": counters.to_json(),
    }


def write_summary(
    path: Path,
    *,
    input_path: Path,
    input_sha256: str,
    input_rows: int,
    unique_input_domains: int,
    skipped_input_rows: int,
    duplicate_input_domains: int,
    skipped_reason_counts: Mapping[str, int],
    skipped_sample: Sequence[Mapping[str, Any]],
    counters: SummaryCounters,
    started_at: str,
    finished_at: str,
    elapsed_seconds: float,
    output_path: Path,
    output_row_count: int,
    metadata_path: Path,
    source_dataset: Mapping[str, Any],
    checkpoint_path: Path,
    checkpoint_meta_path: Path,
    csv_path: Path | None,
    concurrency: int,
    domain_workers: int,
    timeout_config: Mapping[str, float],
    request_stats: RequestStats,
) -> None:
    parquet_row_groups = (
        pq.ParquetFile(output_path).metadata.num_row_groups
        if output_path.exists()
        else 0
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "project_name": PROJECT_NAME,
        "input_filename": input_path.name,
        "input_sha256": input_sha256,
        "source_dataset": dict(source_dataset),
        "input_rows": input_rows,
        "unique_input_domains": unique_input_domains,
        "skipped_input_rows": skipped_input_rows,
        "duplicate_input_domains": duplicate_input_domains,
        "skipped_reason_counts": dict(skipped_reason_counts),
        "skipped_input_sample": list(skipped_sample),
        **counters.to_json(),
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "concurrency": concurrency,
        "domain_workers": domain_workers,
        "timeout_config": dict(timeout_config),
        "request_stats": request_stats.to_json(),
        "retry_status_codes": sorted(RETRYABLE_STATUS_CODES),
        "retry_delays_seconds": list(RETRY_DELAYS),
        "redirect_limit": DEFAULT_REDIRECT_LIMIT,
        "http_fallback_policy": (
            "HTTPS is attempted first. HTTP fallback is used only after "
            "connect_timeout, connect_error, or tls_error. DNS failures and ordinary "
            "HTTP responses do not trigger fallback."
        ),
        "response_size_limits": {
            "llms_txt_bytes": LLMS_SAMPLE_LIMIT,
            "robots_txt_bytes": ROBOTS_SAMPLE_LIMIT,
        },
        "ai_policy_set_version": AI_POLICY_SET_VERSION,
        "ai_policy_groups": AI_POLICY_GROUPS,
        "ai_policy_tokens": list(TRACKED_AI_TOKENS.keys()),
        "output_filename": output_path.name,
        "output_path": str(output_path),
        "output_rows": output_row_count,
        "output_row_count": output_row_count,
        "output_bytes": output_path.stat().st_size if output_path.exists() else 0,
        "output_metadata_path": str(metadata_path),
        "output_metadata_bytes": metadata_path.stat().st_size
        if metadata_path.exists()
        else 0,
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_bytes": checkpoint_path.stat().st_size
        if checkpoint_path.exists()
        else 0,
        "checkpoint_metadata_path": str(checkpoint_meta_path),
        "checkpoint_metadata_bytes": checkpoint_meta_path.stat().st_size
        if checkpoint_meta_path.exists()
        else 0,
        "csv_output_path": str(csv_path) if csv_path else None,
        "parquet_batch_size": DEFAULT_BATCH_SIZE,
        "parquet_row_groups": parquet_row_groups,
        "base_endpoint_requests": output_row_count * 2,
        "actual_request_attempts": request_stats.attempts,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    os.replace(tmp_path, path)


async def async_main(args: argparse.Namespace) -> int:
    started_perf = time.perf_counter()
    started_at = utc_now_iso()
    checkpoint_path: Path = args.checkpoint_output
    parquet_path: Path = args.processed_output
    summary_path: Path = args.summary_output
    csv_path: Path | None = args.csv_output

    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)

    input_digest = file_sha256(args.input)
    checkpoint_meta_path = checkpoint_metadata_path(checkpoint_path)
    parquet_tmp_path = parquet_path.with_name(f".{parquet_path.name}.tmp")
    summary_tmp_path = summary_path.with_name(f".{summary_path.name}.tmp")

    if args.resume and args.overwrite:
        raise ValueError("--resume and --overwrite cannot be used together")
    if parquet_path.exists() and not args.overwrite:
        raise FileExistsError(f"{parquet_path} already exists. Use --overwrite.")
    if csv_path is not None and csv_path.exists() and not args.overwrite:
        raise FileExistsError(f"{csv_path} already exists. Use --overwrite.")
    if args.overwrite:
        for cleanup_path in (
            checkpoint_path,
            checkpoint_meta_path,
            parquet_tmp_path,
            summary_path,
            summary_tmp_path,
            output_metadata_path(parquet_path),
        ):
            if cleanup_path.exists():
                cleanup_path.unlink()
        if csv_path is not None and csv_path.exists():
            csv_path.unlink()
        if (
            csv_path is None
            and parquet_path == DEFAULT_PARQUET_PATH
            and DEFAULT_CSV_PATH.exists()
        ):
            DEFAULT_CSV_PATH.unlink()
            logging.info(
                "Removed stale legacy CSV during overwrite: %s", DEFAULT_CSV_PATH
            )
    if checkpoint_path.exists() and not args.resume:
        if not args.overwrite:
            raise FileExistsError(
                f"{checkpoint_path} already exists. Use --resume or --overwrite."
            )

    (
        domains,
        input_rows,
        unique_input_domains,
        skipped_count,
        duplicate_count,
        skip_reasons,
        skipped_sample,
        domain_column,
        rank_column,
        categories_column,
    ) = load_domains(args.input, args.limit, args.domain_column)
    if not domains:
        raise ValueError(f"No valid domains found in {args.input}")
    input_manifest = load_input_manifest()
    source_dataset = source_metadata_for_input(args.input, input_digest, input_manifest)

    completed: set[str] = set()
    if args.resume and checkpoint_path.exists():
        validate_checkpoint_compatibility(
            checkpoint_path, checkpoint_meta_path, input_digest=input_digest
        )
        completed = completed_domains_from_checkpoint(checkpoint_path)
        logging.info("Resume enabled. Found %s completed domains.", len(completed))
    elif args.resume:
        raise FileNotFoundError(f"{checkpoint_path} does not exist; cannot resume.")
    else:
        write_output_metadata_sidecar(
            checkpoint_meta_path,
            checkpoint_metadata(
                input_path=args.input,
                input_digest=input_digest,
                started_at=started_at,
            ),
        )

    pending = [item for item in domains if item.domain not in completed]
    logging.info(
        "Accepted %s unique domains. Pending %s. Concurrency %s. Batch size %s.",
        len(domains),
        len(pending),
        args.concurrency,
        DEFAULT_BATCH_SIZE,
    )
    timeout_config = {
        "connect": args.connect_timeout,
        "read": args.read_timeout,
        "write": args.write_timeout,
        "pool": args.pool_timeout,
    }

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
    safety_cache = HostSafetyCache()
    request_stats = RequestStats()
    stats = SummaryCounters()
    last_progress_at = time.monotonic()

    async with httpx.AsyncClient(
        follow_redirects=False,
        http2=True,
        verify=True,
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": args.user_agent, "Accept": "*/*"},
    ) as client:
        worker_count = min(args.domain_workers, len(pending)) if pending else 0
        input_queue: asyncio.Queue[DomainInput | None] = asyncio.Queue(
            maxsize=max(worker_count * 2, 1)
        )
        result_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=max(worker_count * 2, 1)
        )

        async def producer() -> None:
            for item in pending:
                await input_queue.put(item)
            for _ in range(worker_count):
                await input_queue.put(None)

        async def worker() -> None:
            while True:
                item = await input_queue.get()
                try:
                    if item is None:
                        return
                    row = await process_domain(
                        item,
                        client,
                        semaphore,
                        safety_cache,
                        request_stats,
                    )
                    await result_queue.put(row)
                finally:
                    input_queue.task_done()

        producer_task = asyncio.create_task(producer()) if pending else None
        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

        if pending:
            with open_jsonl_text(checkpoint_path, "a") as checkpoint_handle:
                for index in range(len(pending)):
                    row = await result_queue.get()
                    write_jsonl_record(checkpoint_handle, row)
                    stats.update(row)
                    result_queue.task_done()

                    now = time.monotonic()
                    if (
                        stats.processed_domains % args.log_every == 0
                        or now - last_progress_at >= args.progress_seconds
                        or index + 1 == len(pending)
                    ):
                        total_done = len(completed) + stats.processed_domains
                        logging.info(
                            "Processed %s / %s domains | llms.txt present: %s | "
                            "robots.txt present: %s | errors: %s",
                            total_done,
                            len(domains),
                            stats.llms_txt_present,
                            stats.robots_txt_present,
                            stats.domains_with_endpoint_errors,
                        )
                        last_progress_at = now

        await input_queue.join()
        await result_queue.join()
        if producer_task is not None:
            await producer_task
        await asyncio.gather(*workers)

    finished_at = utc_now_iso()
    parquet_schema_metadata = {
        "project_name": PROJECT_NAME,
        "ai_web_signals_schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "input_filename": args.input.name,
        "input_sha256": input_digest,
        "source_name": source_dataset.get("source_name", SOURCE_NAME),
        "source_url": source_dataset.get("source_url", SOURCE_URL),
        "source_license": source_dataset.get("license", SOURCE_LICENSE),
        "source_license_url": source_dataset.get("license_url", SOURCE_LICENSE_URL),
        "collection_started_at": started_at,
        "collection_finished_at": finished_at,
        "ai_policy_set_version": AI_POLICY_SET_VERSION,
        "generating_script": "collection/fetch.py",
    }
    row_count, final_counters = write_parquet_from_checkpoint(
        checkpoint_path,
        parquet_path,
        DEFAULT_BATCH_SIZE,
        metadata=parquet_schema_metadata,
    )
    if csv_path is not None:
        write_csv_from_checkpoint(checkpoint_path, csv_path)

    elapsed = time.perf_counter() - started_perf
    metadata_path = output_metadata_path(parquet_path)
    processed_metadata = build_processed_metadata(
        input_path=args.input,
        input_digest=input_digest,
        source_dataset=source_dataset,
        started_at=started_at,
        finished_at=finished_at,
        output_path=parquet_path,
        output_row_count=row_count,
        counters=final_counters,
        concurrency=args.concurrency,
        domain_workers=args.domain_workers,
        timeout_config=timeout_config,
        request_stats=request_stats,
    )
    write_output_metadata_sidecar(metadata_path, processed_metadata)
    write_summary(
        summary_path,
        input_path=args.input,
        input_sha256=input_digest,
        input_rows=input_rows,
        unique_input_domains=unique_input_domains,
        skipped_input_rows=skipped_count,
        duplicate_input_domains=duplicate_count,
        skipped_reason_counts=skip_reasons,
        skipped_sample=skipped_sample,
        counters=final_counters,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_seconds=elapsed,
        output_path=parquet_path,
        output_row_count=row_count,
        metadata_path=metadata_path,
        source_dataset=source_dataset,
        checkpoint_path=checkpoint_path,
        checkpoint_meta_path=checkpoint_meta_path,
        csv_path=csv_path,
        concurrency=args.concurrency,
        domain_workers=args.domain_workers,
        timeout_config=timeout_config,
        request_stats=request_stats,
    )

    logging.info("Wrote %s rows to %s", row_count, parquet_path)
    logging.info("Wrote compact checkpoint %s", checkpoint_path)
    if csv_path is not None:
        logging.info("Wrote opt-in CSV %s", csv_path)
    logging.info("Wrote %s", summary_path)
    logging.info(
        "Input columns: domain=%s rank=%s categories=%s",
        domain_column,
        rank_column or "(none)",
        categories_column or "(none)",
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch compact V1 /llms.txt and /robots.txt signals into Parquet. "
            "CSV and response bodies are not written by default."
        )
    )
    parser.add_argument(
        "input", type=Path, help="Path to the input CSV containing domains."
    )
    parser.add_argument(
        "--checkpoint-output",
        type=Path,
        default=DEFAULT_CHECKPOINT_PATH,
        help="Compact JSONL checkpoint used for resume; contains no response bodies.",
    )
    parser.add_argument(
        "--raw-output",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--processed-output",
        type=Path,
        default=DEFAULT_PARQUET_PATH,
        help="Primary processed Parquet output path.",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=None,
        help="Optional CSV output path. No CSV is written by default.",
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
    parser.add_argument(
        "--domain-workers",
        type=int,
        default=DEFAULT_DOMAIN_WORKERS,
        help="Number of active domain workers.",
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


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.raw_output is not None:
        args.checkpoint_output = args.raw_output
        logging.warning("--raw-output is deprecated; use --checkpoint-output.")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.domain_workers < 1:
        parser.error("--domain-workers must be at least 1")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.resume and args.overwrite:
        parser.error("--resume and --overwrite cannot be used together")
    if args.log_every < 1:
        parser.error("--log-every must be at least 1")
    if args.progress_seconds <= 0:
        parser.error("--progress-seconds must be greater than 0")
    for option, value in (
        ("--connect-timeout", args.connect_timeout),
        ("--read-timeout", args.read_timeout),
        ("--write-timeout", args.write_timeout),
        ("--pool-timeout", args.pool_timeout),
    ):
        if value <= 0:
            parser.error(f"{option} must be greater than 0")
    if not args.input.exists():
        parser.error(f"input file does not exist: {args.input}")
    if not args.input.is_file():
        parser.error(f"input path is not a file: {args.input}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        logging.warning("Interrupted. Compact checkpoint records remain resumable.")
        return 130
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
