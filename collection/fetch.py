"""Collect public AI web signals for Cloudflare Radar domain buckets."""

from __future__ import annotations

import argparse
import asyncio
import csv
import email.utils
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TextIO
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

LOGGER = logging.getLogger(__name__)

VERSION = "3.2.0"
SCHEMA_VERSION = 6
REPOSITORY_URL = "https://github.com/derailable/ai-web-signals"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collection" else SCRIPT_DIR
OUTPUT_PATH = REPO_ROOT / "data/processed/domains.csv"
CHECKPOINT_PATH = REPO_ROOT / "data/raw/domains_checkpoint.jsonl"
CHECKPOINT_META_PATH = REPO_ROOT / "data/raw/domains_checkpoint.meta.json"

USER_AGENT = f"AIWebSignals/{VERSION} (+{REPOSITORY_URL})"
DEFAULT_POPULARITY_BUCKET = 50000
DOMAIN_WORKERS = 30
REQUEST_CONCURRENCY = 40
LOG_EVERY = 500
PROGRESS_SECONDS = 30.0
REDIRECT_LIMIT = 8
LLMS_SAMPLE_LIMIT = 256 * 1024
ROBOTS_SAMPLE_LIMIT = 512 * 1024
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
RETRY_DELAYS = (1.0,)
MAX_RETRY_AFTER_SECONDS = 10.0

EndpointName = Literal["llms_txt", "robots_txt"]

LLMS_STATUSES = {
    "present",
    "absent",
    "empty",
    "html",
    "non_text",
    "http_error",
    "network_error",
}
ROBOTS_STATUSES = {
    "parsed",
    "absent",
    "empty",
    "html",
    "non_text",
    "unparseable",
    "http_error",
    "network_error",
}
POLICY_VALUES = {
    "allow_default",
    "allow_explicit",
    "allow_wildcard",
    "partial_explicit",
    "partial_wildcard",
    "blocked_explicit",
    "blocked_wildcard",
    "unknown",
}
RESTRICTED_STATES = {"none", "some", "all", "unknown"}
SCAN_STATES = {"complete", "partial", "failed"}

# First-party docs checked 2026-07-29:
# OpenAI: https://developers.openai.com/api/docs/bots
# Anthropic: https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
# Google: https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
# Apple: https://support.apple.com/en-ie/119829
# Perplexity: https://docs.perplexity.ai/docs/resources/perplexity-crawlers
# Mistral: https://docs.mistral.ai/robots
# DuckDuckGo: https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot
# Meta official crawler doc was linked from Cloudflare Radar during review:
# https://developers.facebook.com/docs/sharing/webmasters/web-crawlers
TRAINING_BOTS = [
    ("GPTBot", "gpt_bot_policy"),
    ("ClaudeBot", "claude_bot_policy"),
    ("Google-Extended", "google_extended_policy"),
    ("Applebot-Extended", "applebot_extended_policy"),
    ("meta-externalagent", "meta_external_agent_policy"),
]
SEARCH_BOTS = [
    ("OAI-SearchBot", "oai_search_bot_policy"),
    ("Claude-SearchBot", "claude_search_bot_policy"),
    ("PerplexityBot", "perplexity_bot_policy"),
    ("DuckAssistBot", "duck_assist_bot_policy"),
    ("MistralAI-Index", "mistral_ai_index_policy"),
]
USER_FETCH_BOTS = [
    ("ChatGPT-User", "chatgpt_user_policy"),
    ("Claude-User", "claude_user_policy"),
    ("Perplexity-User", "perplexity_user_policy"),
    ("MistralAI-User", "mistral_ai_user_policy"),
]
TRACKED_BOTS = TRAINING_BOTS + SEARCH_BOTS + USER_FETCH_BOTS
TRACKED_BOT_TOKENS = [token for token, _column in TRACKED_BOTS]
POLICY_COLUMNS = [column for _token, column in TRACKED_BOTS]

OUTPUT_COLUMNS = [
    "domain",
    "has_llms_txt",
    "llms_txt_status",
    "robots_txt_status",
    "has_explicit_ai_policy",
    "training_bots_restricted",
    "search_bots_restricted",
    "user_fetch_bots_restricted",
    *POLICY_COLUMNS,
    "scan_status",
]


@dataclass(frozen=True)
class DomainInput:
    popularity_bucket: int
    domain: str


@dataclass(frozen=True)
class CollectionSettings:
    workers: int = DOMAIN_WORKERS
    request_concurrency: int = REQUEST_CONCURRENCY
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 5.0
    pool_timeout: float = 5.0
    llms_sample_limit: int = LLMS_SAMPLE_LIMIT
    robots_sample_limit: int = ROBOTS_SAMPLE_LIMIT
    redirect_limit: int = REDIRECT_LIMIT

    def as_metadata(self) -> dict[str, Any]:
        return {
            "workers": self.workers,
            "request_concurrency": self.request_concurrency,
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout,
            "pool_timeout": self.pool_timeout,
            "llms_sample_limit": self.llms_sample_limit,
            "robots_sample_limit": self.robots_sample_limit,
            "redirect_limit": self.redirect_limit,
            "retryable_status_codes": sorted(RETRYABLE_STATUS_CODES),
            "retry_delays": list(RETRY_DELAYS),
            "max_retry_after_seconds": MAX_RETRY_AFTER_SECONDS,
        }


@dataclass(frozen=True)
class EndpointEvidence:
    attempted: bool
    completed: bool
    requested_scheme: str | None
    final_scheme: str | None
    http_status: int | None
    content_type: str | None
    bytes_read: int
    body_truncated: bool
    redirect_count: int
    retry_count: int
    error_type: str | None
    classification: str
    fetched_at: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "completed": self.completed,
            "requested_scheme": self.requested_scheme,
            "final_scheme": self.final_scheme,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "bytes_read": self.bytes_read,
            "body_truncated": self.body_truncated,
            "redirect_count": self.redirect_count,
            "retry_count": self.retry_count,
            "error_type": self.error_type,
            "classification": self.classification,
            "fetched_at": self.fetched_at,
        }


@dataclass(frozen=True)
class FetchResult:
    status: int | None
    content_type: str | None
    body: bytes
    error_type: str | None
    requested_scheme: str
    final_scheme: str | None
    bytes_read: int
    body_truncated: bool
    redirect_count: int
    retry_count: int


@dataclass
class RequestStats:
    attempts: int = 0
    retries: int = 0
    redirects: int = 0
    http_fallbacks: int = 0


class HostSafetyCache:
    """Bounded DNS safety cache for practical redirect target screening.

    This checks all resolved addresses before each request and reuses one task per
    host. It does not prove DNS-rebinding safety inside httpx's connection layer.
    """

    def __init__(self, max_entries: int = 50000) -> None:
        self._tasks: dict[str, asyncio.Task[str | None]] = {}
        self._max_entries = max_entries

    async def check(self, host: str) -> str | None:
        key = host.lower().rstrip(".")
        task = self._tasks.get(key)
        if task is None:
            if len(self._tasks) >= self._max_entries:
                self._tasks.pop(next(iter(self._tasks)))
            task = asyncio.create_task(asyncio.to_thread(resolve_host_safety, key))
            self._tasks[key] = task
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            if self._tasks.get(key) is task:
                self._tasks.pop(key, None)
            raise


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_csv_data_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _row in reader)


def stable_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalize_domain(raw: str) -> tuple[str | None, str | None]:
    value = raw.strip().lower().rstrip(".")
    if not value:
        return None, "empty domain"
    if "://" in value:
        return None, "contains a URL scheme"
    if any(character in value for character in "/?#"):
        return None, "contains a URL path, query, or fragment"
    if any(character.isspace() for character in value):
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
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(labels) < 2 or not all(label_pattern.fullmatch(label) for label in labels):
        return None, "contains an invalid DNS label"

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value, None
    return None, "IP addresses are not accepted"


def identify_column(fieldnames: Sequence[str], candidates: Sequence[str]) -> str | None:
    by_lowercase = {name.strip().lower(): name for name in fieldnames}
    for candidate in candidates:
        if candidate in by_lowercase:
            return by_lowercase[candidate]
    return None


def identify_domain_column(fieldnames: Sequence[str]) -> str:
    exact = identify_column(fieldnames, ("domain", "hostname", "host"))
    if exact:
        return exact
    matches = [name for name in fieldnames if "domain" in name.strip().lower()]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(
        "Could not identify the domain column. "
        f"Available columns: {', '.join(fieldnames)}"
    )


def load_domains(
    path: Path,
    limit: int | None,
    popularity_bucket: int = DEFAULT_POPULARITY_BUCKET,
) -> tuple[list[DomainInput], Counter[str]]:
    domains: list[DomainInput] = []
    skipped: Counter[str] = Counter()
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header row.")

        domain_column = identify_domain_column(reader.fieldnames)
        for row in reader:
            normalized, reason = normalize_domain(row.get(domain_column, "") or "")
            if reason:
                skipped[reason] += 1
                continue
            assert normalized is not None
            if normalized in seen:
                skipped["duplicate after normalization"] += 1
                continue
            seen.add(normalized)
            domains.append(
                DomainInput(
                    popularity_bucket=popularity_bucket,
                    domain=normalized,
                )
            )
            if limit is not None and len(domains) >= limit:
                break

    return domains, skipped


def is_forbidden_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def resolve_host_safety(host: str) -> str | None:
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        return "private_address" if is_forbidden_ip(literal) else None

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "dns_error"

    for result in results:
        try:
            address = ipaddress.ip_address(result[4][0])
        except ValueError:
            return "dns_error"
        if is_forbidden_ip(address):
            return "private_address"
    return None


async def validate_url(url: str, safety_cache: HostSafetyCache) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "invalid_url"
    if parsed.username is not None or parsed.password is not None:
        return "invalid_url"
    return await safety_cache.check(parsed.hostname)


def classify_httpx_error(error: Exception) -> str:
    if isinstance(error, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(error, httpx.ReadTimeout):
        return "read_timeout"
    if isinstance(error, httpx.WriteTimeout):
        return "write_timeout"
    if isinstance(error, httpx.PoolTimeout):
        return "pool_timeout"
    if isinstance(error, httpx.InvalidURL):
        return "invalid_url"
    if isinstance(error, httpx.TooManyRedirects):
        return "redirect_error"
    if isinstance(error, httpx.ConnectError):
        description = repr(error).lower()
        cause = error.__cause__
        if (
            isinstance(cause, ssl.SSLError)
            or "certificate" in description
            or "tls" in description
            or "ssl" in description
        ):
            return "tls_error"
        if (
            isinstance(cause, socket.gaierror)
            or "name or service not known" in description
            or "nodename nor servname" in description
        ):
            return "dns_error"
        return "connect_error"
    return "network_error"


def should_retry_exception(error: Exception) -> bool:
    return isinstance(
        error,
        (
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.PoolTimeout,
            httpx.ConnectError,
        ),
    )


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return min(float(text), MAX_RETRY_AFTER_SECONDS)
    try:
        parsed = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    seconds = (parsed - datetime.now(UTC)).total_seconds()
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


async def read_limited(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                truncated = True
                break
    finally:
        await response.aclose()
    body = b"".join(chunks)
    return body[:limit], truncated


def redacted_url(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


async def fetch_once(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    url: str,
    body_limit: int,
    settings: CollectionSettings,
) -> FetchResult:
    requested_scheme = urlparse(url).scheme
    total_redirects = 0
    total_retries = 0

    for attempt in range(len(RETRY_DELAYS) + 1):
        current_url = url
        redirects_this_attempt = 0
        retry_delay: float | None = None

        try:
            while True:
                safety_error = await validate_url(current_url, safety_cache)
                if safety_error:
                    return FetchResult(
                        None,
                        None,
                        b"",
                        safety_error,
                        requested_scheme,
                        urlparse(current_url).scheme or None,
                        0,
                        False,
                        total_redirects,
                        total_retries,
                    )

                async with semaphore:
                    stats.attempts += 1
                    request = client.build_request("GET", redacted_url(current_url))
                    response = await client.send(request, stream=True)

                if 300 <= response.status_code < 400 and response.headers.get(
                    "location"
                ):
                    location = response.headers["location"]
                    await response.aclose()
                    redirects_this_attempt += 1
                    total_redirects += 1
                    stats.redirects += 1
                    if redirects_this_attempt > settings.redirect_limit:
                        return FetchResult(
                            None,
                            None,
                            b"",
                            "redirect_error",
                            requested_scheme,
                            urlparse(current_url).scheme or None,
                            0,
                            False,
                            total_redirects,
                            total_retries,
                        )
                    current_url = urljoin(current_url, location)
                    if urlparse(current_url).scheme not in {"http", "https"}:
                        return FetchResult(
                            None,
                            None,
                            b"",
                            "unsafe_redirect",
                            requested_scheme,
                            urlparse(current_url).scheme or None,
                            0,
                            False,
                            total_redirects,
                            total_retries,
                        )
                    continue

                if response.status_code in RETRYABLE_STATUS_CODES and attempt < len(
                    RETRY_DELAYS
                ):
                    retry_after = parse_retry_after(response.headers.get("retry-after"))
                    await response.aclose()
                    total_retries += 1
                    stats.retries += 1
                    retry_delay = (
                        retry_after
                        if retry_after is not None
                        else RETRY_DELAYS[attempt] + random.uniform(0.0, 0.25)
                    )
                else:
                    body, truncated = await read_limited(response, body_limit)
                    return FetchResult(
                        response.status_code,
                        response.headers.get("content-type"),
                        body,
                        None,
                        requested_scheme,
                        urlparse(str(response.url)).scheme or None,
                        len(body),
                        truncated,
                        total_redirects,
                        total_retries,
                    )
                break

        except httpx.HTTPError as error:
            if attempt < len(RETRY_DELAYS) and should_retry_exception(error):
                total_retries += 1
                stats.retries += 1
                await asyncio.sleep(RETRY_DELAYS[attempt] + random.uniform(0.0, 0.25))
                continue
            return FetchResult(
                None,
                None,
                b"",
                classify_httpx_error(error),
                requested_scheme,
                urlparse(current_url).scheme or None,
                0,
                False,
                total_redirects,
                total_retries,
            )

        if retry_delay is not None:
            await asyncio.sleep(retry_delay)
            continue

    return FetchResult(
        None,
        None,
        b"",
        "network_error",
        requested_scheme,
        requested_scheme,
        0,
        False,
        total_redirects,
        total_retries,
    )


def should_http_fallback(result: FetchResult) -> bool:
    return result.status is None and result.error_type in {
        "connect_timeout",
        "connect_error",
        "tls_error",
    }


async def fetch_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    domain: str,
    path: str,
    body_limit: int,
    settings: CollectionSettings,
) -> FetchResult:
    https_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        stats,
        f"https://{domain}{path}",
        body_limit,
        settings,
    )
    if not should_http_fallback(https_result):
        return https_result

    stats.http_fallbacks += 1
    http_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        stats,
        f"http://{domain}{path}",
        body_limit,
        settings,
    )
    return FetchResult(
        http_result.status,
        http_result.content_type,
        http_result.body,
        http_result.error_type,
        "https",
        http_result.final_scheme,
        http_result.bytes_read,
        http_result.body_truncated,
        https_result.redirect_count + http_result.redirect_count,
        https_result.retry_count + http_result.retry_count,
    )


def looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    control_bytes = sum(1 for byte in sample if byte < 9 or 13 < byte < 32)
    return control_bytes / len(sample) < 0.02


def decode_text(data: bytes, content_type: str | None) -> str | None:
    if not looks_textual(data):
        return None
    charset: str | None = None
    if content_type:
        match = re.search(
            r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.IGNORECASE
        )
        if match:
            charset = match.group(1).lower()
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


def looks_like_html(text: str) -> bool:
    sample = text[:8192].lower()
    return bool(
        any(
            marker in sample for marker in ("<!doctype html", "<html", "<head", "<body")
        )
        or re.search(r"<(?:title|div|span|script|style|meta|form|nav|footer)\b", sample)
    )


def is_text_content_type(content_type: str | None) -> bool:
    if content_type is None:
        return True
    media_type = content_type.split(";", 1)[0].strip().lower()
    return (
        media_type.startswith("text/")
        or media_type in {"application/json", "application/xml", "application/x-ndjson"}
        or media_type.endswith(("+json", "+xml"))
    )


def is_success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def classify_llms_txt(result: FetchResult) -> str:
    if result.error_type:
        return "network_error"
    if result.status in {404, 410}:
        return "absent"
    if not is_success(result.status):
        return "http_error"
    if not result.body:
        return "empty"
    if not is_text_content_type(result.content_type):
        return "non_text"
    text = decode_text(result.body, result.content_type)
    if text is None:
        return "non_text"
    if not text.strip():
        return "empty"
    if looks_like_html(text):
        return "html"
    return "present"


def strip_robots_comment(line: str) -> str:
    escaped = False
    for index, character in enumerate(line):
        if character == "\\" and not escaped:
            escaped = True
            continue
        if character == "#" and not escaped:
            return line[:index]
        escaped = False
    return line


def parse_robots_groups(text: str) -> tuple[list[dict[str, Any]], bool]:
    groups: list[dict[str, Any]] = []
    current_agents: list[str] = []
    current_rules: list[dict[str, str]] = []
    saw_supported_field = False

    def flush() -> None:
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
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key in {"user-agent", "allow", "disallow", "sitemap"}:
            saw_supported_field = True

        if key == "user-agent":
            if current_agents and current_rules:
                flush()
            if value:
                current_agents.append(value.lower())
        elif key in {"allow", "disallow"} and current_agents:
            current_rules.append({"directive": key, "path": value})
        else:
            continue

    flush()
    return groups, saw_supported_field


def classify_selected_rules(rules: Sequence[Mapping[str, str]], provenance: str) -> str:
    allows = [
        rule.get("path", "")
        for rule in rules
        if rule.get("directive") == "allow" and rule.get("path", "").strip()
    ]
    disallows = [
        rule.get("path", "")
        for rule in rules
        if rule.get("directive") == "disallow" and rule.get("path", "").strip()
    ]
    if not disallows:
        return f"allow_{provenance}"
    if "/" in disallows and not allows:
        return f"blocked_{provenance}"
    return f"partial_{provenance}"


def classify_bot_policy(groups: Sequence[Mapping[str, Any]], bot: str) -> str:
    target = bot.lower()
    explicit_groups: list[Mapping[str, Any]] = []
    wildcard_groups: list[Mapping[str, Any]] = []

    for group in groups:
        agents = [str(agent).lower() for agent in group.get("agents", [])]
        if target in agents:
            explicit_groups.append(group)
        elif "*" in agents:
            wildcard_groups.append(group)

    if explicit_groups:
        rules = [rule for group in explicit_groups for rule in group.get("rules", [])]
        return classify_selected_rules(rules, "explicit")
    if wildcard_groups:
        rules = [rule for group in wildcard_groups for rule in group.get("rules", [])]
        return classify_selected_rules(rules, "wildcard")
    return "allow_default"


def classify_robots_txt(result: FetchResult) -> tuple[str, dict[str, str]]:
    unknown_policies = {token: "unknown" for token in TRACKED_BOT_TOKENS}
    if result.error_type:
        return "network_error", unknown_policies
    if result.status in {404, 410}:
        return "absent", {token: "allow_default" for token in TRACKED_BOT_TOKENS}
    if not is_success(result.status):
        return "http_error", unknown_policies
    if not result.body:
        return "empty", {token: "allow_default" for token in TRACKED_BOT_TOKENS}
    if not is_text_content_type(result.content_type):
        return "non_text", unknown_policies
    text = decode_text(result.body, result.content_type)
    if text is None:
        return "non_text", unknown_policies
    if looks_like_html(text):
        return "html", unknown_policies
    if not text.strip() or not any(
        strip_robots_comment(line).strip() for line in text.splitlines()
    ):
        return "empty", {token: "allow_default" for token in TRACKED_BOT_TOKENS}

    try:
        groups, saw_supported_field = parse_robots_groups(text)
    except Exception:
        LOGGER.exception("Unexpected robots parser failure")
        return "unparseable", unknown_policies

    if not saw_supported_field:
        return "unparseable", unknown_policies

    return "parsed", {
        token: classify_bot_policy(groups, token) for token in TRACKED_BOT_TOKENS
    }


def endpoint_evidence(
    result: FetchResult,
    classification: str,
    completed: bool,
) -> EndpointEvidence:
    return EndpointEvidence(
        attempted=True,
        completed=completed,
        requested_scheme=result.requested_scheme,
        final_scheme=result.final_scheme,
        http_status=result.status,
        content_type=result.content_type,
        bytes_read=result.bytes_read,
        body_truncated=result.body_truncated,
        redirect_count=result.redirect_count,
        retry_count=result.retry_count,
        error_type=result.error_type,
        classification=classification,
        fetched_at=utc_now_iso(),
    )


def missing_endpoint_evidence() -> dict[str, Any]:
    return EndpointEvidence(
        attempted=False,
        completed=False,
        requested_scheme=None,
        final_scheme=None,
        http_status=None,
        content_type=None,
        bytes_read=0,
        body_truncated=False,
        redirect_count=0,
        retry_count=0,
        error_type=None,
        classification="network_error",
        fetched_at=None,
    ).to_json()


def endpoint_is_complete(endpoint: Mapping[str, Any] | None) -> bool:
    return bool(endpoint and endpoint.get("completed") is True)


def llms_completed(classification: str) -> bool:
    return classification in {"present", "absent", "empty", "html", "non_text"}


def robots_completed(classification: str) -> bool:
    return classification in {
        "parsed",
        "absent",
        "empty",
        "html",
        "non_text",
        "unparseable",
    }


def has_llms_value(status: str) -> bool | None:
    if status == "present":
        return True
    if status in {"absent", "empty", "html", "non_text"}:
        return False
    return None


def summarize_blocking(
    policies: Mapping[str, str], bots: Sequence[tuple[str, str]]
) -> str:
    values = [policies.get(token, "unknown") for token, _column in bots]
    if any(value == "unknown" for value in values):
        return "unknown"
    restricted = sum(value.startswith(("partial_", "blocked_")) for value in values)
    if restricted == 0:
        return "none"
    if restricted == len(values):
        return "all"
    return "some"


def scan_status_from_endpoints(
    llms_endpoint: Mapping[str, Any],
    robots_endpoint: Mapping[str, Any],
) -> str:
    known_count = int(endpoint_is_complete(llms_endpoint)) + int(
        endpoint_is_complete(robots_endpoint)
    )
    if known_count == 2:
        return "complete"
    if known_count == 1:
        return "partial"
    return "failed"


def project_output_row(record: Mapping[str, Any]) -> dict[str, Any]:
    endpoints = record["endpoints"]
    llms_status = str(endpoints["llms_txt"]["classification"])
    robots_status = str(endpoints["robots_txt"]["classification"])
    policies = record.get("robots_policies") or {
        token: "unknown" for token in TRACKED_BOT_TOKENS
    }

    row: dict[str, Any] = {
        "domain": record["domain"],
        "has_llms_txt": has_llms_value(llms_status),
        "llms_txt_status": llms_status,
        "robots_txt_status": robots_status,
        "has_explicit_ai_policy": (
            any(str(value).endswith("_explicit") for value in policies.values())
            if robots_status in {"parsed", "absent", "empty"}
            else None
        ),
        "training_bots_restricted": summarize_blocking(policies, TRAINING_BOTS),
        "search_bots_restricted": summarize_blocking(policies, SEARCH_BOTS),
        "user_fetch_bots_restricted": summarize_blocking(policies, USER_FETCH_BOTS),
    }
    for token, column in TRACKED_BOTS:
        row[column] = policies.get(token, "unknown")
    row["scan_status"] = scan_status_from_endpoints(
        endpoints["llms_txt"], endpoints["robots_txt"]
    )
    return row


def build_record(
    item: DomainInput,
    endpoints: Mapping[str, Mapping[str, Any]],
    robots_policies: Mapping[str, str] | None,
) -> dict[str, Any]:
    record = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "popularity_bucket": item.popularity_bucket,
        "domain": item.domain,
        "endpoints": {
            "llms_txt": dict(endpoints.get("llms_txt") or missing_endpoint_evidence()),
            "robots_txt": dict(
                endpoints.get("robots_txt") or missing_endpoint_evidence()
            ),
        },
        "robots_policies": dict(
            robots_policies
            if robots_policies is not None
            else {token: "unknown" for token in TRACKED_BOT_TOKENS}
        ),
        "recorded_at": utc_now_iso(),
    }
    validate_checkpoint_record(record)
    return record


async def process_domain(
    item: DomainInput,
    existing: Mapping[str, Any] | None,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    settings: CollectionSettings,
) -> dict[str, Any] | None:
    existing_endpoints = dict(existing.get("endpoints", {})) if existing else {}
    endpoints: dict[str, Mapping[str, Any]] = {
        "llms_txt": existing_endpoints.get("llms_txt") or missing_endpoint_evidence(),
        "robots_txt": existing_endpoints.get("robots_txt")
        or missing_endpoint_evidence(),
    }
    robots_policies = (
        dict(existing.get("robots_policies", {}))
        if existing and existing.get("robots_policies")
        else None
    )

    tasks: dict[EndpointName, asyncio.Task[FetchResult]] = {}
    if not endpoint_is_complete(endpoints["llms_txt"]):
        tasks["llms_txt"] = asyncio.create_task(
            fetch_endpoint(
                client,
                semaphore,
                safety_cache,
                stats,
                item.domain,
                "/llms.txt",
                settings.llms_sample_limit,
                settings,
            )
        )
    if not endpoint_is_complete(endpoints["robots_txt"]):
        tasks["robots_txt"] = asyncio.create_task(
            fetch_endpoint(
                client,
                semaphore,
                safety_cache,
                stats,
                item.domain,
                "/robots.txt",
                settings.robots_sample_limit,
                settings,
            )
        )

    if not tasks:
        return None

    for name, task in tasks.items():
        try:
            result = await task
        except Exception:
            LOGGER.exception("Unexpected failure fetching %s for %s", name, item.domain)
            result = FetchResult(
                None, None, b"", "internal_error", "https", None, 0, False, 0, 0
            )

        if name == "llms_txt":
            classification = classify_llms_txt(result)
            endpoints[name] = endpoint_evidence(
                result, classification, llms_completed(classification)
            ).to_json()
        else:
            classification, robots_policies = classify_robots_txt(result)
            endpoints[name] = endpoint_evidence(
                result, classification, robots_completed(classification)
            ).to_json()

    return build_record(item, endpoints, robots_policies)


def validate_endpoint(endpoint: Mapping[str, Any], allowed_statuses: set[str]) -> None:
    required = {
        "attempted",
        "completed",
        "requested_scheme",
        "final_scheme",
        "http_status",
        "content_type",
        "bytes_read",
        "body_truncated",
        "redirect_count",
        "retry_count",
        "error_type",
        "classification",
        "fetched_at",
    }
    if set(endpoint) != required:
        raise ValueError("Checkpoint endpoint evidence does not match the schema.")
    if endpoint["classification"] not in allowed_statuses:
        raise ValueError("Checkpoint endpoint has an invalid classification.")
    for key in ("attempted", "completed", "body_truncated"):
        if not isinstance(endpoint[key], bool):
            raise TypeError(f"Checkpoint endpoint `{key}` must be boolean.")
    for key in ("bytes_read", "redirect_count", "retry_count"):
        if not isinstance(endpoint[key], int):
            raise TypeError(f"Checkpoint endpoint `{key}` must be an int.")
        if endpoint[key] < 0:
            raise ValueError(f"Checkpoint endpoint `{key}` must be non-negative.")


def validate_checkpoint_record(record: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "collector_version",
        "popularity_bucket",
        "domain",
        "endpoints",
        "robots_policies",
        "recorded_at",
    }
    if set(record) != required:
        raise ValueError("Checkpoint record does not match the schema.")
    if record["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Checkpoint record has an incompatible schema version.")
    if not isinstance(record.get("domain"), str) or not record["domain"]:
        raise ValueError("Checkpoint record has an invalid domain.")
    if record["popularity_bucket"] != DEFAULT_POPULARITY_BUCKET:
        raise ValueError("Checkpoint record has an unsupported popularity bucket.")
    endpoints = record["endpoints"]
    if not isinstance(endpoints, Mapping):
        raise TypeError("Checkpoint record endpoints must be an object.")
    validate_endpoint(endpoints.get("llms_txt", {}), LLMS_STATUSES)
    validate_endpoint(endpoints.get("robots_txt", {}), ROBOTS_STATUSES)

    policies = record["robots_policies"]
    if not isinstance(policies, Mapping) or set(policies) != set(TRACKED_BOT_TOKENS):
        raise ValueError("Checkpoint record has an invalid robots policy map.")
    invalid = set(policies.values()) - POLICY_VALUES
    if invalid:
        raise ValueError(f"Checkpoint record has invalid policy values: {invalid}")


def validate_output_row(row: Mapping[str, Any]) -> None:
    if list(row.keys()) != OUTPUT_COLUMNS:
        raise ValueError("Output row does not match the CSV schema.")
    for column, value in row.items():
        if isinstance(value, dict | list | tuple | set):
            raise TypeError(f"Output row column `{column}` contains nested data.")
    if row["llms_txt_status"] not in LLMS_STATUSES:
        raise ValueError("Output row has an invalid llms.txt status.")
    if row["robots_txt_status"] not in ROBOTS_STATUSES:
        raise ValueError("Output row has an invalid robots.txt status.")
    if row["scan_status"] not in SCAN_STATES:
        raise ValueError("Output row has an invalid scan status.")
    for column in (
        "training_bots_restricted",
        "search_bots_restricted",
        "user_fetch_bots_restricted",
    ):
        if row[column] not in RESTRICTED_STATES:
            raise ValueError(f"Output row has an invalid {column} value.")
    if row["has_llms_txt"] not in {True, False, None}:
        raise ValueError("Output row has an invalid has_llms_txt value.")
    if row["has_explicit_ai_policy"] not in {True, False, None}:
        raise ValueError("Output row has an invalid has_explicit_ai_policy value.")
    for column in POLICY_COLUMNS:
        if row[column] not in POLICY_VALUES:
            raise ValueError(f"Output row has an invalid {column} value.")


def validate_output_contract(
    domains: Sequence[DomainInput], latest_records: Mapping[str, Mapping[str, Any]]
) -> None:
    if len(set(OUTPUT_COLUMNS)) != len(OUTPUT_COLUMNS):
        raise ValueError("Output schema contains duplicate column names.")
    if any(
        not column or not re.fullmatch(r"[a-z][a-z0-9_]*", column)
        for column in OUTPUT_COLUMNS
    ):
        raise ValueError("Output schema contains invalid column names.")
    forbidden_columns = {
        "rank",
        "ranking",
        "row_rank",
        "source_rank",
        "index",
        "row_number",
        "",
    }
    if forbidden_columns & set(OUTPUT_COLUMNS):
        raise ValueError("Output schema contains an index or rank-like column.")
    if any(not column.endswith("_policy") for column in POLICY_COLUMNS):
        raise ValueError("Per-agent policy columns must end with `_policy`.")
    if len(set(POLICY_COLUMNS)) != len(POLICY_COLUMNS):
        raise ValueError("Per-agent policy columns are not unique.")

    domain_values = [item.domain for item in domains]
    if len(set(domain_values)) != len(domain_values):
        raise ValueError("Input domains contain duplicates after normalization.")
    projected_row_count = sum(1 for item in domains if item.domain in latest_records)
    if projected_row_count > len(domains):
        raise ValueError("Output row count would exceed input domain count.")


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return

    with path.open("r", encoding="utf-8") as handle:
        pending_malformed: tuple[int, str] | None = None
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if pending_malformed is not None:
                raise ValueError(
                    "Malformed checkpoint line "
                    f"{pending_malformed[0]} is not the final line."
                )
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                pending_malformed = (line_number, line)
                continue
            if not isinstance(value, dict):
                raise TypeError(f"Checkpoint line {line_number} is not a JSON object.")
            validate_checkpoint_record(value)
            yield value

        if pending_malformed is not None:
            LOGGER.warning(
                "Ignoring an incomplete final checkpoint line at line %s.",
                pending_malformed[0],
            )


def load_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in iter_jsonl(path):
        latest[str(record["domain"])] = record
    return latest


def write_checkpoint_row(handle: TextIO, record: Mapping[str, Any]) -> None:
    validate_checkpoint_record(record)
    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    handle.flush()


def taxonomy_metadata() -> list[dict[str, str]]:
    purpose_by_token = (
        {token: "training" for token, _column in TRAINING_BOTS}
        | {token: "search_or_retrieval_indexing" for token, _column in SEARCH_BOTS}
        | {token: "user_triggered_fetching" for token, _column in USER_FETCH_BOTS}
    )
    return [
        {"token": token, "column": column, "purpose": purpose_by_token[token]}
        for token, column in TRACKED_BOTS
    ]


def checkpoint_metadata(
    input_path: Path,
    input_digest: str,
    input_row_count: int,
    settings: CollectionSettings,
) -> dict[str, Any]:
    taxonomy = taxonomy_metadata()
    settings_metadata = settings.as_metadata()
    return {
        "schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "input_filename": input_path.name,
        "input_sha256": input_digest,
        "input_row_count": input_row_count,
        "source_population": "cloudflare_radar_top_50000_unordered_bucket",
        "popularity_bucket": DEFAULT_POPULARITY_BUCKET,
        "tracked_agent_taxonomy": taxonomy,
        "tracked_agent_taxonomy_digest": stable_digest(taxonomy),
        "collection_settings": settings_metadata,
        "collection_settings_digest": stable_digest(settings_metadata),
        "output_columns": OUTPUT_COLUMNS,
        "started_at": utc_now_iso(),
        "completed_at": None,
        "final_status_counts": None,
    }


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def prepare_checkpoint(
    input_path: Path,
    domains: Sequence[DomainInput],
    fresh: bool,
    settings: CollectionSettings,
) -> dict[str, dict[str, Any]]:
    input_digest = file_sha256(input_path)
    input_row_count = count_csv_data_rows(input_path)

    if fresh:
        for path in (CHECKPOINT_PATH, CHECKPOINT_META_PATH, OUTPUT_PATH):
            if path.exists():
                path.unlink()

    if CHECKPOINT_PATH.exists() != CHECKPOINT_META_PATH.exists():
        raise ValueError(
            "Checkpoint files are incomplete. Re-run with --fresh to start over."
        )

    expected_taxonomy_digest = stable_digest(taxonomy_metadata())
    expected_settings_digest = stable_digest(settings.as_metadata())

    if not CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
        CHECKPOINT_PATH.touch()
        write_json_atomic(
            CHECKPOINT_META_PATH,
            checkpoint_metadata(input_path, input_digest, input_row_count, settings),
        )
        return {}

    metadata = json.loads(CHECKPOINT_META_PATH.read_text(encoding="utf-8"))
    checks = {
        "schema version": metadata.get("schema_version") == SCHEMA_VERSION,
        "input digest": metadata.get("input_sha256") == input_digest,
        "taxonomy": metadata.get("tracked_agent_taxonomy_digest")
        == expected_taxonomy_digest,
        "collector settings": metadata.get("collection_settings_digest")
        == expected_settings_digest,
        "output columns": metadata.get("output_columns") == OUTPUT_COLUMNS,
    }
    if not all(checks.values()):
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise ValueError(
            "The checkpoint is incompatible with this run "
            f"({failed}). Re-run with --fresh to start over."
        )
    return load_checkpoint(CHECKPOINT_PATH)


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return value


def write_output_csv(
    domains: Sequence[DomainInput], latest_records: Mapping[str, Mapping[str, Any]]
) -> int:
    validate_output_contract(domains, latest_records)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_PATH.with_name(f".{OUTPUT_PATH.name}.tmp")
    count = 0

    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for item in domains:
            record = latest_records.get(item.domain)
            if record is None:
                continue
            row = project_output_row(record)
            validate_output_row(row)
            writer.writerow(
                {column: csv_value(row[column]) for column in OUTPUT_COLUMNS}
            )
            count += 1

    os.replace(temporary, OUTPUT_PATH)
    return count


def compact_checkpoint(
    domains: Sequence[DomainInput], latest_records: Mapping[str, Mapping[str, Any]]
) -> int:
    temporary = CHECKPOINT_PATH.with_name(f".{CHECKPOINT_PATH.name}.tmp")
    count = 0
    with temporary.open("w", encoding="utf-8") as handle:
        for item in domains:
            record = latest_records.get(item.domain)
            if record is None:
                continue
            write_checkpoint_row(handle, record)
            count += 1
    os.replace(temporary, CHECKPOINT_PATH)
    return count


def update_completion_metadata(final_counts: Mapping[str, int]) -> None:
    metadata = json.loads(CHECKPOINT_META_PATH.read_text(encoding="utf-8"))
    metadata["completed_at"] = utc_now_iso()
    metadata["final_status_counts"] = dict(final_counts)
    write_json_atomic(CHECKPOINT_META_PATH, metadata)


def mark_collection_started() -> None:
    metadata = json.loads(CHECKPOINT_META_PATH.read_text(encoding="utf-8"))
    metadata["started_at"] = utc_now_iso()
    metadata["completed_at"] = None
    metadata["final_status_counts"] = None
    write_json_atomic(CHECKPOINT_META_PATH, metadata)


def record_fully_complete(record: Mapping[str, Any] | None) -> bool:
    if not record:
        return False
    endpoints = record.get("endpoints", {})
    return endpoint_is_complete(endpoints.get("llms_txt")) and endpoint_is_complete(
        endpoints.get("robots_txt")
    )


async def collect(
    input_path: Path,
    domains: Sequence[DomainInput],
    fresh: bool,
    settings: CollectionSettings,
) -> int:
    started = time.perf_counter()
    latest_records = prepare_checkpoint(input_path, domains, fresh, settings)
    mark_collection_started()
    pending = [
        item
        for item in domains
        if not record_fully_complete(latest_records.get(item.domain))
    ]

    LOGGER.info(
        "Loaded %s domains. %s fully complete, %s pending or partial.",
        len(domains),
        len(domains) - len(pending),
        len(pending),
    )

    stats = RequestStats()
    processed_this_run = 0
    status_counts: Counter[str] = Counter()
    endpoint_counts: Counter[str] = Counter()
    last_progress = time.monotonic()

    if pending:
        timeout = httpx.Timeout(
            connect=settings.connect_timeout,
            read=settings.read_timeout,
            write=settings.write_timeout,
            pool=settings.pool_timeout,
        )
        limits = httpx.Limits(
            max_connections=max(settings.request_concurrency * 2, 60),
            max_keepalive_connections=max(settings.request_concurrency, 30),
        )
        semaphore = asyncio.Semaphore(settings.request_concurrency)
        safety_cache = HostSafetyCache()

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            limits=limits,
            verify=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/plain,text/markdown,*/*;q=0.1",
            },
        ) as client:
            worker_count = min(settings.workers, len(pending))
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
                        try:
                            record = await process_domain(
                                item,
                                latest_records.get(item.domain),
                                client,
                                semaphore,
                                safety_cache,
                                stats,
                                settings,
                            )
                            if record is not None:
                                await result_queue.put(record)
                        except Exception:
                            LOGGER.exception(
                                "Unexpected failure scanning %s", item.domain
                            )
                            await result_queue.put(
                                build_record(
                                    item,
                                    {
                                        "llms_txt": missing_endpoint_evidence(),
                                        "robots_txt": missing_endpoint_evidence(),
                                    },
                                    None,
                                )
                            )
                    finally:
                        input_queue.task_done()

            producer_task = asyncio.create_task(producer())
            workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

            with CHECKPOINT_PATH.open("a", encoding="utf-8") as checkpoint:
                for _ in range(len(pending)):
                    record = await result_queue.get()
                    try:
                        write_checkpoint_row(checkpoint, record)
                        latest_records[str(record["domain"])] = record
                        processed_this_run += 1
                        row = project_output_row(record)
                        status_counts[str(row["scan_status"])] += 1
                        endpoint_counts[f"llms:{row['llms_txt_status']}"] += 1
                        endpoint_counts[f"robots:{row['robots_txt_status']}"] += 1
                    finally:
                        result_queue.task_done()

                    now = time.monotonic()
                    if (
                        processed_this_run % LOG_EVERY == 0
                        or now - last_progress >= PROGRESS_SECONDS
                        or processed_this_run == len(pending)
                    ):
                        rate = processed_this_run / max(
                            time.perf_counter() - started, 0.1
                        )
                        LOGGER.info(
                            "Processed %s / %s pending | complete=%s partial=%s "
                            "failed=%s | retries=%s | %.2f domains/s",
                            processed_this_run,
                            len(pending),
                            status_counts["complete"],
                            status_counts["partial"],
                            status_counts["failed"],
                            stats.retries,
                            rate,
                        )
                        last_progress = now

            await input_queue.join()
            await result_queue.join()
            await producer_task
            await asyncio.gather(*workers)

    row_count = write_output_csv(domains, latest_records)
    final_counts = Counter(
        str(project_output_row(latest_records[item.domain])["scan_status"])
        for item in domains
        if item.domain in latest_records
    )
    compacted = compact_checkpoint(domains, latest_records)
    update_completion_metadata(final_counts)

    LOGGER.info("Wrote %s rows to %s", row_count, OUTPUT_PATH)
    LOGGER.info("Compacted %s checkpoint records at %s", compacted, CHECKPOINT_PATH)
    LOGGER.info(
        "Final scan status: complete=%s partial=%s failed=%s",
        final_counts["complete"],
        final_counts["partial"],
        final_counts["failed"],
    )
    LOGGER.info(
        "HTTP attempts=%s retries=%s redirects=%s fallbacks=%s elapsed=%.1fs",
        stats.attempts,
        stats.retries,
        stats.redirects,
        stats.http_fallbacks,
        time.perf_counter() - started,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan Cloudflare Radar bucket domains for llms.txt and declared "
            "AI crawler policy signals. Writes data/processed/domains.csv and "
            "resumes automatically."
        )
    )
    parser.add_argument(
        "input", type=Path, help="Input CSV containing a domain column."
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Scan only the first N valid domains. Useful for testing.",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Discard the existing checkpoint and start over.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DOMAIN_WORKERS,
        help=f"Concurrent domain workers. Default: {DOMAIN_WORKERS}.",
    )
    parser.add_argument(
        "--request-concurrency",
        type=int,
        default=REQUEST_CONCURRENCY,
        help=f"Maximum concurrent HTTP requests. Default: {REQUEST_CONCURRENCY}.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="HTTP connect timeout in seconds. Default: 5.0.",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=10.0,
        help="HTTP read timeout in seconds. Default: 10.0.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.request_concurrency < 1:
        parser.error("--request-concurrency must be at least 1")
    if args.connect_timeout <= 0 or args.read_timeout <= 0:
        parser.error("--connect-timeout and --read-timeout must be positive")

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        domains, skipped = load_domains(args.input, args.limit)
        if not domains:
            raise ValueError(f"No valid domains found in {args.input}")
        if skipped:
            LOGGER.info(
                "Skipped %s input rows: %s",
                sum(skipped.values()),
                ", ".join(f"{reason}={count}" for reason, count in skipped.items()),
            )

        settings = CollectionSettings(
            workers=args.workers,
            request_concurrency=args.request_concurrency,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
        )
        return asyncio.run(collect(args.input.resolve(), domains, args.fresh, settings))
    except KeyboardInterrupt:
        LOGGER.warning("Interrupted. Re-run the command to resume.")
        return 130
    except Exception:
        LOGGER.exception("Fatal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
