"""Collect public AI web signals for the Tranco Top 100,000 domains."""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import logging
import os
import re
import socket
import ssl
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from h2.exceptions import ProtocolError as H2ProtocolError

LOGGER = logging.getLogger(__name__)

VERSION = "3.4.1"
REPOSITORY_URL = "https://github.com/derailable/ai-web-signals"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collection" else SCRIPT_DIR
OUTPUT_PATH = REPO_ROOT / "data/processed/domains.csv"
DEFAULT_INPUT_PATH = REPO_ROOT / "data/input/tranco-top-100000.csv"

USER_AGENT = f"AIWebSignals/{VERSION} (+{REPOSITORY_URL})"
TRANCO_SCAN_SCOPE = 100000
DOMAIN_WORKERS = 50
REQUEST_CONCURRENCY = 50
PROGRESS_SECONDS = 300.0
REDIRECT_LIMIT = 4
LLMS_SAMPLE_LIMIT = 256 * 1024
ROBOTS_SAMPLE_LIMIT = 512 * 1024
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
WRITE_TIMEOUT = 3.0
POOL_TIMEOUT = 3.0
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
HTML_MARKUP_RE = re.compile(
    r"<(?:title|div|span|script|style|meta|form|nav|footer)\b"
)

# First-party docs checked 2026-07-29:
# OpenAI: https://developers.openai.com/api/docs/bots
# Anthropic: https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
# Google: https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
# Apple: https://support.apple.com/en-ie/119829
# Perplexity: https://docs.perplexity.ai/docs/resources/perplexity-crawlers
# Mistral: https://docs.mistral.ai/robots
# DuckDuckGo: https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot
# Meta official crawler documentation checked during review:
# https://developers.facebook.com/docs/sharing/webmasters/web-crawlers
TRAINING_BOTS = (
    "GPTBot",
    "ClaudeBot",
    "Google-Extended",
    "Applebot-Extended",
    "meta-externalagent",
)
SEARCH_BOTS = (
    "OAI-SearchBot",
    "Claude-SearchBot",
    "PerplexityBot",
    "DuckAssistBot",
    "MistralAI-Index",
)
USER_FETCH_BOTS = (
    "ChatGPT-User",
    "Claude-User",
    "Perplexity-User",
    "MistralAI-User",
)
BOT_GROUPS = {
    "training_bots_restricted": TRAINING_BOTS,
    "search_bots_restricted": SEARCH_BOTS,
    "user_fetch_bots_restricted": USER_FETCH_BOTS,
}
TRACKED_BOT_TOKENS = [
    token for group_tokens in BOT_GROUPS.values() for token in group_tokens
]
UNKNOWN_ROBOTS_POLICIES = {token: "unknown" for token in TRACKED_BOT_TOKENS}
ALLOW_DEFAULT_ROBOTS_POLICIES = {
    token: "allow_default" for token in TRACKED_BOT_TOKENS
}

OUTPUT_COLUMNS = [
    "rank",
    "domain",
    "has_llms_txt",
    "llms_txt_status",
    "robots_txt_status",
    "has_explicit_ai_policy",
    "any_ai_bot_restricted",
    "training_bots_restricted",
    "search_bots_restricted",
    "user_fetch_bots_restricted",
    "scan_status",
]


@dataclass(frozen=True)
class DomainInput:
    rank: int
    domain: str


@dataclass(frozen=True)
class FetchResult:
    status: int | None
    content_type: str | None
    body: bytes
    error_type: str | None


@dataclass
class RequestStats:
    attempts: int = 0
    redirects: int = 0
    http_fallbacks: int = 0
    http_fallback_recoveries: int = 0
    request_durations: list[float] = field(default_factory=list)
    endpoint_statuses: Counter[str] = field(default_factory=Counter)
    endpoint_error_reasons: Counter[str] = field(default_factory=Counter)


class HostSafetyCache:
    """Bounded DNS safety cache for practical redirect target screening.

    This checks all resolved addresses before each request and caches completed
    results. It does not prove DNS-rebinding safety inside httpx's connection
    layer.
    """

    def __init__(self, max_entries: int = TRANCO_SCAN_SCOPE) -> None:
        self._results: dict[str, str | None] = {}
        self._tasks: dict[str, asyncio.Task[str | None]] = {}
        self._max_entries = max_entries

    def _evict_one(self) -> None:
        if self._results:
            self._results.pop(next(iter(self._results)))
        elif self._tasks:
            self._tasks.pop(next(iter(self._tasks)))

    async def check(self, host: str) -> str | None:
        key = host.lower().rstrip(".")
        if key in self._results:
            return self._results[key]

        task = self._tasks.get(key)
        if task is None:
            if len(self._results) + len(self._tasks) >= self._max_entries:
                self._evict_one()
            task = asyncio.create_task(asyncio.to_thread(resolve_host_safety, key))
            self._tasks[key] = task
        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            if self._tasks.get(key) is task:
                self._tasks.pop(key, None)
            raise
        if self._tasks.get(key) is task:
            self._tasks.pop(key, None)
            if len(self._results) + len(self._tasks) >= self._max_entries:
                self._evict_one()
            self._results[key] = result
        return result


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
    if len(labels) < 2 or not all(
        DOMAIN_LABEL_RE.fullmatch(label) for label in labels
    ):
        return None, "contains an invalid DNS label"

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value, None
    return None, "IP addresses are not accepted"


def parse_rank(raw: str, row_number: int) -> int:
    value = raw.strip()
    if not value or not value.isdecimal():
        raise ValueError(f"Input row {row_number} has a non-numeric rank.")
    rank = int(value)
    if rank < 1:
        raise ValueError(f"Input row {row_number} has a rank below 1.")
    return rank


def load_domains(
    path: Path, expected_count: int = TRANCO_SCAN_SCOPE
) -> list[DomainInput]:
    domains: list[DomainInput] = []
    seen_domains: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header row.")
        if reader.fieldnames != ["rank", "domain"]:
            raise ValueError(
                "Input CSV must have exactly these columns in order: rank,domain."
            )

        for row_number, row in enumerate(reader, start=2):
            rank = parse_rank(row.get("rank", "") or "", row_number)
            expected_rank = len(domains) + 1
            if rank != expected_rank:
                raise ValueError(
                    f"Input row {row_number} has rank {rank}; "
                    f"expected {expected_rank}."
                )

            normalized, reason = normalize_domain(row.get("domain", "") or "")
            if reason:
                raise ValueError(f"Input row {row_number} has invalid domain: {reason}.")
            assert normalized is not None
            if normalized in seen_domains:
                raise ValueError(f"Input contains duplicate domain {normalized}.")
            seen_domains.add(normalized)
            domains.append(DomainInput(rank=rank, domain=normalized))

    if len(domains) != expected_count:
        raise ValueError(
            f"Input CSV must contain exactly {expected_count} data rows; "
            f"found {len(domains)}."
        )
    return domains


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
    if isinstance(error, H2ProtocolError):
        return "protocol_error"
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
    if isinstance(error, httpx.RemoteProtocolError):
        return "protocol_error"
    if isinstance(error, httpx.ConnectError):
        description = repr(error).lower()
        causes: list[BaseException] = []
        cause = error.__cause__
        while cause is not None:
            causes.append(cause)
            cause = cause.__cause__
        if (
            any(isinstance(cause, ssl.SSLError) for cause in causes)
            or "certificate" in description
            or "tls" in description
            or "ssl" in description
        ):
            return "tls_error"
        if (
            any(isinstance(cause, socket.gaierror) for cause in causes)
            or "name or service not known" in description
            or "nodename nor servname" in description
        ):
            return "dns_error"
        if any(isinstance(cause, ConnectionRefusedError) for cause in causes) or (
            "connection refused" in description
        ):
            return "connection_refused"
        if any(isinstance(cause, ConnectionResetError) for cause in causes) or (
            "connection reset" in description
        ):
            return "connection_reset"
        return "other_network_error"
    return "other_network_error"


async def read_limited(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                break
    finally:
        await response.aclose()
    body = b"".join(chunks)
    return body[:limit]


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
) -> FetchResult:
    current_url = url
    redirects = 0

    try:
        while True:
            safety_error = await validate_url(current_url, safety_cache)
            if safety_error:
                return FetchResult(None, None, b"", safety_error)

            async with semaphore:
                stats.attempts += 1
                attempt_started = time.perf_counter()
                request = client.build_request("GET", redacted_url(current_url))
                try:
                    response = await client.send(request, stream=True)

                    if 300 <= response.status_code < 400 and response.headers.get(
                        "location"
                    ):
                        location = response.headers["location"]
                        await response.aclose()
                        redirects += 1
                        stats.redirects += 1
                        if redirects > REDIRECT_LIMIT:
                            return FetchResult(None, None, b"", "redirect_error")
                        current_url = urljoin(current_url, location)
                        if urlparse(current_url).scheme not in {"http", "https"}:
                            return FetchResult(None, None, b"", "unsafe_redirect")
                        continue

                    body = await read_limited(response, body_limit)
                    return FetchResult(
                        response.status_code,
                        response.headers.get("content-type"),
                        body,
                        None,
                    )
                finally:
                    stats.request_durations.append(time.perf_counter() - attempt_started)

    except (httpx.HTTPError, H2ProtocolError) as error:
        return FetchResult(None, None, b"", classify_httpx_error(error))

    return FetchResult(None, None, b"", "other_network_error")


def should_http_fallback(result: FetchResult) -> bool:
    return result.status is None and result.error_type in {
        "connect_timeout",
        "connection_refused",
        "connection_reset",
        "other_network_error",
        "protocol_error",
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
) -> FetchResult:
    https_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        stats,
        f"https://{domain}{path}",
        body_limit,
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
    )
    if http_result.status is not None:
        stats.http_fallback_recoveries += 1
    return http_result


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
        match = CHARSET_RE.search(content_type)
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
        or HTML_MARKUP_RE.search(sample)
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
    if result.error_type:
        return "network_error", UNKNOWN_ROBOTS_POLICIES
    if result.status in {404, 410}:
        return "absent", ALLOW_DEFAULT_ROBOTS_POLICIES
    if not is_success(result.status):
        return "http_error", UNKNOWN_ROBOTS_POLICIES
    if not result.body:
        return "empty", ALLOW_DEFAULT_ROBOTS_POLICIES
    if not is_text_content_type(result.content_type):
        return "non_text", UNKNOWN_ROBOTS_POLICIES
    text = decode_text(result.body, result.content_type)
    if text is None:
        return "non_text", UNKNOWN_ROBOTS_POLICIES
    if looks_like_html(text):
        return "html", UNKNOWN_ROBOTS_POLICIES
    if not text.strip() or not any(
        strip_robots_comment(line).strip() for line in text.splitlines()
    ):
        return "empty", ALLOW_DEFAULT_ROBOTS_POLICIES

    try:
        groups, saw_supported_field = parse_robots_groups(text)
    except Exception:
        return "unparseable", UNKNOWN_ROBOTS_POLICIES

    if not saw_supported_field:
        return "unparseable", UNKNOWN_ROBOTS_POLICIES

    return "parsed", {
        token: classify_bot_policy(groups, token) for token in TRACKED_BOT_TOKENS
    }


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


def policy_is_restricted(policy: str) -> bool:
    return policy.startswith(("partial_", "blocked_"))


def summarize_blocking(policies: Mapping[str, str], bots: Sequence[str]) -> str:
    values = [policies.get(token, "unknown") for token in bots]
    if any(value == "unknown" for value in values):
        return "unknown"
    restricted = sum(policy_is_restricted(value) for value in values)
    if restricted == 0:
        return "none"
    if restricted == len(values):
        return "all"
    return "some"


def any_ai_bot_restricted_value(
    robots_status: str, policies: Mapping[str, str]
) -> bool | None:
    if robots_status not in {"parsed", "absent", "empty"}:
        return None
    values = [policies.get(token, "unknown") for token in TRACKED_BOT_TOKENS]
    if any(value == "unknown" for value in values):
        return None
    return any(policy_is_restricted(value) for value in values)


def has_explicit_ai_policy_value(
    robots_status: str, policies: Mapping[str, str]
) -> bool | None:
    if robots_status not in {"parsed", "absent", "empty"}:
        return None
    values = [policies.get(token, "unknown") for token in TRACKED_BOT_TOKENS]
    if any(value == "unknown" for value in values):
        return None
    return any(value.endswith("_explicit") for value in values)


def scan_status_from_statuses(llms_status: str, robots_status: str) -> str:
    known_count = int(llms_completed(llms_status)) + int(
        robots_completed(robots_status)
    )
    if known_count == 2:
        return "complete"
    if known_count == 1:
        return "partial"
    return "failed"


def build_output_row(
    rank: int,
    domain: str,
    llms_status: str,
    robots_status: str,
    robots_policies: Mapping[str, str] | None,
) -> dict[str, Any]:
    policies = robots_policies or {token: "unknown" for token in TRACKED_BOT_TOKENS}
    row: dict[str, Any] = {
        "rank": rank,
        "domain": domain,
        "has_llms_txt": has_llms_value(llms_status),
        "llms_txt_status": llms_status,
        "robots_txt_status": robots_status,
        "has_explicit_ai_policy": has_explicit_ai_policy_value(
            robots_status, policies
        ),
        "any_ai_bot_restricted": any_ai_bot_restricted_value(
            robots_status, policies
        ),
        **{
            column: summarize_blocking(policies, bots)
            for column, bots in BOT_GROUPS.items()
        },
    }
    row["scan_status"] = scan_status_from_statuses(llms_status, robots_status)
    return row


async def process_domain(
    item: DomainInput,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
) -> dict[str, Any]:
    llms_result, robots_result = await asyncio.gather(
        fetch_endpoint(
            client,
            semaphore,
            safety_cache,
            stats,
            item.domain,
            "/llms.txt",
            LLMS_SAMPLE_LIMIT,
        ),
        fetch_endpoint(
            client,
            semaphore,
            safety_cache,
            stats,
            item.domain,
            "/robots.txt",
            ROBOTS_SAMPLE_LIMIT,
        ),
        return_exceptions=True,
    )
    if isinstance(llms_result, Exception):
        llms_result = FetchResult(None, None, b"", "internal_error")
    if isinstance(robots_result, Exception):
        robots_result = FetchResult(None, None, b"", "internal_error")

    llms_status = classify_llms_txt(llms_result)
    robots_status, robots_policies = classify_robots_txt(robots_result)
    stats.endpoint_statuses[f"llms_txt:{llms_status}"] += 1
    stats.endpoint_statuses[f"robots_txt:{robots_status}"] += 1
    if llms_result.error_type:
        stats.endpoint_error_reasons[f"llms_txt:{llms_result.error_type}"] += 1
    if robots_result.error_type:
        stats.endpoint_error_reasons[f"robots_txt:{robots_result.error_type}"] += 1

    return build_output_row(
        item.rank, item.domain, llms_status, robots_status, robots_policies
    )


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return value


def write_output_csv(
    domains: Sequence[DomainInput], latest_rows: Mapping[str, Mapping[str, Any]]
) -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_PATH.with_name(f".{OUTPUT_PATH.name}.tmp")
    count = 0

    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for item in domains:
            row = latest_rows.get(item.domain)
            if row is None:
                continue
            # Keep the CSV contract explicit for downstream readr/tidyverse loading.
            writer.writerow(
                {column: csv_value(row[column]) for column in OUTPUT_COLUMNS}
            )
            count += 1

    os.replace(temporary, OUTPUT_PATH)
    return count


def percentile(values: Sequence[float], quantile: float) -> float | None:
    if not values:
        return None
    sorted_values = sorted(values)
    index = min(
        len(sorted_values) - 1,
        max(0, round((len(sorted_values) - 1) * quantile)),
    )
    return sorted_values[index]


def log_scan_summary(stats: RequestStats) -> None:
    median_duration = percentile(stats.request_durations, 0.50)
    p95_duration = percentile(stats.request_durations, 0.95)
    LOGGER.info(
        "HTTP attempts=%s redirects=%s http_fallbacks=%s "
        "http_fallback_recoveries=%s",
        stats.attempts,
        stats.redirects,
        stats.http_fallbacks,
        stats.http_fallback_recoveries,
    )
    if median_duration is not None and p95_duration is not None:
        LOGGER.info(
            "Request duration median=%.3fs p95=%.3fs",
            median_duration,
            p95_duration,
        )
    if stats.endpoint_statuses:
        LOGGER.info("Endpoint statuses: %s", dict(stats.endpoint_statuses.most_common()))
    if stats.endpoint_error_reasons:
        LOGGER.info(
            "Network error reasons: %s",
            dict(stats.endpoint_error_reasons.most_common()),
        )


async def collect(
    domains: Sequence[DomainInput],
) -> int:
    started = time.perf_counter()
    latest_rows: dict[str, dict[str, Any]] = {}
    pending = list(domains)

    stats = RequestStats()
    processed_this_run = 0
    last_progress = time.monotonic()
    last_progress_processed = 0

    if pending:
        timeout = httpx.Timeout(
            connect=CONNECT_TIMEOUT,
            read=READ_TIMEOUT,
            write=WRITE_TIMEOUT,
            pool=POOL_TIMEOUT,
        )
        limits = httpx.Limits(
            max_connections=max(REQUEST_CONCURRENCY * 2, 60),
            max_keepalive_connections=max(REQUEST_CONCURRENCY, 30),
        )
        semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)
        safety_cache = HostSafetyCache()

        async with httpx.AsyncClient(
            follow_redirects=False,
            http2=True,
            timeout=timeout,
            limits=limits,
            verify=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/plain,text/markdown,*/*;q=0.1",
            },
        ) as client:
            worker_count = min(DOMAIN_WORKERS, len(pending))
            input_queue: asyncio.Queue[DomainInput | None] = asyncio.Queue(
                maxsize=max(worker_count * 2, 1)
            )

            async def producer() -> None:
                for item in pending:
                    await input_queue.put(item)
                for _ in range(worker_count):
                    await input_queue.put(None)

            async def worker() -> None:
                nonlocal last_progress, last_progress_processed, processed_this_run
                while True:
                    item = await input_queue.get()
                    try:
                        if item is None:
                            return
                        try:
                            row = await process_domain(
                                item,
                                client,
                                semaphore,
                                safety_cache,
                                stats,
                            )
                        except Exception:
                            row = build_output_row(
                                item.rank,
                                item.domain,
                                "network_error",
                                "network_error",
                                None,
                            )
                        latest_rows[str(row["domain"])] = row
                        processed_this_run += 1

                        now = time.monotonic()
                        if now - last_progress >= PROGRESS_SECONDS:
                            rate = processed_this_run / max(
                                time.perf_counter() - started, 0.1
                            )
                            interval_elapsed = max(now - last_progress, 0.1)
                            interval_processed = (
                                processed_this_run - last_progress_processed
                            )
                            interval_rate = interval_processed / interval_elapsed
                            LOGGER.info(
                                "Processed %s / %s pending | "
                                "%.2f recent domains/s | %.2f avg domains/s",
                                processed_this_run,
                                len(pending),
                                interval_rate,
                                rate,
                            )
                            last_progress = now
                            last_progress_processed = processed_this_run
                    finally:
                        input_queue.task_done()

            producer_task = asyncio.create_task(producer())
            workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

            await input_queue.join()
            await producer_task
            await asyncio.gather(*workers)

    write_output_csv(domains, latest_rows)
    log_scan_summary(stats)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) > 1:
        print(f"Usage: {Path(sys.argv[0]).name} [INPUT]", file=sys.stderr)
        return 2

    input_path = Path(arguments[0]) if arguments else DEFAULT_INPUT_PATH
    if not input_path.is_file():
        print(f"input file does not exist: {input_path}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        domains = load_domains(input_path)
        if not domains:
            raise ValueError(f"No valid domains found in {input_path}")
        return asyncio.run(collect(domains))
    except KeyboardInterrupt:
        LOGGER.warning("Interrupted. Re-run the command to start a fresh collection.")
        return 130
    except Exception:
        LOGGER.exception("Fatal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
