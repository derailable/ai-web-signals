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
from random import Random
from typing import Any
from urllib.parse import ParseResult, urljoin, urlparse

import httpx
from h2.exceptions import ProtocolError as H2ProtocolError

LOGGER = logging.getLogger(__name__)

VERSION = "3.4.1"
REPOSITORY_URL = "https://github.com/derailable/ai-web-signals"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collection" else SCRIPT_DIR
OUTPUT_PATH = REPO_ROOT / "data/processed/domains.csv"
AGENT_POLICIES_OUTPUT_PATH = REPO_ROOT / "data/processed/agent-policies.csv"
DEFAULT_INPUT_PATH = REPO_ROOT / "data/input/tranco-top-100000.csv"

USER_AGENT = f"AIWebSignals/{VERSION} (+{REPOSITORY_URL})"
TRANCO_SCAN_SCOPE = 100000
DOMAIN_WORKERS = 50
REQUEST_CONCURRENCY = 50
MAX_KEEPALIVE_CONNECTIONS = 20
KEEPALIVE_EXPIRY = 10.0
DNS_CACHE_MAX_ENTRIES = 10_000
MAX_PENDING_OUTPUT_ROWS = 500
PROGRESS_SECONDS = 60.0
REDIRECT_LIMIT = 4
REQUEST_DURATION_SAMPLE_LIMIT = 20_000
LLMS_SAMPLE_LIMIT = 256 * 1024
ROBOTS_SAMPLE_LIMIT = 512 * 1024
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
WRITE_TIMEOUT = 3.0
POOL_TIMEOUT = 3.0
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
HTML_MARKUP_RE = re.compile(r"<(?:title|div|span|script|style|meta|form|nav|footer)\b")
CONTENT_SIGNAL_ASSIGNMENT_RE = re.compile(
    r"^([a-z][a-z0-9-]*)\s*=\s*([a-z]+)$", re.IGNORECASE
)
CONTENT_SIGNAL_MENTION_RE = re.compile(
    r"(?:^|\s)(search|ai-input|ai-train)\s*(?==|$)", re.IGNORECASE
)

# First-party docs checked 2026-08-16:
# OpenAI: https://developers.openai.com/api/docs/bots
# Anthropic: https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
# Google: https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
# Apple: https://support.apple.com/en-ie/119829
# Perplexity: https://docs.perplexity.ai/docs/resources/perplexity-crawlers
# Mistral: https://docs.mistral.ai/robots
# DuckDuckGo: https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot
# Content Signals: https://contentsignals.org/
# Meta official crawler documentation checked during review:
# https://developers.facebook.com/docs/sharing/webmasters/web-crawlers
TRAINING_BOTS = (
    "GPTBot",
    "ClaudeBot",
    "Google-Extended",
    "Applebot-Extended",
    "meta-externalagent",
    "MistralAI-Training",
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
PURPOSE_GROUPS = {
    "training": TRAINING_BOTS,
    "search": SEARCH_BOTS,
    "user_fetch": USER_FETCH_BOTS,
}
TRACKED_BOT_TOKENS = [
    token for group_tokens in PURPOSE_GROUPS.values() for token in group_tokens
]
AGENT_PURPOSE_GROUPS = {
    token: purpose_group
    for purpose_group, group_tokens in PURPOSE_GROUPS.items()
    for token in group_tokens
}
UNKNOWN_ROBOTS_POLICIES = {token: "unknown" for token in TRACKED_BOT_TOKENS}
ALLOW_DEFAULT_ROBOTS_POLICIES = {token: "allow_default" for token in TRACKED_BOT_TOKENS}
ROBOTS_POLICY_VALUES = {
    "allow_default",
    "allow_explicit",
    "allow_wildcard",
    "partial_explicit",
    "partial_wildcard",
    "blocked_explicit",
    "blocked_wildcard",
    "unknown",
}

CONTENT_SIGNAL_PURPOSES = ("search", "ai-input", "ai-train")
CONTENT_SIGNAL_VALUES = {"yes", "no", "unspecified", "invalid", "unknown"}
UNSPECIFIED_CONTENT_SIGNALS = {
    purpose: "unspecified" for purpose in CONTENT_SIGNAL_PURPOSES
}
UNKNOWN_CONTENT_SIGNALS = {purpose: "unknown" for purpose in CONTENT_SIGNAL_PURPOSES}

OUTPUT_COLUMNS = [
    "rank",
    "domain",
    "has_llms_txt",
    "llms_txt_status",
    "robots_txt_status",
    "content_signal_search",
    "content_signal_ai_input",
    "content_signal_ai_train",
    "has_explicit_ai_policy",
    "any_ai_bot_restricted",
    "training_bots_restricted",
    "search_bots_restricted",
    "user_fetch_bots_restricted",
    "scan_status",
]

AGENT_POLICY_COLUMNS = ["rank", "domain", "agent", "purpose_group", "policy"]

LLMS_STATUS_VALUES = {
    "present",
    "absent",
    "empty",
    "html",
    "non_text",
    "http_error",
    "network_error",
}
ROBOTS_STATUS_VALUES = {
    "parsed",
    "absent",
    "empty",
    "html",
    "non_text",
    "unparseable",
    "http_error",
    "network_error",
}
GROUPED_RESTRICTION_VALUES = {"none", "some", "all", "unknown"}
SCAN_STATUS_VALUES = {"complete", "partial", "failed"}


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


@dataclass(frozen=True)
class ProcessedDomain:
    domain_row: Mapping[str, Any]
    agent_policies: Mapping[str, str]


@dataclass
class RequestStats:
    attempts: int = 0
    redirects: int = 0
    http_fallbacks: int = 0
    http_fallback_recoveries: int = 0
    request_durations: list[float] = field(default_factory=list)
    request_duration_count: int = 0
    duration_random: Random = field(default_factory=lambda: Random(0))
    endpoint_statuses: Counter[str] = field(default_factory=Counter)
    endpoint_error_reasons: Counter[str] = field(default_factory=Counter)

    def record_duration(self, duration: float) -> None:
        self.request_duration_count += 1
        if len(self.request_durations) < REQUEST_DURATION_SAMPLE_LIMIT:
            self.request_durations.append(duration)
            return
        index = self.duration_random.randrange(self.request_duration_count)
        if index < REQUEST_DURATION_SAMPLE_LIMIT:
            self.request_durations[index] = duration


@dataclass
class ProgressStats:
    total: int
    started: float = field(default_factory=time.perf_counter)
    last_report: float = field(default_factory=time.monotonic)
    processed_at_last_report: int = 0
    processed: int = 0
    complete: int = 0
    partial: int = 0
    failed: int = 0

    def record_row(self, row: Mapping[str, Any]) -> None:
        self.processed += 1
        status = row["scan_status"]
        if status == "complete":
            self.complete += 1
        elif status == "partial":
            self.partial += 1
        else:
            self.failed += 1


class HostSafetyCache:
    """Bounded DNS safety cache for practical redirect target screening.

    This checks all resolved addresses before each request and caches completed
    results. It does not prove DNS-rebinding safety inside httpx's connection
    layer.
    """

    def __init__(self, max_entries: int = DNS_CACHE_MAX_ENTRIES) -> None:
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
    if len(labels) < 2 or not all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
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
                    f"Input row {row_number} has rank {rank}; expected {expected_rank}."
                )

            normalized, reason = normalize_domain(row.get("domain", "") or "")
            if reason:
                raise ValueError(
                    f"Input row {row_number} has invalid domain: {reason}."
                )
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


def validate_port(parsed: ParseResult) -> str | None:
    try:
        port = parsed.port
    except ValueError:
        return "unsafe_port"
    if parsed.scheme == "http" and port not in {None, 80}:
        return "unsafe_port"
    if parsed.scheme == "https" and port not in {None, 443}:
        return "unsafe_port"
    return None


async def validate_url(
    url: str, safety_cache: HostSafetyCache
) -> tuple[ParseResult | None, str | None]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "invalid_url"
    if parsed.username is not None or parsed.password is not None:
        return None, "invalid_url"
    port_error = validate_port(parsed)
    if port_error:
        return None, port_error
    safety_error = await safety_cache.check(parsed.hostname)
    if safety_error:
        return None, safety_error
    return parsed, None


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
    body = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            remaining = limit - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])
            if len(body) >= limit:
                break
    finally:
        await response.aclose()
    return bytes(body)


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
            _parsed, safety_error = await validate_url(current_url, safety_cache)
            if safety_error:
                return FetchResult(None, None, b"", safety_error)

            async with semaphore:
                stats.attempts += 1
                attempt_started = time.perf_counter()
                request = client.build_request("GET", current_url)
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
                        continue

                    body = await read_limited(response, body_limit)
                    return FetchResult(
                        response.status_code,
                        response.headers.get("content-type"),
                        body,
                        None,
                    )
                finally:
                    stats.record_duration(time.perf_counter() - attempt_started)

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
    current_content_signals: list[str] = []
    saw_supported_field = False

    def flush() -> None:
        nonlocal current_agents, current_rules, current_content_signals
        if current_agents:
            groups.append(
                {
                    "agents": list(dict.fromkeys(current_agents)),
                    "rules": list(current_rules),
                    "content_signals": list(current_content_signals),
                }
            )
        current_agents = []
        current_rules = []
        current_content_signals = []

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
            if current_agents and (current_rules or current_content_signals):
                flush()
            if value:
                current_agents.append(value.lower())
        elif key in {"allow", "disallow"} and current_agents:
            current_rules.append({"directive": key, "path": value})
        elif key == "content-signal" and current_agents:
            current_content_signals.append(value)
        else:
            continue

    flush()
    return groups, saw_supported_field


def parse_domain_content_signal_declaration(value: str) -> dict[str, str]:
    """Parse an unscoped Content-Signal declaration for domain-level use.

    The first-party syntax also permits a leading path. Path-scoped declarations
    cannot be represented truthfully by one domain-level value, so they are not
    applicable here.
    """

    declaration = value.strip()
    if not declaration or declaration.startswith("/"):
        return {}

    parsed: dict[str, str] = {}
    for raw_assignment in declaration.split(","):
        assignment = raw_assignment.strip()
        if not assignment:
            continue

        match = CONTENT_SIGNAL_ASSIGNMENT_RE.fullmatch(assignment)
        if match:
            purpose = match.group(1).lower()
            if purpose not in CONTENT_SIGNAL_PURPOSES:
                continue
            signal_value = match.group(2).lower()
            state = signal_value if signal_value in {"yes", "no"} else "invalid"
            previous = parsed.get(purpose)
            parsed[purpose] = state if previous in {None, state} else "invalid"
            continue

        for purpose in CONTENT_SIGNAL_MENTION_RE.findall(assignment):
            parsed[purpose.lower()] = "invalid"

    return parsed


def classify_content_signals(
    groups: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    observed: dict[str, list[str]] = {
        purpose: [] for purpose in CONTENT_SIGNAL_PURPOSES
    }

    for group in groups:
        agents = [str(agent).lower() for agent in group.get("agents", [])]
        if "*" not in agents:
            continue
        for declaration in group.get("content_signals", []):
            parsed = parse_domain_content_signal_declaration(str(declaration))
            for purpose, state in parsed.items():
                observed[purpose].append(state)

    classifications: dict[str, str] = {}
    for purpose, states in observed.items():
        if not states:
            classifications[purpose] = "unspecified"
        elif "invalid" in states or len(set(states)) > 1:
            # The first-party docs define yes/no but no conflict precedence.
            classifications[purpose] = "invalid"
        else:
            classifications[purpose] = states[0]
    return classifications


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


def classify_robots_txt(
    result: FetchResult,
) -> tuple[str, dict[str, str], dict[str, str]]:
    if result.error_type:
        return "network_error", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS
    if result.status in {404, 410}:
        return "absent", ALLOW_DEFAULT_ROBOTS_POLICIES, UNSPECIFIED_CONTENT_SIGNALS
    if not is_success(result.status):
        return "http_error", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS
    if not result.body:
        return "empty", ALLOW_DEFAULT_ROBOTS_POLICIES, UNSPECIFIED_CONTENT_SIGNALS
    if not is_text_content_type(result.content_type):
        return "non_text", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS
    text = decode_text(result.body, result.content_type)
    if text is None:
        return "non_text", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS
    if looks_like_html(text):
        return "html", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS
    if not text.strip() or not any(
        strip_robots_comment(line).strip() for line in text.splitlines()
    ):
        return "empty", ALLOW_DEFAULT_ROBOTS_POLICIES, UNSPECIFIED_CONTENT_SIGNALS

    try:
        groups, saw_supported_field = parse_robots_groups(text)
    except Exception:  # noqa: BLE001 - any parser failure is an unparseable file
        return "unparseable", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS

    if not saw_supported_field:
        return "unparseable", UNKNOWN_ROBOTS_POLICIES, UNKNOWN_CONTENT_SIGNALS

    return (
        "parsed",
        {token: classify_bot_policy(groups, token) for token in TRACKED_BOT_TOKENS},
        classify_content_signals(groups),
    )


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
    content_signals: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    policies = robots_policies or {token: "unknown" for token in TRACKED_BOT_TOKENS}
    signals = content_signals or UNKNOWN_CONTENT_SIGNALS
    row: dict[str, Any] = {
        "rank": rank,
        "domain": domain,
        "has_llms_txt": has_llms_value(llms_status),
        "llms_txt_status": llms_status,
        "robots_txt_status": robots_status,
        "content_signal_search": signals["search"],
        "content_signal_ai_input": signals["ai-input"],
        "content_signal_ai_train": signals["ai-train"],
        "has_explicit_ai_policy": has_explicit_ai_policy_value(robots_status, policies),
        "any_ai_bot_restricted": any_ai_bot_restricted_value(robots_status, policies),
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
) -> ProcessedDomain:
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
    )

    llms_status = classify_llms_txt(llms_result)
    robots_status, robots_policies, content_signals = classify_robots_txt(robots_result)
    stats.endpoint_statuses[f"llms_txt:{llms_status}"] += 1
    stats.endpoint_statuses[f"robots_txt:{robots_status}"] += 1
    if llms_result.error_type:
        stats.endpoint_error_reasons[f"llms_txt:{llms_result.error_type}"] += 1
    if robots_result.error_type:
        stats.endpoint_error_reasons[f"robots_txt:{robots_result.error_type}"] += 1

    return ProcessedDomain(
        domain_row=build_output_row(
            item.rank,
            item.domain,
            llms_status,
            robots_status,
            robots_policies,
            content_signals,
        ),
        agent_policies=robots_policies,
    )


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    return value


def build_agent_policy_row(
    item: DomainInput, agent: str, policy: str
) -> dict[str, Any]:
    return {
        "rank": item.rank,
        "domain": item.domain,
        "agent": agent,
        "purpose_group": AGENT_PURPOSE_GROUPS[agent],
        "policy": policy,
    }


async def write_ordered_results(
    domains: Sequence[DomainInput],
    completed: asyncio.Queue[ProcessedDomain],
    window: asyncio.Semaphore,
    domain_writer: csv.DictWriter,
    agent_policy_writer: csv.DictWriter,
) -> tuple[int, int]:
    buffered_results: dict[int, ProcessedDomain] = {}
    domain_count = 0
    agent_policy_count = 0
    next_index = 0

    for _ in domains:
        result = await completed.get()
        row = result.domain_row
        rank = row.get("rank")
        if isinstance(rank, bool) or not isinstance(rank, int):
            raise TypeError("Completed row has an invalid rank.")
        if rank < 1 or rank > len(domains):
            raise ValueError(f"Completed row has out-of-range rank {rank}.")

        item = domains[rank - 1]
        if item.rank != rank or row.get("domain") != item.domain:
            raise ValueError(f"Completed row does not match input rank {rank}.")
        if rank <= next_index or rank in buffered_results:
            raise ValueError(f"Completed row has duplicate rank {rank}.")
        buffered_results[rank] = result

        while next_index < len(domains):
            expected = domains[next_index]
            if expected.rank not in buffered_results:
                break
            ordered_result = buffered_results.pop(expected.rank)
            ordered_row = ordered_result.domain_row
            # Keep the CSV contract explicit for downstream readr/tidyverse loading.
            domain_writer.writerow(
                {column: csv_value(ordered_row[column]) for column in OUTPUT_COLUMNS}
            )
            domain_count += 1
            for agent in TRACKED_BOT_TOKENS:
                agent_row = build_agent_policy_row(
                    expected, agent, ordered_result.agent_policies[agent]
                )
                agent_policy_writer.writerow(agent_row)
                agent_policy_count += 1
            next_index += 1
            window.release()

    expected_agent_policy_count = len(domains) * len(TRACKED_BOT_TOKENS)
    if domain_count != len(domains) or buffered_results:
        raise RuntimeError(
            f"Expected {len(domains)} domain rows; wrote {domain_count}."
        )
    if agent_policy_count != expected_agent_policy_count:
        raise RuntimeError(
            f"Expected {expected_agent_policy_count} agent policy rows; "
            f"wrote {agent_policy_count}."
        )
    return domain_count, agent_policy_count


def validate_domains_output(path: Path, domains: Sequence[DomainInput]) -> int:
    logical_columns = {
        "has_llms_txt",
        "has_explicit_ai_policy",
        "any_ai_bot_restricted",
    }
    content_signal_columns = {
        "content_signal_search",
        "content_signal_ai_input",
        "content_signal_ai_train",
    }
    grouped_columns = set(BOT_GROUPS)

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != OUTPUT_COLUMNS:
            raise ValueError("Domain output CSV has an unexpected schema.")

        count = 0
        for expected in domains:
            row = next(reader, None)
            if row is None:
                raise ValueError(f"Domain output is missing rank {expected.rank}.")
            if row["rank"] != str(expected.rank) or row["domain"] != expected.domain:
                raise ValueError(
                    f"Domain output does not match input rank {expected.rank}."
                )
            if any(
                row[column] not in {"true", "false", ""} for column in logical_columns
            ):
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid logical data."
                )
            if row["llms_txt_status"] not in LLMS_STATUS_VALUES:
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid llms status."
                )
            if row["robots_txt_status"] not in ROBOTS_STATUS_VALUES:
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid robots status."
                )
            if any(
                row[column] not in CONTENT_SIGNAL_VALUES
                for column in content_signal_columns
            ):
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid Content-Signal data."
                )
            if any(
                row[column] not in GROUPED_RESTRICTION_VALUES
                for column in grouped_columns
            ):
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid grouped data."
                )
            if row["scan_status"] not in SCAN_STATUS_VALUES:
                raise ValueError(
                    f"Domain output rank {expected.rank} has invalid scan status."
                )
            if any(value is None for value in row.values()):
                raise ValueError(
                    f"Domain output rank {expected.rank} has a non-scalar cell."
                )
            count += 1

        if next(reader, None) is not None:
            raise ValueError("Domain output has more rows than the input.")
    return count


def validate_agent_policies_output(path: Path, domains: Sequence[DomainInput]) -> int:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != AGENT_POLICY_COLUMNS:
            raise ValueError("Agent policy output CSV has an unexpected schema.")

        count = 0
        for expected in domains:
            for agent in TRACKED_BOT_TOKENS:
                row = next(reader, None)
                if row is None:
                    raise ValueError(
                        f"Agent policy output is missing {expected.domain} / {agent}."
                    )
                if (
                    row["rank"] != str(expected.rank)
                    or row["domain"] != expected.domain
                    or row["agent"] != agent
                ):
                    raise ValueError(
                        "Agent policy output is not in deterministic rank/agent order."
                    )
                if row["purpose_group"] != AGENT_PURPOSE_GROUPS[agent]:
                    raise ValueError(
                        f"Agent policy output has the wrong group for {agent}."
                    )
                if row["policy"] not in ROBOTS_POLICY_VALUES:
                    raise ValueError(
                        f"Agent policy output has an invalid policy for {agent}."
                    )
                if any(value is None for value in row.values()):
                    raise ValueError("Agent policy output has a non-scalar cell.")
                count += 1

        if next(reader, None) is not None:
            raise ValueError("Agent policy output has more rows than expected.")
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


def log_scan_summary(stats: RequestStats, progress: ProgressStats) -> None:
    median_duration = percentile(stats.request_durations, 0.50)
    p95_duration = percentile(stats.request_durations, 0.95)
    LOGGER.info(
        "HTTP attempts=%s redirects=%s http_fallbacks=%s "
        "http_fallback_recoveries=%s complete=%s partial=%s failed=%s",
        stats.attempts,
        stats.redirects,
        stats.http_fallbacks,
        stats.http_fallback_recoveries,
        progress.complete,
        progress.partial,
        progress.failed,
    )
    if median_duration is not None and p95_duration is not None:
        LOGGER.info(
            "Sampled request duration median=%.3fs p95=%.3fs "
            "(%s of %s attempts sampled)",
            median_duration,
            p95_duration,
            len(stats.request_durations),
            stats.request_duration_count,
        )
    if stats.endpoint_statuses:
        LOGGER.info(
            "Endpoint statuses: %s", dict(stats.endpoint_statuses.most_common())
        )
    if stats.endpoint_error_reasons:
        LOGGER.info(
            "Network error reasons: %s",
            dict(stats.endpoint_error_reasons.most_common()),
        )


def maybe_log_progress(progress: ProgressStats, stats: RequestStats) -> None:
    now = time.monotonic()
    if now - progress.last_report < PROGRESS_SECONDS:
        return
    elapsed = max(time.perf_counter() - progress.started, 0.1)
    interval_elapsed = max(now - progress.last_report, 0.1)
    interval_processed = progress.processed - progress.processed_at_last_report
    LOGGER.info(
        "Processed %s / %s domains (%.2f%%) | %.2f recent domains/s | "
        "%.2f avg domains/s | complete=%s partial=%s failed=%s | "
        "http_attempts=%s http_fallbacks=%s",
        progress.processed,
        progress.total,
        progress.processed / max(progress.total, 1) * 100,
        interval_processed / interval_elapsed,
        progress.processed / elapsed,
        progress.complete,
        progress.partial,
        progress.failed,
        stats.attempts,
        stats.http_fallbacks,
    )
    progress.last_report = now
    progress.processed_at_last_report = progress.processed


def publish_validated_outputs(replacements: Sequence[tuple[Path, Path]]) -> None:
    """Replace a related set of outputs, rolling back catchable failures."""
    backups: dict[Path, Path | None] = {}
    published: list[Path] = []
    preserved_backups: set[Path] = set()

    try:
        # Hard links retain the old files without copying these large CSVs.
        for _temporary, final in replacements:
            backup = final.with_name(f".{final.name}.previous")
            backup.unlink(missing_ok=True)
            if final.exists():
                os.link(final, backup)
                backups[final] = backup
            else:
                backups[final] = None

        for temporary, final in replacements:
            os.replace(temporary, final)
            published.append(final)
    except BaseException:
        for final in reversed(published):
            backup = backups[final]
            try:
                if backup is None:
                    final.unlink(missing_ok=True)
                else:
                    os.replace(backup, final)
            except OSError:
                LOGGER.critical("Could not restore previous output %s", final)
                if backup is not None:
                    preserved_backups.add(backup)
        raise
    finally:
        for backup in backups.values():
            if backup is not None and backup not in preserved_backups:
                try:
                    backup.unlink(missing_ok=True)
                except OSError:
                    LOGGER.warning("Could not remove output backup %s", backup)


async def collect(
    domains: Sequence[DomainInput],
) -> int:
    stats = RequestStats()
    progress = ProgressStats(total=len(domains))
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    AGENT_POLICIES_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    domain_temporary = OUTPUT_PATH.with_name(f".{OUTPUT_PATH.name}.tmp")
    agent_policy_temporary = AGENT_POLICIES_OUTPUT_PATH.with_name(
        f".{AGENT_POLICIES_OUTPUT_PATH.name}.tmp"
    )

    try:
        with (
            domain_temporary.open("w", encoding="utf-8", newline="") as domain_handle,
            agent_policy_temporary.open(
                "w", encoding="utf-8", newline=""
            ) as agent_policy_handle,
        ):
            domain_writer = csv.DictWriter(domain_handle, fieldnames=OUTPUT_COLUMNS)
            agent_policy_writer = csv.DictWriter(
                agent_policy_handle, fieldnames=AGENT_POLICY_COLUMNS
            )
            domain_writer.writeheader()
            agent_policy_writer.writeheader()
            domain_count = 0
            agent_policy_count = 0

            if domains:
                timeout = httpx.Timeout(
                    connect=CONNECT_TIMEOUT,
                    read=READ_TIMEOUT,
                    write=WRITE_TIMEOUT,
                    pool=POOL_TIMEOUT,
                )
                limits = httpx.Limits(
                    max_connections=REQUEST_CONCURRENCY,
                    max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
                    keepalive_expiry=KEEPALIVE_EXPIRY,
                )
                semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)
                safety_cache = HostSafetyCache()
                iterator = iter(domains)
                worker_count = min(DOMAIN_WORKERS, len(domains))
                window = asyncio.Semaphore(min(MAX_PENDING_OUTPUT_ROWS, len(domains)))
                completed: asyncio.Queue[ProcessedDomain] = asyncio.Queue()

                async with httpx.AsyncClient(
                    follow_redirects=False,
                    http2=True,
                    timeout=timeout,
                    limits=limits,
                    verify=True,
                    trust_env=False,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "text/plain,text/markdown,*/*;q=0.1",
                    },
                ) as client:

                    async def worker() -> None:
                        while True:
                            await window.acquire()
                            try:
                                item = next(iterator)
                            except StopIteration:
                                window.release()
                                return
                            try:
                                result = await process_domain(
                                    item,
                                    client,
                                    semaphore,
                                    safety_cache,
                                    stats,
                                )
                            except Exception:
                                LOGGER.exception(
                                    "Internal error while processing %s", item.domain
                                )
                                stats.endpoint_error_reasons[
                                    "domain:internal_error"
                                ] += 1
                                result = ProcessedDomain(
                                    domain_row=build_output_row(
                                        item.rank,
                                        item.domain,
                                        "network_error",
                                        "network_error",
                                        None,
                                        UNKNOWN_CONTENT_SIGNALS,
                                    ),
                                    agent_policies=UNKNOWN_ROBOTS_POLICIES,
                                )
                            await completed.put(result)
                            progress.record_row(result.domain_row)
                            maybe_log_progress(progress, stats)

                    async with asyncio.TaskGroup() as tasks:
                        output_task = tasks.create_task(
                            write_ordered_results(
                                domains,
                                completed,
                                window,
                                domain_writer,
                                agent_policy_writer,
                            )
                        )
                        for _ in range(worker_count):
                            tasks.create_task(worker())
                    domain_count, agent_policy_count = output_task.result()

            if domain_count != len(domains):
                raise RuntimeError(
                    f"Expected {len(domains)} domain rows; wrote {domain_count}."
                )
            expected_agent_policy_count = len(domains) * len(TRACKED_BOT_TOKENS)
            if agent_policy_count != expected_agent_policy_count:
                raise RuntimeError(
                    f"Expected {expected_agent_policy_count} agent policy rows; "
                    f"wrote {agent_policy_count}."
                )

        validate_domains_output(domain_temporary, domains)
        validate_agent_policies_output(agent_policy_temporary, domains)
        publish_validated_outputs(
            (
                (agent_policy_temporary, AGENT_POLICIES_OUTPUT_PATH),
                (domain_temporary, OUTPUT_PATH),
            )
        )
    except BaseException:
        for temporary in (domain_temporary, agent_policy_temporary):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("Could not remove temporary output %s", temporary)
        raise

    log_scan_summary(stats, progress)
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
