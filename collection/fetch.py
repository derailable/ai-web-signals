"""Collect public AI web signals for Cloudflare Radar domain buckets."""

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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

LOGGER = logging.getLogger(__name__)

VERSION = "3.4.0"
REPOSITORY_URL = "https://github.com/derailable/ai-web-signals"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collection" else SCRIPT_DIR
OUTPUT_PATH = REPO_ROOT / "data/processed/domains.csv"

USER_AGENT = f"AIWebSignals/{VERSION} (+{REPOSITORY_URL})"
DEFAULT_POPULARITY_BUCKET = 100000
DOMAIN_WORKERS = 75
REQUEST_CONCURRENCY = 120
PROGRESS_SECONDS = 300.0
DEBUG_VALIDATE_ROWS = False
REDIRECT_LIMIT = 4
LLMS_SAMPLE_LIMIT = 256 * 1024
ROBOTS_SAMPLE_LIMIT = 512 * 1024
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
WRITE_TIMEOUT = 3.0
POOL_TIMEOUT = 3.0
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
HTML_MARKUP_RE = re.compile(
    r"<(?:title|div|span|script|style|meta|form|nav|footer)\b"
)

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
UNKNOWN_ROBOTS_POLICIES = {token: "unknown" for token in TRACKED_BOT_TOKENS}
ALLOW_DEFAULT_ROBOTS_POLICIES = {
    token: "allow_default" for token in TRACKED_BOT_TOKENS
}

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
    domain: str


@dataclass(frozen=True)
class CollectionSettings:
    workers: int = DOMAIN_WORKERS
    request_concurrency: int = REQUEST_CONCURRENCY
    connect_timeout: float = CONNECT_TIMEOUT
    read_timeout: float = READ_TIMEOUT
    write_timeout: float = WRITE_TIMEOUT
    pool_timeout: float = POOL_TIMEOUT
    llms_sample_limit: int = LLMS_SAMPLE_LIMIT
    robots_sample_limit: int = ROBOTS_SAMPLE_LIMIT
    redirect_limit: int = REDIRECT_LIMIT


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


class HostSafetyCache:
    """Bounded DNS safety cache for practical redirect target screening.

    This checks all resolved addresses before each request and caches completed
    results. It does not prove DNS-rebinding safety inside httpx's connection
    layer.
    """

    def __init__(self, max_entries: int = DEFAULT_POPULARITY_BUCKET) -> None:
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


def load_domains(path: Path) -> tuple[list[DomainInput], Counter[str]]:
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
            domains.append(DomainInput(domain=normalized))
            if len(domains) >= DEFAULT_POPULARITY_BUCKET:
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
    settings: CollectionSettings,
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
                request = client.build_request("GET", redacted_url(current_url))
                response = await client.send(request, stream=True)

                if 300 <= response.status_code < 400 and response.headers.get(
                    "location"
                ):
                    location = response.headers["location"]
                    await response.aclose()
                    redirects += 1
                    stats.redirects += 1
                    if redirects > settings.redirect_limit:
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

    except httpx.HTTPError as error:
        return FetchResult(None, None, b"", classify_httpx_error(error))

    return FetchResult(None, None, b"", "network_error")


def should_http_fallback(result: FetchResult) -> bool:
    return result.status is None and result.error_type in {
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
        LOGGER.exception("Unexpected robots parser failure")
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
    domain: str,
    llms_status: str,
    robots_status: str,
    robots_policies: Mapping[str, str] | None,
) -> dict[str, Any]:
    policies = robots_policies or {token: "unknown" for token in TRACKED_BOT_TOKENS}
    row: dict[str, Any] = {
        "domain": domain,
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
    row["scan_status"] = scan_status_from_statuses(llms_status, robots_status)
    if DEBUG_VALIDATE_ROWS:
        validate_output_row(row)
    return row


async def process_domain(
    item: DomainInput,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    settings: CollectionSettings,
) -> dict[str, Any]:
    llms_status = "network_error"
    robots_status = "network_error"
    robots_policies: dict[str, str] | None = None

    tasks: dict[EndpointName, asyncio.Task[FetchResult]] = {
        "llms_txt": asyncio.create_task(
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
        ),
        "robots_txt": asyncio.create_task(
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
    }

    for name, task in tasks.items():
        try:
            result = await task
        except Exception:
            LOGGER.exception("Unexpected failure fetching %s for %s", name, item.domain)
            result = FetchResult(None, None, b"", "internal_error")

        if name == "llms_txt":
            llms_status = classify_llms_txt(result)
        else:
            robots_status, robots_policies = classify_robots_txt(result)

    return build_output_row(item.domain, llms_status, robots_status, robots_policies)


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
    domains: Sequence[DomainInput], latest_rows: Mapping[str, Mapping[str, Any]]
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
    projected_row_count = sum(1 for item in domains if item.domain in latest_rows)
    if projected_row_count > len(domains):
        raise ValueError("Output row count would exceed input domain count.")
    if DEBUG_VALIDATE_ROWS:
        for row in latest_rows.values():
            validate_output_row(row)


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
    validate_output_contract(domains, latest_rows)
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
            writer.writerow(
                {column: csv_value(row[column]) for column in OUTPUT_COLUMNS}
            )
            count += 1

    os.replace(temporary, OUTPUT_PATH)
    return count


async def collect(
    domains: Sequence[DomainInput],
    settings: CollectionSettings,
) -> int:
    started = time.perf_counter()
    latest_rows: dict[str, dict[str, Any]] = {}
    pending = list(domains)

    LOGGER.info(
        "Loaded %s domains for a fresh one-shot collection.",
        len(domains),
    )

    stats = RequestStats()
    processed_this_run = 0
    status_counts: Counter[str] = Counter()
    last_progress = time.monotonic()
    last_progress_processed = 0

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
            http2=True,
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
                            row = await process_domain(
                                item,
                                client,
                                semaphore,
                                safety_cache,
                                stats,
                                settings,
                            )
                            await result_queue.put(row)
                        except Exception:
                            LOGGER.exception(
                                "Unexpected failure scanning %s", item.domain
                            )
                            await result_queue.put(
                                build_output_row(
                                    item.domain,
                                    "network_error",
                                    "network_error",
                                    None,
                                )
                            )
                    finally:
                        input_queue.task_done()

            producer_task = asyncio.create_task(producer())
            workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

            for _ in range(len(pending)):
                row = await result_queue.get()
                try:
                    latest_rows[str(row["domain"])] = row
                    processed_this_run += 1
                    status_counts[str(row["scan_status"])] += 1
                finally:
                    result_queue.task_done()

                now = time.monotonic()
                if now - last_progress >= PROGRESS_SECONDS:
                    rate = processed_this_run / max(
                        time.perf_counter() - started, 0.1
                    )
                    interval_elapsed = max(now - last_progress, 0.1)
                    interval_processed = processed_this_run - last_progress_processed
                    interval_rate = interval_processed / interval_elapsed
                    LOGGER.info(
                        "Processed %s / %s pending | %.2f recent domains/s | "
                        "%.2f avg domains/s",
                        processed_this_run,
                        len(pending),
                        interval_rate,
                        rate,
                    )
                    last_progress = now
                    last_progress_processed = processed_this_run

            await input_queue.join()
            await result_queue.join()
            await producer_task
            await asyncio.gather(*workers)

    row_count = write_output_csv(domains, latest_rows)
    final_counts = status_counts

    LOGGER.info("Wrote %s rows to %s", row_count, OUTPUT_PATH)
    LOGGER.info(
        "Final scan status: complete=%s partial=%s failed=%s",
        final_counts["complete"],
        final_counts["partial"],
        final_counts["failed"],
    )
    LOGGER.info(
        "HTTP attempts=%s redirects=%s fallbacks=%s elapsed=%.1fs",
        stats.attempts,
        stats.redirects,
        stats.http_fallbacks,
        time.perf_counter() - started,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(f"Usage: {Path(sys.argv[0]).name} INPUT", file=sys.stderr)
        return 2

    input_path = Path(arguments[0])
    if not input_path.is_file():
        print(f"input file does not exist: {input_path}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        domains, skipped = load_domains(input_path)
        if not domains:
            raise ValueError(f"No valid domains found in {input_path}")
        if skipped:
            LOGGER.info(
                "Skipped %s input rows: %s",
                sum(skipped.values()),
                ", ".join(f"{reason}={count}" for reason, count in skipped.items()),
            )

        return asyncio.run(collect(domains, CollectionSettings()))
    except KeyboardInterrupt:
        LOGGER.warning("Interrupted. Re-run the command to start a fresh collection.")
        return 130
    except Exception:
        LOGGER.exception("Fatal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
