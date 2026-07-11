#!/usr/bin/env python3
"""Collect simple V1 AI readiness signals for popular domains.

The script reads a CSV containing domains and writes one analysis-ready CSV:

    data/processed/domains.csv

A compact JSONL checkpoint is maintained automatically so interrupted runs can
resume. Re-run the same command to retry partial or failed scans. Use --fresh
only when you intentionally want to discard the checkpoint and start over.

Usage:
    uv run python collection/fetch.py data/input/domains.csv
    uv run python collection/fetch.py data/input/domains.csv --limit 100
    uv run python collection/fetch.py data/input/domains.csv --fresh

Dependency:
    httpx
"""

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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence, TextIO
from urllib.parse import urljoin, urlparse

import httpx

VERSION = "2.1.0"
SCHEMA_VERSION = 2

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "collection" else SCRIPT_DIR
OUTPUT_PATH = REPO_ROOT / "data/processed/domains.csv"
CHECKPOINT_PATH = REPO_ROOT / "data/raw/domains_checkpoint.jsonl"
CHECKPOINT_META_PATH = REPO_ROOT / "data/raw/domains_checkpoint.meta.json"

USER_AGENT = f"AIWebSignals/{VERSION} (+https://github.com/TypeError/ai-web-signals)"
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

OUTPUT_COLUMNS = [
    "rank",
    "domain",
    "categories",
    "has_llms_txt",
    "training_bots_blocked",
    "search_bots_blocked",
    "ai_policy_explicit",
    "scan_status",
]

TRAINING_BOTS = [
    "GPTBot",
    "ClaudeBot",
    "Google-Extended",
    "Applebot-Extended",
    "Meta-ExternalAgent",
]
SEARCH_BOTS = ["OAI-SearchBot", "Claude-SearchBot", "PerplexityBot"]
TRACKED_BOTS = TRAINING_BOTS + SEARCH_BOTS
ROBOTS_FIELDS = {
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

BLOCKED_STATES = {"none", "some", "all", "unknown"}
SCAN_STATES = {"complete", "partial", "failed"}
RESTRICTION_DIRECTIVES = {"disallow", "partial_disallow", "partial_allow"}


@dataclass(frozen=True)
class DomainInput:
    rank: int | None
    domain: str
    categories: str | None


@dataclass(frozen=True)
class EndpointResult:
    status: int | None
    content_type: str | None
    body: bytes
    error: str | None


@dataclass
class RequestStats:
    attempts: int = 0
    retries: int = 0
    redirects: int = 0
    http_fallbacks: int = 0


class HostSafetyCache:
    """Cache DNS safety checks so redirects cannot target local addresses."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[str | None]] = {}

    async def check(self, host: str) -> str | None:
        key = host.lower().rstrip(".")
        task = self._tasks.get(key)
        if task is None:
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
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def parse_optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def load_domains(
    path: Path, limit: int | None
) -> tuple[list[DomainInput], Counter[str]]:
    domains: list[DomainInput] = []
    skipped: Counter[str] = Counter()
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header row.")

        domain_column = identify_domain_column(reader.fieldnames)
        rank_column = identify_column(reader.fieldnames, ("rank", "ranking"))
        category_column = identify_column(reader.fieldnames, ("categories", "category"))

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
                    rank=(
                        parse_optional_int(row.get(rank_column))
                        if rank_column
                        else None
                    ),
                    domain=normalized,
                    categories=row.get(category_column) if category_column else None,
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
    if isinstance(error, httpx.PoolTimeout):
        return "pool_timeout"
    if isinstance(error, httpx.InvalidURL):
        return "invalid_url"
    if isinstance(error, httpx.ConnectError):
        description = repr(error).lower()
        cause = error.__cause__
        if (
            isinstance(cause, ssl.SSLError)
            or "certificate" in description
            or "tls" in description
        ):
            return "tls_error"
        if (
            isinstance(cause, socket.gaierror)
            or "name or service not known" in description
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
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = (parsed - datetime.now(timezone.utc)).total_seconds()
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


async def read_limited(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            remaining = limit - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
            if len(chunk) > remaining:
                break
    finally:
        await response.aclose()
    return b"".join(chunks)


async def fetch_once(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    url: str,
    body_limit: int,
) -> EndpointResult:
    for attempt in range(len(RETRY_DELAYS) + 1):
        current_url = url
        redirects = 0
        retry_delay: float | None = None

        try:
            while True:
                safety_error = await validate_url(current_url, safety_cache)
                if safety_error:
                    return EndpointResult(None, None, b"", safety_error)

                async with semaphore:
                    stats.attempts += 1
                    response = await client.send(
                        client.build_request("GET", current_url),
                        stream=True,
                    )

                    if 300 <= response.status_code < 400 and response.headers.get(
                        "location"
                    ):
                        location = response.headers["location"]
                        await response.aclose()
                        redirects += 1
                        stats.redirects += 1
                        if redirects > REDIRECT_LIMIT:
                            return EndpointResult(None, None, b"", "redirect_error")
                        next_url = urljoin(current_url, location)
                        if urlparse(next_url).scheme not in {"http", "https"}:
                            return EndpointResult(None, None, b"", "unsafe_redirect")
                        current_url = next_url
                        continue

                    if response.status_code in RETRYABLE_STATUS_CODES and attempt < len(
                        RETRY_DELAYS
                    ):
                        retry_after = parse_retry_after(
                            response.headers.get("retry-after")
                        )
                        await response.aclose()
                        stats.retries += 1
                        retry_delay = (
                            retry_after
                            if retry_after is not None
                            else RETRY_DELAYS[attempt] + random.uniform(0.0, 0.25)
                        )
                    else:
                        body = await read_limited(response, body_limit)
                        content_type = response.headers.get("content-type")
                        return EndpointResult(
                            response.status_code,
                            content_type,
                            body,
                            None,
                        )
                break

        except httpx.HTTPError as error:
            if attempt < len(RETRY_DELAYS) and should_retry_exception(error):
                stats.retries += 1
                await asyncio.sleep(RETRY_DELAYS[attempt] + random.uniform(0.0, 0.25))
                continue
            return EndpointResult(None, None, b"", classify_httpx_error(error))

        if retry_delay is not None:
            await asyncio.sleep(retry_delay)
            continue

    return EndpointResult(None, None, b"", "network_error")


async def fetch_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
    domain: str,
    path: str,
    body_limit: int,
) -> EndpointResult:
    https_result = await fetch_once(
        client,
        semaphore,
        safety_cache,
        stats,
        f"https://{domain}{path}",
        body_limit,
    )
    if https_result.status is not None or https_result.error not in {
        "connect_timeout",
        "connect_error",
        "tls_error",
    }:
        return https_result

    stats.http_fallbacks += 1
    return await fetch_once(
        client,
        semaphore,
        safety_cache,
        stats,
        f"http://{domain}{path}",
        body_limit,
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
        match = re.search(r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.I)
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


def is_success(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def evaluate_llms_txt(result: EndpointResult) -> tuple[bool | None, bool]:
    """Return (has_llms_txt, known). Unknown values become blank in CSV."""

    if result.error:
        return None, False
    if result.status in {404, 410}:
        return False, True
    if not is_success(result.status):
        return None, False
    if not result.body:
        return False, True

    text = decode_text(result.body, result.content_type)
    if text is None or not text.strip() or looks_like_html(text):
        return False, True
    return True, True


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
    recognized = False

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
            if current_agents:
                flush()
            continue
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        recognized = recognized or key in ROBOTS_FIELDS

        if key == "user-agent":
            if current_agents and current_rules:
                flush()
            if value:
                current_agents.append(value.lower())
        elif key in {"allow", "disallow"} and current_agents:
            current_rules.append({"directive": key, "path": value})

    flush()
    return groups, recognized


def classify_rules(rules: Sequence[Mapping[str, str]]) -> str:
    allows = [
        str(rule.get("path", ""))
        for rule in rules
        if rule.get("directive") == "allow" and rule.get("path")
    ]
    disallows = [
        str(rule.get("path", ""))
        for rule in rules
        if rule.get("directive") == "disallow" and rule.get("path")
    ]

    if "/" in disallows:
        return "partial_allow" if allows else "disallow"
    if disallows:
        return "partial_disallow"
    return "allow"


def classify_bot_policy(
    groups: Sequence[Mapping[str, Any]], bot: str
) -> tuple[str, bool]:
    target = bot.lower()
    explicit_groups: list[Mapping[str, Any]] = []
    wildcard_groups: list[Mapping[str, Any]] = []

    for group in groups:
        agents = [str(agent).lower() for agent in group.get("agents", [])]
        if target in agents:
            explicit_groups.append(group)
        elif "*" in agents:
            wildcard_groups.append(group)

    selected = explicit_groups or wildcard_groups
    if not selected:
        return "allow", False

    rules = [rule for group in selected for rule in group.get("rules", [])]
    return classify_rules(rules), bool(explicit_groups)


def evaluate_robots_txt(
    result: EndpointResult,
) -> tuple[dict[str, str] | None, bool | None, bool]:
    """Return (bot policies, explicit AI policy, known)."""

    if result.error:
        return None, None, False
    if result.status in {404, 410}:
        return {bot: "allow" for bot in TRACKED_BOTS}, False, True
    if not is_success(result.status):
        return None, None, False
    if not result.body:
        return {bot: "allow" for bot in TRACKED_BOTS}, False, True

    text = decode_text(result.body, result.content_type)
    if text is None or looks_like_html(text):
        return None, None, False
    if not text.strip() or not any(
        strip_robots_comment(line).strip() for line in text.splitlines()
    ):
        return {bot: "allow" for bot in TRACKED_BOTS}, False, True

    groups, recognized = parse_robots_groups(text)
    if not recognized:
        return None, None, False

    policies: dict[str, str] = {}
    explicit = False
    for bot in TRACKED_BOTS:
        directive, is_explicit = classify_bot_policy(groups, bot)
        policies[bot] = directive
        explicit = explicit or is_explicit
    return policies, explicit, True


def summarize_blocking(policies: Mapping[str, str], bots: Sequence[str]) -> str:
    blocked = sum(policies[bot] in RESTRICTION_DIRECTIVES for bot in bots)
    if blocked == 0:
        return "none"
    if blocked == len(bots):
        return "all"
    return "some"


def scan_status(llms_known: bool, robots_known: bool) -> str:
    known_count = int(llms_known) + int(robots_known)
    if known_count == 2:
        return "complete"
    if known_count == 1:
        return "partial"
    return "failed"


def failed_row(item: DomainInput) -> dict[str, Any]:
    return {
        "rank": item.rank,
        "domain": item.domain,
        "categories": item.categories,
        "has_llms_txt": None,
        "training_bots_blocked": "unknown",
        "search_bots_blocked": "unknown",
        "ai_policy_explicit": None,
        "scan_status": "failed",
    }


async def process_domain(
    item: DomainInput,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    safety_cache: HostSafetyCache,
    stats: RequestStats,
) -> dict[str, Any]:
    results = await asyncio.gather(
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

    llms_result = (
        results[0]
        if isinstance(results[0], EndpointResult)
        else EndpointResult(None, None, b"", "internal_error")
    )
    robots_result = (
        results[1]
        if isinstance(results[1], EndpointResult)
        else EndpointResult(None, None, b"", "internal_error")
    )

    has_llms_txt, llms_known = evaluate_llms_txt(llms_result)
    policies, explicit, robots_known = evaluate_robots_txt(robots_result)

    return {
        "rank": item.rank,
        "domain": item.domain,
        "categories": item.categories,
        "has_llms_txt": has_llms_txt,
        "training_bots_blocked": summarize_blocking(policies, TRAINING_BOTS)
        if policies
        else "unknown",
        "search_bots_blocked": summarize_blocking(policies, SEARCH_BOTS)
        if policies
        else "unknown",
        "ai_policy_explicit": explicit,
        "scan_status": scan_status(llms_known, robots_known),
    }


def validate_row(row: Mapping[str, Any]) -> None:
    if set(row) != set(OUTPUT_COLUMNS):
        raise ValueError("Checkpoint row does not match the V1 output schema.")
    if not isinstance(row.get("domain"), str) or not row["domain"]:
        raise ValueError("Checkpoint row has an invalid domain.")
    if row.get("training_bots_blocked") not in BLOCKED_STATES:
        raise ValueError("Checkpoint row has an invalid training bot state.")
    if row.get("search_bots_blocked") not in BLOCKED_STATES:
        raise ValueError("Checkpoint row has an invalid search bot state.")
    if row.get("scan_status") not in SCAN_STATES:
        raise ValueError("Checkpoint row has an invalid scan status.")
    if row.get("has_llms_txt") not in {True, False, None}:
        raise ValueError("Checkpoint row has an invalid llms.txt value.")
    if row.get("ai_policy_explicit") not in {True, False, None}:
        raise ValueError("Checkpoint row has an invalid AI policy value.")


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
                raise ValueError(f"Checkpoint line {line_number} is not a JSON object.")
            validate_row(value)
            yield value

        if pending_malformed is not None:
            logging.warning(
                "Ignoring an incomplete final checkpoint line at line %s.",
                pending_malformed[0],
            )


def load_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in iter_jsonl(path):
        latest[str(row["domain"])] = row
    return latest


def write_checkpoint_row(handle: TextIO, row: Mapping[str, Any]) -> None:
    validate_row(row)
    handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    handle.flush()


def checkpoint_metadata(input_path: Path, input_digest: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "collector_version": VERSION,
        "input_filename": input_path.name,
        "input_sha256": input_digest,
        "columns": OUTPUT_COLUMNS,
        "created_at": utc_now_iso(),
    }


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def prepare_checkpoint(input_path: Path, fresh: bool) -> dict[str, dict[str, Any]]:
    input_digest = file_sha256(input_path)

    if fresh:
        for path in (CHECKPOINT_PATH, CHECKPOINT_META_PATH, OUTPUT_PATH):
            if path.exists():
                path.unlink()

    if CHECKPOINT_PATH.exists() != CHECKPOINT_META_PATH.exists():
        raise ValueError(
            "Checkpoint files are incomplete. Re-run with --fresh to start over."
        )

    if not CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
        CHECKPOINT_PATH.touch()
        write_json_atomic(
            CHECKPOINT_META_PATH,
            checkpoint_metadata(input_path, input_digest),
        )
        return {}

    metadata = json.loads(CHECKPOINT_META_PATH.read_text(encoding="utf-8"))
    compatible = (
        metadata.get("schema_version") == SCHEMA_VERSION
        and metadata.get("input_sha256") == input_digest
        and metadata.get("columns") == OUTPUT_COLUMNS
    )
    if not compatible:
        raise ValueError(
            "The checkpoint belongs to a different input or schema. "
            "Re-run with --fresh to start over."
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
            validate_row(row)
            writer.writerow(
                {column: csv_value(row[column]) for column in OUTPUT_COLUMNS}
            )
            count += 1

    os.replace(temporary, OUTPUT_PATH)
    return count


async def collect(input_path: Path, domains: Sequence[DomainInput], fresh: bool) -> int:
    started = time.perf_counter()
    latest_rows = prepare_checkpoint(input_path, fresh)
    completed = {
        item.domain
        for item in domains
        if latest_rows.get(item.domain, {}).get("scan_status") == "complete"
    }
    pending = [item for item in domains if item.domain not in completed]

    logging.info(
        "Loaded %s domains. %s complete, %s pending.",
        len(domains),
        len(completed),
        len(pending),
    )

    stats = RequestStats()
    processed_this_run = 0
    status_counts: Counter[str] = Counter()
    llms_counts: Counter[str] = Counter()
    last_progress = time.monotonic()

    if pending:
        timeout = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
        limits = httpx.Limits(
            max_connections=max(REQUEST_CONCURRENCY * 2, 60),
            max_keepalive_connections=max(REQUEST_CONCURRENCY, 30),
        )
        semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)
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
            worker_count = min(DOMAIN_WORKERS, len(pending))
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
                            )
                        except Exception:
                            logging.exception(
                                "Unexpected failure scanning %s", item.domain
                            )
                            row = failed_row(item)
                        await result_queue.put(row)
                    finally:
                        input_queue.task_done()

            producer_task = asyncio.create_task(producer())
            workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

            with CHECKPOINT_PATH.open("a", encoding="utf-8") as checkpoint:
                for _ in range(len(pending)):
                    row = await result_queue.get()
                    try:
                        write_checkpoint_row(checkpoint, row)
                        latest_rows[str(row["domain"])] = row
                        processed_this_run += 1
                        status_counts[str(row["scan_status"])] += 1
                        llms_value = row["has_llms_txt"]
                        llms_label = (
                            "present"
                            if llms_value is True
                            else "absent"
                            if llms_value is False
                            else "unknown"
                        )
                        llms_counts[llms_label] += 1
                    finally:
                        result_queue.task_done()

                    now = time.monotonic()
                    if (
                        processed_this_run % LOG_EVERY == 0
                        or now - last_progress >= PROGRESS_SECONDS
                        or processed_this_run == len(pending)
                    ):
                        logging.info(
                            "Processed %s / %s pending | complete=%s "
                            "partial=%s failed=%s | llms.txt present=%s",
                            processed_this_run,
                            len(pending),
                            status_counts["complete"],
                            status_counts["partial"],
                            status_counts["failed"],
                            llms_counts["present"],
                        )
                        last_progress = now

            await input_queue.join()
            await result_queue.join()
            await producer_task
            await asyncio.gather(*workers)

    row_count = write_output_csv(domains, latest_rows)
    final_counts = Counter(
        str(latest_rows[item.domain]["scan_status"])
        for item in domains
        if item.domain in latest_rows
    )
    llms_present = sum(
        latest_rows[item.domain]["has_llms_txt"] is True
        for item in domains
        if item.domain in latest_rows
    )

    logging.info("Wrote %s rows to %s", row_count, OUTPUT_PATH)
    logging.info(
        "Final scan status: complete=%s partial=%s failed=%s | llms.txt present=%s",
        final_counts["complete"],
        final_counts["partial"],
        final_counts["failed"],
        llms_present,
    )
    logging.info(
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
            "Scan domains for llms.txt and AI crawler policy signals. "
            "Writes data/processed/domains.csv and resumes automatically."
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        domains, skipped = load_domains(args.input, args.limit)
        if not domains:
            raise ValueError(f"No valid domains found in {args.input}")
        if skipped:
            logging.info(
                "Skipped %s input rows: %s",
                sum(skipped.values()),
                ", ".join(f"{reason}={count}" for reason, count in skipped.items()),
            )

        return asyncio.run(collect(args.input.resolve(), domains, args.fresh))
    except KeyboardInterrupt:
        logging.warning("Interrupted. Re-run the command to resume.")
        return 130
    except Exception as error:
        logging.exception("Fatal error: %s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
