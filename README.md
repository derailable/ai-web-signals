# ai-web-signals

`ai-web-signals` measures a narrow set of public web signals across
Cloudflare Radar's Top 50,000 domain population:

1. whether a plausible `/llms.txt` is published;
2. how `/robots.txt` declares policy for documented AI-related agents; and
3. whether that policy is explicit to a tracked agent or inherited from
   `User-agent: *`.

This is a measurement of published site policy and public discovery signals. It
does not prove crawler compliance, AI-provider behavior, search visibility,
internal AI adoption, or legal permission.

Python performs collection and deterministic parsing. R performs loading,
validation, summaries, visualization, and report work.

## Repository Data Policy

Generated data and rendered outputs are local-only:

```text
data/input/
data/raw/
data/processed/
results/tables/
results/figures/
_site/
```

Keep original source files under `data/input/` for local provenance. Do not
commit collected checkpoint files, processed CSVs, figures, or rendered reports.

## Data Source

Use the manually downloaded Cloudflare Radar domain bucket file as the primary
workflow for this study. A Cloudflare API token is not required.

Cloudflare documents two different domain datasets:

- the ordered Top 100 list; and
- unordered popularity bucket datasets, including Top 50,000.

For this project, the ordinary Top 50,000 CSV is treated as an unordered
popularity bucket. Do not treat row order as rank, manufacture sequential ranks,
or make rank-band claims from this file. The processed CSV intentionally omits
rank and bucket columns; source-population provenance is retained in checkpoint
metadata.

Official source reference:
<https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/>

## Expected Input

The collector accepts UTF-8 CSV input with a domain column:

| Column | Required | Aliases | Behavior |
| --- | --- | --- | --- |
| `domain` | Yes | `hostname`, `host`, one unambiguous `*domain*` column | Normalized with IDNA, lowercased, trailing dot removed, validated, and deduplicated |

An input `rank` or `ranking` column is ignored for the Top 50,000 bucket unless
the collection method is later changed to a provenance-backed ordered Cloudflare
Top 100 source. A single `domain` column remains sufficient.

Example:

```csv
domain
googleapis.com
googlevideo.com
```

## Collect Data

Prerequisites:

- Python 3.11 or newer with `uv`
- R with `renv`
- Quarto for report rendering

Install Python dependencies:

```bash
uv sync
```

Restore R dependencies:

```bash
Rscript -e 'renv::restore()'
```

If `renv` sandbox activation hangs locally, use:

```bash
RENV_CONFIG_SANDBOX_ENABLED=FALSE Rscript -e 'renv::restore()'
```

Set the input path:

```bash
INPUT=data/input/cloudflare-radar_top-50000-domains_YYYYMMDD-YYYYMMDD.csv
```

Run a 100-domain smoke collection:

```bash
uv run python collection/fetch.py "$INPUT" --limit 100
```

Run the full Top 50,000 collection:

```bash
uv run python collection/fetch.py "$INPUT"
```

Each run starts fresh and replaces the previous checkpoint and processed CSV.

Operational options:

```text
--limit N
--workers N
--request-concurrency N
--connect-timeout SECONDS
--read-timeout SECONDS
```

Defaults favor a one-shot collection: 50 domain workers, 80 concurrent HTTP
requests, 3-second connect timeout, 5-second read timeout, and no retries.

## Collection Scope

For each domain, the collector requests only:

```text
/llms.txt
/robots.txt
```

It does not fetch homepages, `/llms-full.txt`, sitemaps, discovered links,
JavaScript-rendered pages, DNS enrichment, WHOIS, certificates, technology
fingerprints, or additional external APIs.

Network behavior:

- one shared asynchronous `httpx` client;
- bounded worker and request concurrency;
- explicit connect, read, write, and pool timeouts;
- HTTPS first;
- HTTP fallback only after selected connection or TLS failures;
- no HTTP fallback after an HTTP response or application-level result;
- HTTP/HTTPS redirects only, with a redirect limit;
- redirect targets screened for credentials and unsafe address classes;
- bounded streaming body reads;
- retries disabled by default;
- TLS verification remains enabled; and
- user agent:
  `AIWebSignals/<version> (+https://github.com/derailable/ai-web-signals)`.

The redirect DNS safety cache is a practical defense, not a proof against every
DNS-rebinding race inside the HTTP stack.

## Processed CSV

Analysis output is atomically written to:

```text
data/processed/domains.csv
```

The file is UTF-8 CSV, one row per normalized domain, deterministic in input
order, and contains no response bodies or raw HTTP diagnostics.

Table grain: one row represents one normalized source domain and its collected
AI web signals. There are no row names, index columns, rank columns, nested JSON
cells, or one-row-per-bot expansions.

Exact ordered schema:

| column | r_type | nullable | allowed_values | description |
| --- | --- | --- | --- | --- |
| `domain` | character | no | normalized hostname | ASCII/IDNA normalized source domain. |
| `has_llms_txt` | logical | yes | `true`, `false`, blank | True only for plausible observed `/llms.txt`; blank when unresolved. |
| `llms_txt_status` | character | no | see endpoint enums | `/llms.txt` endpoint classification. |
| `robots_txt_status` | character | no | see endpoint enums | `/robots.txt` endpoint classification. |
| `has_explicit_ai_policy` | logical | yes | `true`, `false`, blank | Whether any tracked policy came from an explicit matching group. |
| `training_bots_restricted` | character | no | see grouped enum | Restriction summary for training/control tokens. |
| `search_bots_restricted` | character | no | see grouped enum | Restriction summary for search/indexing agents. |
| `user_fetch_bots_restricted` | character | no | see grouped enum | Restriction summary for user-triggered agents. |
| `gpt_bot_policy` | character | no | see policy enum | Policy for `GPTBot`. |
| `claude_bot_policy` | character | no | see policy enum | Policy for `ClaudeBot`. |
| `google_extended_policy` | character | no | see policy enum | Policy for `Google-Extended`. |
| `applebot_extended_policy` | character | no | see policy enum | Policy for `Applebot-Extended`. |
| `meta_external_agent_policy` | character | no | see policy enum | Policy for `meta-externalagent`. |
| `oai_search_bot_policy` | character | no | see policy enum | Policy for `OAI-SearchBot`. |
| `claude_search_bot_policy` | character | no | see policy enum | Policy for `Claude-SearchBot`. |
| `perplexity_bot_policy` | character | no | see policy enum | Policy for `PerplexityBot`. |
| `duck_assist_bot_policy` | character | no | see policy enum | Policy for `DuckAssistBot`. |
| `mistral_ai_index_policy` | character | no | see policy enum | Policy for `MistralAI-Index`. |
| `chatgpt_user_policy` | character | no | see policy enum | Policy for `ChatGPT-User`. |
| `claude_user_policy` | character | no | see policy enum | Policy for `Claude-User`. |
| `perplexity_user_policy` | character | no | see policy enum | Policy for `Perplexity-User`. |
| `mistral_ai_user_policy` | character | no | see policy enum | Policy for `MistralAI-User`. |
| `scan_status` | character | no | `complete`, `partial`, `failed` | Overall endpoint completion status. |

Boolean fields use lowercase `true` and `false`; unknown booleans are unquoted
empty fields and must not be read as `false`. Categorical `unknown` is an enum
value, not a missing value.

Canonical R import:

```r
source("analysis/data.R")

domains <- readr::read_csv(
  "data/processed/domains.csv",
  col_types = domain_col_types,
  na = "",
  locale = readr::locale(encoding = "UTF-8"),
  name_repair = "check_unique",
  show_col_types = FALSE,
  progress = FALSE
)

validate_domains(domains)
```

`load_domains()` wraps this import and validation. It fails if names, order,
types, duplicates, accidental index columns, parsing problems, or enum values do
not match the schema.

The Python writer also validates exact column order, unique snake-case names,
valid logical/status/policy values, per-agent `_policy` suffixes, duplicate
domains, absence of rank/index columns, scalar cells, and output row count
before atomically replacing the CSV.

### Endpoint Statuses

`llms_txt_status`:

```text
present
absent
empty
html
non_text
http_error
network_error
```

`has_llms_txt` is `true` only for `present`, `false` for known non-present
states (`absent`, `empty`, `html`, `non_text`), and blank for unresolved HTTP or
network failures.

`robots_txt_status`:

```text
parsed
absent
empty
html
non_text
unparseable
http_error
network_error
```

`robots.txt` classifications describe declared policy shape, not verified
path-level access or provider compliance.

### Per-Agent Policy Enum

Each per-agent policy column uses:

```text
allow_default
allow_explicit
allow_wildcard
partial_explicit
partial_wildcard
blocked_explicit
blocked_wildcard
unknown
```

Definitions:

- `allow_default`: no explicit or wildcard group applies;
- `allow_explicit`: an explicit matching group applies with no effective
  restriction;
- `allow_wildcard`: the wildcard group applies with no effective restriction;
- `partial_explicit`: an explicit group declares some restriction but not a
  simple full-site disallow;
- `partial_wildcard`: wildcard declares some restriction but not a simple
  full-site disallow;
- `blocked_explicit`: explicit group contains unqualified `Disallow: /`;
- `blocked_wildcard`: wildcard group contains unqualified `Disallow: /`; and
- `unknown`: robots policy could not be classified.

A full-site disallow with meaningful `Allow` exceptions is classified as
partial.

### Summary Fields

`training_bots_restricted`, `search_bots_restricted`, and
`user_fetch_bots_restricted` use:

```text
none
some
all
unknown
```

Partial and full restrictions both count as restricted. `all` means all tracked
agents in that group have some declared restriction; it does not necessarily
mean every path is blocked. `unknown` remains distinct from `none`.

`has_explicit_ai_policy` reports whether any tracked policy came from an explicit
agent group.

## Tracked Agents

| token | purpose_group | processed_column |
| --- | --- | --- |
| `GPTBot` | training | `gpt_bot_policy` |
| `ClaudeBot` | training | `claude_bot_policy` |
| `Google-Extended` | training/control token | `google_extended_policy` |
| `Applebot-Extended` | training/control token | `applebot_extended_policy` |
| `meta-externalagent` | training | `meta_external_agent_policy` |
| `OAI-SearchBot` | search/indexing | `oai_search_bot_policy` |
| `Claude-SearchBot` | search/indexing | `claude_search_bot_policy` |
| `PerplexityBot` | search/indexing | `perplexity_bot_policy` |
| `DuckAssistBot` | search/indexing | `duck_assist_bot_policy` |
| `MistralAI-Index` | search/indexing | `mistral_ai_index_policy` |
| `ChatGPT-User` | user-triggered fetching | `chatgpt_user_policy` |
| `Claude-User` | user-triggered fetching | `claude_user_policy` |
| `Perplexity-User` | user-triggered fetching | `perplexity_user_policy` |
| `MistralAI-User` | user-triggered fetching | `mistral_ai_user_policy` |

`Google-Extended` and `Applebot-Extended` are robots control tokens rather than
standalone HTTP crawlers. The official Meta crawler URL is linked from
Cloudflare Radar's verified bot directory.

User-triggered agents may be initiated by a person using a product, and some
first-party documentation states that robots rules may not apply or may
generally be ignored. This project still measures the site's declared policy
toward those tokens.

First-party references:

- OpenAI: <https://developers.openai.com/api/docs/bots>
- Anthropic: <https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler>
- Google: <https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers>
- Apple: <https://support.apple.com/en-ie/119829>
- Perplexity: <https://docs.perplexity.ai/docs/resources/perplexity-crawlers>
- Mistral: <https://docs.mistral.ai/robots>
- DuckDuckGo: <https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot>
- Meta crawler URL: <https://developers.facebook.com/docs/sharing/webmasters/web-crawlers>

## Checkpoint

Checkpoint files:

```text
data/raw/domains_checkpoint.jsonl
data/raw/domains_checkpoint.meta.json
```

The JSONL checkpoint is an internal record for the current one-shot collection,
not a duplicate of the analysis CSV. It is recreated at the start of every run
and preserves compact endpoint evidence:

```text
attempted
completed
requested_scheme
final_scheme
http_status
content_type
bytes_read
body_truncated
redirect_count
retry_count
error_type
classification
fetched_at
```

It also preserves final per-agent robots classifications. It does not store
response bodies, cookies, arbitrary headers, credentials, secrets, full
exception strings, or final URLs with query strings.

The metadata records schema version, collector version, input filename, input
SHA-256, input row count, source population, popularity bucket, tracked-agent
taxonomy digest, collection settings digest, start time, completion time, and
final status counts. Successful completion compacts the checkpoint atomically to
one record per domain.

## Analysis

Load the processed CSV from R:

```bash
RENV_CONFIG_SANDBOX_ENABLED=FALSE Rscript -e 'source("analysis/data.R"); d <- load_domains(); print(dim(d))'
```

Render the report when ready to work on narrative and figures:

```bash
quarto render
```

The report remains a draft scaffold. Final conclusions, polished charts, and
publication narrative belong in the R/Quarto phase after the full collection.

## Limitations

- Cloudflare Top 50,000 bucket membership is coarse popularity evidence, not an
  exact rank.
- `robots.txt` is a declared crawler policy mechanism, not access control.
- User-agent strings can be spoofed.
- Redirect target screening reduces obvious unsafe fetches but cannot guarantee
  perfect DNS-rebinding prevention.
- `/llms.txt` is classified only for plausible presence, not semantic quality.
- Live sites change; smoke-test outcomes should not be treated as findings.

## Attribution And License

Domain population derived from Cloudflare Radar Domain Rankings, published by
Cloudflare, Inc. Cloudflare is the source of the population, not an author or
endorser of this analysis. The Cloudflare dataset is made available under
CC BY-NC 4.0. Project code is MIT licensed.
