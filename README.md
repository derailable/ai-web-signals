# ai-web-signals

`ai-web-signals` measures a narrow set of public web signals across the Tranco
Top 100,000 standard domains:

1. whether a plausible `/llms.txt` is published;
2. how `/robots.txt` declares policy for documented AI-related agents; and
3. whether that policy is explicit to a tracked agent or inherited from
   `User-agent: *`; and
4. site-wide `Content-Signal` declarations for search, AI input, and AI
   training.

This is a measurement of published site policy and public discovery signals. It
does not prove crawler compliance, AI-provider behavior, search visibility,
internal AI adoption, or legal permission.

Python performs collection and deterministic parsing. R performs loading,
validation, summaries, visualization, and report work.

## Repository Data Policy

Generated data and rendered outputs are local-only:

```text
data/input/
data/processed/
results/tables/
results/figures/
_site/
```

Keep original source files under `data/input/` for local provenance. Do not
commit processed CSVs, figures, or rendered reports.

## Data Source

This project uses the top 100,000 domains from the standard Tranco list PYGVJ,
generated on July 29, 2026. The exact list is available at
<https://tranco-list.eu/list/PYGVJ>.

The standard Tranco list uses pay-level domains and does not include subdomain
entries. This project preserves Tranco rank and scans the first 100,000 ranked
domains only. The one-million-domain upstream source is stored at
`data/input/top-1m.csv`; the normalized scanner input is
`data/input/tranco-top-100000.csv`.

List PYGVJ aggregates rankings from Chrome UX Report (CrUX), Farsight,
Majestic, Cloudflare Radar, and Cisco Umbrella over the 30-day period from
June 30, 2026 through July 29, 2026. Tranco combines the source lists using the
Dowdall rule, retains pay-level domains, and uses the first one million domains
from each available source. Tranco rank is an aggregate rank; it is not traffic
volume, exact visitor count, page views, or a direct measurement of HTTP
reachability.

Tranco currently aggregates lists from Cisco Umbrella, Majestic, Farsight, the
Chrome User Experience Report (CrUX), and Cloudflare Radar. Cisco Umbrella is
available free of charge; Majestic is available under CC BY 3.0; CrUX is
available under CC BY-SA 4.0; and Cloudflare Radar is available under
CC BY-NC 4.0. Tranco is not affiliated with these providers, and Tranco does not
endorse this project.

Required citation:

Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej
Korczyński, and Wouter Joosen. 2019. "Tranco: A Research-Oriented Top Sites
Ranking Hardened Against Manipulation." Proceedings of the 26th Annual Network
and Distributed System Security Symposium (NDSS 2019).
<https://doi.org/10.14722/ndss.2019.23386>

## Expected Input

The collector accepts the prepared UTF-8 Tranco Top 100K CSV:

| Column | Required | Aliases | Behavior |
| --- | --- | --- | --- |
| `rank` | Yes | none | Tranco aggregate rank, validated as unique sequential integers from 1 through 100000. |
| `domain` | Yes | none | Pay-level domain, normalized with IDNA, lowercased, trailing dot removed, validated, and deduplicated. |

The prepared input must contain exactly 100,000 data rows and this header:

```csv
rank,domain
1,example.com
2,example.org
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

Fetch the standard Tranco list without subdomains and prepare the scanner input:

```bash
./scripts/fetch_tranco.sh
```

The fetch script writes:

```text
data/input/top-1m.csv
data/input/tranco-top-100000.csv
data/input/tranco-metadata.json
```

`top-1m.csv` is the upstream source, `tranco-top-100000.csv` is the normalized
scanner input, and `tranco-metadata.json` records provenance. Rerunning the
fetch script overwrites these files and may change the list ID because Tranco
updates daily.

Run the full Tranco Top 100,000 collection:

```bash
uv run python collection/fetch.py
```

For a smoke collection, pass a smaller temporary Tranco-style CSV as the input
file from test code or a local harness. Production scans use
`data/input/tranco-top-100000.csv`.

Each successful run stages both processed datasets in rank order in temporary
local CSVs, validates them, then atomically replaces each previous processed
CSV only after every input row is written. The collector does not write
checkpoint or metadata files.

Defaults favor a one-shot collection: 50 domain workers, 50 concurrent HTTP
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

- one shared asynchronous `httpx` client with HTTP/2 enabled when supported;
- bounded worker and request concurrency;
- explicit connect, read, write, and pool timeouts;
- HTTPS first;
- HTTP fallback only after selected pre-response connection, protocol, timeout,
  or TLS failures;
- no HTTP fallback after an HTTP response or application-level result;
- HTTP/HTTPS redirects only, with a redirect limit;
- redirect targets screened for credentials and unsafe address classes;
- bounded streaming body reads;
- TLS verification remains enabled; and
- user agent:
  `AIWebSignals/<version> (+https://github.com/derailable/ai-web-signals)`.

The redirect DNS safety cache is a practical defense, not a proof against every
DNS-rebinding race inside the HTTP stack.

## Processed CSVs

Domain-level analysis output is atomically written to:

```text
data/processed/domains.csv
```

The file is UTF-8 CSV, one row per normalized ranked domain, deterministic in
Tranco rank order, and contains no response bodies or raw HTTP diagnostics.

Table grain: one row represents one normalized source domain and its collected
AI web signals. There are no row names, index columns, nested JSON cells,
domain categories, or one-row-per-bot expansions.

Exact ordered schema:

| column | r_type | nullable | allowed_values | description |
| --- | --- | --- | --- | --- |
| `rank` | integer | no | 1 through 100000 | Tranco aggregate rank in the selected standard list. |
| `domain` | character | no | normalized hostname | ASCII/IDNA normalized source domain. |
| `has_llms_txt` | logical | yes | `true`, `false`, blank | True only for plausible observed `/llms.txt`; blank when unresolved. |
| `llms_txt_status` | character | no | see endpoint enums | `/llms.txt` endpoint classification. |
| `robots_txt_status` | character | no | see endpoint enums | `/robots.txt` endpoint classification. |
| `content_signal_search` | character | no | see Content Signal enum | Site-wide published preference for search use. |
| `content_signal_ai_input` | character | no | see Content Signal enum | Site-wide published preference for AI input use. |
| `content_signal_ai_train` | character | no | see Content Signal enum | Site-wide published preference for AI training use. |
| `has_explicit_ai_policy` | logical | yes | `true`, `false`, blank | Whether any tracked AI bot is explicitly addressed. |
| `any_ai_bot_restricted` | logical | yes | `true`, `false`, blank | Whether any tracked AI bot in any group is restricted. |
| `training_bots_restricted` | character | no | see grouped enum | Restriction summary for training/control tokens. |
| `search_bots_restricted` | character | no | see grouped enum | Restriction summary for search/indexing agents. |
| `user_fetch_bots_restricted` | character | no | see grouped enum | Restriction summary for user-triggered agents. |
| `scan_status` | character | no | `complete`, `partial`, `failed` | Overall endpoint completion status. |

Boolean fields use lowercase `true` and `false`; unknown booleans are unquoted
empty fields and must not be read as `false`. Categorical `unknown` is an enum
value, not a missing value.

Canonical R import:

```r
source("analysis/data.R")

agent_policies <- load_agent_policies(domains = domains)
```

The loaders fail if names, order, types, duplicates, accidental index columns,
parsing problems, relationships, or enum values do not match their schemas.

The Python writer also validates both staged CSVs before publication, including
their exact schemas, deterministic ordering, enum values, rank/domain
relationships, and expected row counts.

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

### Content Signals

The three `content_signal_*` fields retain site-wide `Content-Signal`
declarations from a `User-agent: *` group. They are separate from crawler access
policy: `Allow` and `Disallow` classify whether an agent may crawl, while
Content Signals publish purpose-level preferences for how content may be used.

Each field uses:

```text
yes
no
unspecified
invalid
unknown
```

`yes` and `no` are explicit declarations. `unspecified` means an absent, empty,
or successfully parsed `robots.txt` has no applicable site-wide declaration for
that purpose. `invalid` means the purpose was named but its declaration was
malformed or conflicted with another applicable declaration. `unknown` means
the robots observation could not be reliably evaluated.

Directive and purpose names are case-insensitive, with optional whitespace
around comma-separated assignments. Repeated identical values agree;
conflicting values are `invalid` because the first-party documentation does not
define precedence. Agent-specific and path-specific declarations are not
collapsed into domain-wide values. See <https://contentsignals.org/>.

Content Signals are published preferences. They do not prove crawler
compliance, confer technical access control, or establish legal permission.

### Internal Policy Enum

The scanner uses these per-agent policy values to compute the grouped fields in
`domains.csv` and also retains them at agent grain in
`data/processed/agent-policies.csv`:

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

### Agent Policy CSV

`data/processed/agent-policies.csv` contains exactly one row per normalized
domain and tracked agent. It is ordered by Tranco rank and then by the canonical
agent order below. For 100,000 domains and the current 15 agents, it contains
1,500,000 rows.

Exact ordered schema:

| column | r_type | nullable | allowed_values | description |
| --- | --- | --- | --- | --- |
| `rank` | integer | no | 1 through 100000 | Tranco aggregate rank. |
| `domain` | character | no | normalized hostname | Source domain. |
| `agent` | character | no | tracked agents | Canonical robots token. |
| `purpose_group` | character | no | `training`, `search`, `user_fetch` | Stable project purpose group. |
| `policy` | character | no | policy enum above | Parsed agent-specific or inherited crawl policy. |

Like `domains.csv`, this generated dataset is local-only. Agent rows are written
to a temporary CSV alongside each ordered domain result rather than retained as
millions of Python dictionaries.

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
mean every path is blocked. `none` means all tracked bots in the group are known
and none are restricted. `some` means at least one tracked bot is restricted and
at least one is not restricted. `unknown` remains distinct from `none` and means
the group could not be reliably determined.

`any_ai_bot_restricted` is `true` when at least one tracked AI bot in any group
is restricted, `false` when all tracked groups are known and unrestricted, and
blank when the result cannot be determined.

`has_explicit_ai_policy` reports whether any tracked AI bot was explicitly named
by a robots group. A generic `User-agent: *` rule is not counted as an explicit
AI policy.

## Tracked Agents

| token | purpose_group |
| --- | --- |
| `GPTBot` | training |
| `ClaudeBot` | training |
| `Google-Extended` | training/control token |
| `Applebot-Extended` | training/control token |
| `meta-externalagent` | training |
| `MistralAI-Training` | training |
| `OAI-SearchBot` | search/indexing |
| `Claude-SearchBot` | search/indexing |
| `PerplexityBot` | search/indexing |
| `DuckAssistBot` | search/indexing |
| `MistralAI-Index` | search/indexing |
| `ChatGPT-User` | user-triggered fetching |
| `Claude-User` | user-triggered fetching |
| `Perplexity-User` | user-triggered fetching |
| `MistralAI-User` | user-triggered fetching |

`Google-Extended` and `Applebot-Extended` are robots control tokens rather than
standalone HTTP crawlers. The Meta crawler URL is included as a first-party
reference for the tracked Meta token.

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

## Analysis

Methodology statement:

We scanned the top 100,000 pay-level domains from the standard Tranco list for
publicly observable AI-related signals in `robots.txt` and `llms.txt`.

Analysis denominators should distinguish all 100,000 ranked domains selected,
domains for which an HTTP response was observed, domains with successfully
parsed `robots.txt`, and domains with a determined AI-policy result. Failed
network observations are not negative AI-policy observations.

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

- Tranco rank is an aggregate pay-level-domain rank, not measured traffic,
  exact visitors, page views, or HTTP reachability.
- `robots.txt` is a declared crawler policy mechanism, not access control.
- User-agent strings can be spoofed.
- Redirect target screening reduces obvious unsafe fetches but cannot guarantee
  perfect DNS-rebinding prevention.
- `/llms.txt` is classified only for plausible presence, not semantic quality.
- Live sites change; smoke-test outcomes should not be treated as findings.

## Attribution And License

Domain population derived from the standard Tranco list. Tranco currently
aggregates lists from Cisco Umbrella, Majestic, Farsight, the Chrome User
Experience Report (CrUX), and Cloudflare Radar. Cisco Umbrella is available free
of charge; Majestic is available under CC BY 3.0; CrUX is available under
CC BY-SA 4.0; and Cloudflare Radar is available under CC BY-NC 4.0. Tranco is
not affiliated with these providers and does not endorse this analysis. Project
code is MIT licensed.
