# ai-web-signals

`ai-web-signals` measures a small set of public signals showing how popular
websites are adapting to AI discovery and crawler access.

The V1 study asks:

1. Does the domain publish a plausible `/llms.txt` file?
2. Does `/robots.txt` restrict major AI training crawlers?
3. Does `/robots.txt` restrict major AI search crawlers?
4. Are those policies written specifically for AI crawlers or inherited from
   `User-agent: *`?

This is a measurement of public web signals. It is not a complete measure of AI
adoption, internal AI use, search visibility, crawler behavior, or provider
intent.

Python performs collection and deterministic parsing. R can be used for
analysis, visualization, and reporting.

## Data source

The domain population comes from
[Cloudflare Radar Domain Rankings](https://radar.cloudflare.com/domains).

For the current study, download the Top 100,000 domains CSV from Cloudflare
Radar and save the original file under `data/input/`. Include the download date
or date range in the filename.

Example:

```text
data/input/cloudflare-radar_top-100000-domains_YYYYMMDD-YYYYMMDD.csv
```

Keep the source file unchanged for provenance and reproducibility.

### Expected input

The collector accepts a CSV with these columns:

| Column       | Required | Behavior |
| ------------ | -------- | -------- |
| `domain`     | Yes      | Normalized, validated, and deduplicated |
| `rank`       | No       | Preserved when it contains an integer |
| `categories` | No       | Preserved verbatim from the input |

`hostname` or `host` can be used instead of `domain`. `ranking` can be used
instead of `rank`, and `category` can be used instead of `categories`.

Multiple category labels remain in the original field. For example:

```csv
rank,domain,categories
2,googleapis.com,Information Technology;Content Servers
9,googlevideo.com,Search Engines;Video Streaming
```

The collector does not select a primary category or split category values.

## Collect the data

The only runtime dependency is `httpx`.

Set the input path:

```bash
INPUT=data/input/cloudflare-radar_top-100000-domains_YYYYMMDD-YYYYMMDD.csv
```

Run a small sample:

```bash
uv run python collection/fetch.py "$INPUT" --limit 100 --fresh
```

Run the full collection:

```bash
uv run python collection/fetch.py "$INPUT"
```

The collector resumes automatically. Domains with a complete prior result are
skipped. Partial and failed rows are retried when the same command is run again.

Use `--fresh` only when you intend to delete the existing checkpoint and start
the collection again:

```bash
uv run python collection/fetch.py "$INPUT" --fresh
```

A checkpoint is tied to the input file contents and output schema. If either
changes, start a new run with `--fresh`.

## Collection scope

For each domain, the collector requests only:

```text
/llms.txt
/robots.txt
```

It does not request the homepage, `/llms-full.txt`, sitemaps, manifests, or
links found in either file.

The collector uses HTTPS first, follows validated redirects, and falls back to
HTTP only after selected connection or TLS failures. Response bodies are
sampled rather than downloaded without a limit.

## Data artifacts

Analysis-ready output:

```text
data/processed/domains.csv
```

Automatic checkpoint files:

```text
data/raw/domains_checkpoint.jsonl
data/raw/domains_checkpoint.meta.json
```

Generated raw and processed files are reproducible and normally should not be
committed.

## Output schema

The output CSV contains one row per normalized domain and eight columns:

| Column                  | Values | Meaning |
| ----------------------- | ------ | ------- |
| `rank`                  | integer or blank | Rank copied from the input when available |
| `domain`                | text | Normalized domain |
| `categories`            | text or blank | Category value copied verbatim from the input |
| `has_llms_txt`          | `true`, `false`, or blank | Whether a plausible public `/llms.txt` was observed |
| `training_bots_blocked` | `none`, `some`, `all`, `unknown` | How many tracked training bots have restrictive rules |
| `search_bots_blocked`   | `none`, `some`, `all`, `unknown` | How many tracked AI search bots have restrictive rules |
| `ai_policy_explicit`    | `true`, `false`, or blank | Whether an exact tracked AI user-agent group appears in `robots.txt` |
| `scan_status`           | `complete`, `partial`, `failed` | Whether both endpoint results could be classified |

Blank boolean values mean the result could not be determined. They are not the
same as `false`.

The blocking summaries count both full and partial restrictions. Therefore,
`all` means every tracked bot has some restrictive rule. It does not
necessarily mean every bot is completely blocked from the entire site.

### Tracked training bots

```text
GPTBot
ClaudeBot
Google-Extended
Applebot-Extended
Meta-ExternalAgent
```

### Tracked AI search bots

```text
OAI-SearchBot
Claude-SearchBot
PerplexityBot
```

A wildcard `User-agent: *` policy can affect the blocking summaries. However,
`ai_policy_explicit` is `true` only when `robots.txt` contains an exact group
for at least one tracked AI crawler.

## Analyze in R

Load the CSV directly:

```r
library(readr)
library(dplyr)

domains <- read_csv(
  "data/processed/domains.csv",
  na = "",
  show_col_types = FALSE
)

domains |>
  summarise(
    domains = n(),
    complete = sum(scan_status == "complete"),
    llms_txt_present = sum(has_llms_txt %in% TRUE),
    llms_txt_rate_among_known = mean(has_llms_txt, na.rm = TRUE)
  )
```

Expand semicolon-delimited categories only when an analysis needs one row per
category:

```r
library(tidyr)

categories <- domains |>
  select(domain, categories, has_llms_txt) |>
  separate_longer_delim(categories, delim = ";") |>
  mutate(categories = trimws(categories))
```

## Interpretation constraints

- Treat `scan_status` as a data-quality field and report unknown results.
- Do not treat a blank boolean as `false`.
- `has_llms_txt` measures whether a plausible public file was observed. It does
  not measure the file's quality, usefulness, or adoption by AI systems.
- `training_bots_blocked` and `search_bots_blocked` summarize restrictive
  rules. They do not prove that crawlers honor those rules.
- `ai_policy_explicit = false` can still coexist with restrictions inherited
  from `User-agent: *`.
- Preserve `categories` as source data during collection. Split or normalize it
  only in analysis.

## Provenance, license, and citation

Project code is licensed under the root [LICENSE](LICENSE). Cloudflare Radar
source data is separate third-party data made available under
[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/).

Preserve this attribution in reports and derived datasets:

> Domain population derived from Cloudflare Radar Domain Rankings, published by
> Cloudflare, Inc. at https://radar.cloudflare.com/domains and made available
> under CC BY-NC 4.0.

Cloudflare is the source of the domain population, not an author of this project
or its measurements. Cloudflare does not endorse this project or its findings.

Use [CITATION.cff](CITATION.cff) to cite `ai-web-signals` itself.
