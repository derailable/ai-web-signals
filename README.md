# ai-web-signals

`ai-web-signals` measures public AI discovery and crawler-access signals across
popular domains.

The study asks three narrow questions:

1. Does a domain publish a plausible `/llms.txt` file?
2. What policy does `/robots.txt` expose for major AI crawlers?
3. How do those signals vary across the Cloudflare Radar domain population?

This is not a complete measure of AI readiness, internal AI adoption, search
visibility, crawler behavior, or provider intent.

Python performs collection and deterministic parsing. R performs analysis,
visualization, and interpretation.

## Data source

The domain population comes from
[Cloudflare Radar Domain Rankings](https://radar.cloudflare.com/domains).

Cloudflare publishes:

- an ordered Top 100 list that is updated daily
- larger global top-N buckets that are updated weekly and are **unordered**

Use the Top 10,000 bucket for this study. Do not infer rank from CSV row order.
Only use `rank` when the source file contains an explicit rank field.

### Download the input CSV

1. Open <https://radar.cloudflare.com/domains>.
2. Find **Domain popularity worldwide**.
3. Open the chart's **More actions** menu and download the CSV.
4. Select the **Top 10,000** dataset.
5. Save the original file under `data/input/`, including the download date in
   the filename.

Recommended filename:

```text
data/input/cloudflare-radar_top-10000-domains_YYYYMMDD-YYYYMMDD.csv
```

Keep the downloaded file unchanged. The collector normalizes and deduplicates
`domain` values and preserves `rank` and `categories` when present.

## Collect the data

Set the input path once:

```bash
INPUT=data/input/cloudflare-radar_top-10000-domains_YYYYMMDD-YYYYMMDD.csv
```

Run a small validation sample before the full collection:

```bash
uv run python collection/fetch.py "$INPUT" \
  --limit 100 \
  --processed-output /tmp/ai-web-signals/domains.parquet \
  --checkpoint-output /tmp/ai-web-signals/domains_checkpoint.jsonl \
  --summary-output /tmp/ai-web-signals/run_summary.json \
  --overwrite
```

Run the full collection:

```bash
uv run python collection/fetch.py "$INPUT" --overwrite
```

Parquet is the primary analysis format. Generate CSV only for small manual
inspection:

```bash
uv run python collection/fetch.py "$INPUT" \
  --overwrite \
  --csv-output data/processed/domains.csv
```

The collector requests only:

```text
/llms.txt
/robots.txt
```

It does not fetch homepages, `/llms-full.txt`, sitemaps, manifests, or links
found in `llms.txt`.

## Data artifacts

Primary analysis artifact:

```text
data/processed/domains.parquet
```

Operational artifacts:

```text
data/raw/domains_checkpoint.jsonl
data/raw/domains_checkpoint.jsonl.metadata.json
data/raw/run_summary.json
data/processed/domains.parquet.metadata.json
```

Generated raw and processed files should be reproducible and normally should
not be committed.

## Analysis variables

The Parquet file contains one row per normalized domain and retains four groups
of variables:

| Group             | Main variables                                                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Source            | `rank`, `domain`, `categories`                                                                                                          |
| `/llms.txt`       | URL, HTTP status, outcome, presence, content type, bytes read, truncation, H1, heading count, link count, and `llms-full.txt` reference |
| `/robots.txt`     | URL, HTTP status, outcome, presence, content type, bytes read, truncation, and parse error                                              |
| AI crawler policy | Directive and directive source for GPTBot, OAI-SearchBot, ClaudeBot, Claude-SearchBot, PerplexityBot, and Google-Extended               |

Crawler directives use these values:

```text
allow
partial_allow
partial_disallow
disallow
none
error
```

Directive sources use:

```text
explicit
wildcard
none
error
```

`explicit` means an exact crawler user-agent group supplied the policy.
`wildcard` means the policy was inherited from `User-agent: *`.
`none` means no applicable rule was found. `error` means the robots response
could not be classified.

Use `*_outcome` and `collection_complete` as data-quality variables. Do not
analyze only the convenience booleans such as `llms_txt_present`.

## Analyze in R

Load the compact dataset directly:

```r
library(arrow)
library(dplyr)

domains <- read_parquet("data/processed/domains.parquet")

domains |>
  summarise(
    domains = n(),
    complete = mean(collection_complete),
    llms_txt_adoption = mean(llms_txt_present),
    robots_txt_available = mean(robots_txt_present)
  )
```

Expand categories during analysis rather than collection:

```r
library(tidyr)

categories <- domains |>
  select(domain, categories, llms_txt_present) |>
  separate_longer_delim(categories, delim = ";")
```

For larger exploratory queries, use `open_dataset()` to select columns before
collecting them into memory.

## Interpretation constraints

- The Top 10,000 file is an unordered membership bucket, not a precise ranking.
- `llms_txt_present` means a plausible public file was observed. It does not
  measure quality, usefulness, or adoption by AI systems.
- `none` is a valid crawler-policy result. It is not equivalent to `error`.
- Network and HTTP failures are measurement outcomes and should remain visible
  in denominators and sensitivity checks.
- Category values may contain multiple semicolon-delimited labels and should be
  expanded only when the analysis requires it.

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
