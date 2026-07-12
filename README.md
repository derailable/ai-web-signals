# ai-web-signals

`ai-web-signals` measures a small set of public signals showing how popular
domains are adapting to AI discovery and crawler access.

The V1 study asks:

1. Does the domain publish a plausible `/llms.txt` file?
2. Does `/robots.txt` restrict major AI training crawlers?
3. Does `/robots.txt` restrict major AI search crawlers?
4. Does `/robots.txt` restrict user-triggered AI fetch agents?
5. Are those policies written specifically for tracked AI agents or inherited
   from `User-agent: *`?

This is a measurement of public web signals. It is not a complete measure of AI
adoption, internal AI use, search visibility, crawler behavior, or provider
intent.

Python performs collection and deterministic parsing. R can be used for
analysis, visualization, and reporting.

## Repository data policy

This repository is set up to commit code, documentation, and reproducibility
metadata, not study data or rendered outputs.

The following paths are local-only and ignored by git:

```text
data/input/
data/raw/
data/processed/
results/tables/
results/figures/
_site/
```

To rerun the project, bring or generate the local data files described below.
The report reads `data/processed/domains.csv`; it does not require committed
generated tables, figures, or HTML from a previous run.

## Quick start

Prerequisites:

- Python 3.11 or newer with `uv`
- R with `renv`
- Quarto

From a clean clone, restore the R environment:

```bash
Rscript -e 'renv::restore()'
```

Add a Cloudflare Radar domain ranking CSV under `data/input/`, then collect the
processed dataset:

```bash
mkdir -p data/input
INPUT=data/input/cloudflare-radar_top-100000-domains_YYYYMMDD-YYYYMMDD.csv
uv run python collection/fetch.py "$INPUT"
```

Render the report and regenerate tables and figures:

```bash
quarto render
```

If you already have a compatible processed file, place it at
`data/processed/domains.csv` and run only the R restore and Quarto render
steps.

```bash
mkdir -p data/processed
```

If `renv` sandbox activation hangs on a local machine, use a command-scoped
workaround instead of changing the project `.Rprofile`:

```bash
RENV_CONFIG_SANDBOX_ENABLED=FALSE quarto render
```

## Output for publication

The most portable publication artifacts are the generated PNG figures and CSV
tables:

```text
results/figures/01-llms-adoption-by-rank.png
results/figures/02-ai-bot-policy-by-purpose.png
results/figures/03-explicit-vs-inherited-policy.png
results/figures/04-discovery-and-restriction.png

results/tables/key_metrics.csv
results/tables/rank_band_summary.csv
results/tables/bot_policy_summary.csv
results/tables/category_summary.csv
```

Use `_site/index.html` as the review report: it shows the tables, plots,
methodology notes, TODOs, and attribution in one place. For a PDF, the simplest
portable path is to render the HTML report and print or export it to PDF from a
browser. Quarto PDF rendering can also work on machines with a TeX installation,
but it is not required for this project.

Before publishing any chart or table, rerun:

```bash
quarto render
```

Then verify the claim text against `results/tables/`, not against copied values.

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

| Column       | Required | Behavior                                |
| ------------ | -------- | --------------------------------------- |
| `domain`     | Yes      | Normalized, validated, and deduplicated |
| `rank`       | No       | Preserved when it contains an integer   |
| `categories` | No       | Preserved verbatim from the input       |

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

The `data/` directory is entirely local and ignored by git. Create the
subdirectories as needed when collecting or supplying data.

## Output schema

The output CSV contains one row per normalized domain and nine columns:

| Column                    | Values                           | Meaning                                                                |
| ------------------------- | -------------------------------- | ---------------------------------------------------------------------- |
| `rank`                    | integer or blank                 | Rank copied from the input when available                              |
| `domain`                  | text                             | Normalized domain                                                      |
| `categories`              | text or blank                    | Category value copied verbatim from the input                          |
| `has_llms_txt`            | `true`, `false`, or blank        | Whether a plausible public `/llms.txt` was observed                    |
| `training_bots_blocked`   | `none`, `some`, `all`, `unknown` | How many tracked training bots have restrictive rules                  |
| `search_bots_blocked`     | `none`, `some`, `all`, `unknown` | How many tracked AI search bots have restrictive rules                 |
| `user_fetch_bots_blocked` | `none`, `some`, `all`, `unknown` | How many tracked user-triggered AI fetch agents have restrictive rules |
| `policy_explicit`         | `true`, `false`, or blank        | Whether an exact tracked AI user-agent group appears in `robots.txt`   |
| `scan_status`             | `complete`, `partial`, `failed`  | Whether both endpoint results could be classified                      |

Blank boolean values mean the result could not be determined. They are not the
same as `false`.

The blocking summaries count both full and partial restrictions. Therefore,
`all` means every tracked bot has some restrictive rule. It does not
necessarily mean every tracked bot is restricted from every path on the domain.

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
DuckAssistBot
MistralAI-Index
```

### Tracked user-fetch agents

```text
ChatGPT-User
Claude-User
Perplexity-User
MistralAI-User
```

User-fetch agents represent retrieval initiated on behalf of a user. They are
reported separately from automated training and AI search crawlers.

A wildcard `User-agent: *` policy can affect all three blocking summaries.
However, `policy_explicit` is `true` only when `robots.txt` contains an exact
group for at least one tracked AI agent.

## Report and analysis in R

The report title is **AI Web Signals** with the subtitle **How Popular Domains
Are Responding to AI**.

Python owns collection, endpoint classification, crawler-policy parsing,
checkpointing, and processed CSV creation. R owns validation of the processed
dataset, statistical summaries, rank-band analysis, category expansion, tables,
visualization, and reporting.

The analysis code is intentionally small:

```text
analysis/data.R       # loading, validation, rank bands, category expansion
analysis/summaries.R  # metric definitions and denominator choices
analysis/plots.R      # chart theme, figures, and plot-saving helper
index.qmd             # report skeleton and explicit artifact generation
_quarto.yml           # single-report Quarto project configuration
```

Restore the R environment, then render the report from the repository root:

```bash
Rscript -e 'renv::restore()'
quarto render
```

The rendered HTML is written under `_site/`. During render, the report writes
analysis tables and publication figures to:

```text
results/tables/
results/figures/
```

Generated tables and figures are reproducible analysis outputs and are ignored
by default unless the project later decides to publish a specific artifact.

## Interpretation constraints

- Treat `scan_status` as a data-quality field and report unknown results.
- Do not treat a blank boolean as `false`.
- `has_llms_txt` measures whether a plausible public file was observed. It does
  not measure the file's quality, usefulness, or adoption by AI systems.
- `training_bots_blocked`, `search_bots_blocked`, and
  `user_fetch_bots_blocked` summarize restrictive rules. They do not prove
  that providers honor those rules.
- `user_fetch_bots_blocked` measures declared access policy for user-triggered
  retrieval. It does not prove whether a provider will or will not fetch a page
  in response to a user request.
- `policy_explicit = false` can still coexist with restrictions inherited from
  `User-agent: *`.
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
