# ai-web-signals

A reproducible descriptive scan of public AI-related signals across the Tranco
Top 100,000 pay-level domains:

- plausible `/llms.txt` presence;
- `robots.txt` rules applicable to documented AI agents; and
- site-wide `Content-Signal` preferences.

These are published signals—not evidence of permission, compliance, provider
behavior, or AI adoption.

## Run

Requires Python 3.11+, [`uv`](https://docs.astral.sh/uv/), R, and
[Quarto](https://quarto.org/).

```bash
uv sync
Rscript -e 'renv::restore()'
./scripts/fetch_tranco.sh
uv run python collection/fetch.py
quarto render
```

The collector requests only `/llms.txt` and `/robots.txt`, using HTTPS first,
bounded concurrency and response sizes, TLS verification, and screened
redirects.

## Data model

The collector writes two tidy CSVs:

- `data/processed/domains.csv`: one observation per ranked domain;
- `data/processed/agent-policies.csv`: one observation per domain-agent pair.

Load them with fixed `readr` column types:

```r
source("analysis/data.R")
```

Analysis uses `readr`, `dplyr`/`tidyr`, `ggplot2`, and `gt`. Blank logical
values and `unknown` categories mean unresolved—not `false`, absent, allowed,
or unrestricted. Group states are `none`, `some`, `all`, and `unknown`;
partial and full rules both count as restrictive. Agent-level states preserve
whether a rule was explicit or inherited from `User-agent: *`.

Tracked groups:

- Training/control: GPTBot, ClaudeBot, Google-Extended, Applebot-Extended,
  meta-externalagent, MistralAI-Training
- AI search: OAI-SearchBot, Claude-SearchBot, PerplexityBot, DuckAssistBot,
  MistralAI-Index
- User-triggered fetch: ChatGPT-User, Claude-User, Perplexity-User,
  MistralAI-User

### Domain categories

`data/processed/categorized-domains.csv` contains exploratory ChatGPT-assigned
categories for all 100,000 domains.

```bash
Rscript analysis/categories.R
```

The script validates and joins the categories, then writes coverage and signal
rates to `results/tables/category-summary.csv`. Treat the labels as exploratory:
85,039 domains are `Other / Unknown`, and some categories are small.

## Estimation and outputs

All proportions are descriptive and use the denominator shown. Endpoint
missingness may be non-random, so resolved-subset results are not prevalence
estimates for all selected domains. The analysis applies no imputation,
weighting, or inferential tests.

Rendering writes CSV summaries to `results/tables/`, PNG figures to
`results/figures/`, and HTML to `_site/`. Generated inputs and outputs under
`data/input/`, `data/processed/`, `results/`, and `_site/` are ignored by Git.

The current snapshot uses [Tranco list 645ZX](https://tranco-list.eu/list/645ZX),
generated 15 August 2026 and scanned 16 August 2026. Tranco rank is an aggregate
rank—not traffic, audience size, or HTTP reachability.

## Citation

Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., Korczyński, M., and
Joosen, W. (2019). “Tranco: A Research-Oriented Top Sites Ranking Hardened
Against Manipulation.” *NDSS 2019.*
<https://doi.org/10.14722/ndss.2019.23386>

Tranco and its source providers do not endorse this project. Code is MIT
licensed.
