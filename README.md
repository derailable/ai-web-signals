# ai-web-signals

`ai-web-signals` measures public AI-related signals across the Tranco Top
100,000 pay-level domains:

- plausible `/llms.txt` presence;
- `robots.txt` policy for documented AI-related agents and control tokens; and
- site-wide `Content-Signal` preferences.

These are published signals, not evidence of crawler compliance, provider
behavior, legal permission, or internal AI adoption.

## Quick start

Requires Python 3.11+, [`uv`](https://docs.astral.sh/uv/), R, and
[Quarto](https://quarto.org/).

```bash
uv sync
Rscript -e 'renv::restore()'
./scripts/fetch_tranco.sh
uv run python collection/fetch.py
quarto render
```

The collector requests only `/llms.txt` and `/robots.txt`. It uses HTTPS first,
bounded concurrency and response sizes, TLS verification, and screened redirect
targets.

## Data

Generated data and rendered outputs are local-only and ignored by Git:

```text
data/input/
data/processed/
results/
_site/
```

The collector writes:

- `data/processed/domains.csv`: one row per ranked domain;
- `data/processed/agent-policies.csv`: one row per domain and tracked agent.

Load and validate both datasets in R:

```r
source("analysis/data.R")

domains <- load_domains()
agent_policies <- load_agent_policies(domains)
```

Blank logical values and categorical `unknown` values mean unresolved, not
`false` or unrestricted. Group restrictions use `none`, `some`, `all`, and
`unknown`; partial and full restrictions both count as restrictive.

Tracked groups:

- Training/control: GPTBot, ClaudeBot, Google-Extended, Applebot-Extended,
  meta-externalagent, MistralAI-Training
- AI search: OAI-SearchBot, Claude-SearchBot, PerplexityBot, DuckAssistBot,
  MistralAI-Index
- User-triggered fetch: ChatGPT-User, Claude-User, Perplexity-User,
  MistralAI-User

The rendered report writes summary tables to `results/tables/`, figures to
`results/figures/`, and HTML to `_site/`.

## Interpretation

The current inventory uses Tranco list 26J39, generated 16 August 2026.[^list]
The list was fetched and the scan was run on 16 August 2026. Tranco rank is an
aggregate rank, not traffic volume or HTTP reachability.

[^list]: Available at <https://tranco-list.eu/list/26J39/1000000>.

Analysis distinguishes all selected domains from resolved endpoint and policy
observations. Unresolved observations are never recoded as negative results.
Because endpoint failures may be non-random, resolved-subset proportions should
not be generalized to all selected domains.

`robots.txt` and Content Signals express declared policy or preference; they do
not prove enforcement. `/llms.txt` is classified for plausible presence, not
semantic quality. Results are a time-bound descriptive snapshot.

## Citation

Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński,
and Wouter Joosen. 2019. “Tranco: A Research-Oriented Top Sites Ranking Hardened
Against Manipulation,” *Proceedings of the 26th Annual Network and Distributed
System Security Symposium (NDSS 2019).* <https://doi.org/10.14722/ndss.2019.23386>

Tranco and its source providers are not affiliated with this project and do not
endorse it. Project code is MIT licensed.
