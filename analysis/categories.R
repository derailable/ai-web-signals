# Summarize AI-related web signals by ChatGPT-assigned domain category.
suppressPackageStartupMessages({
  library(dplyr)
  library(readr)
})

domains <- read_csv(
  "data/processed/domains.csv",
  col_types = cols_only(
    domain = col_character(),
    has_llms_txt = col_logical(),
    any_ai_bot_restricted = col_logical(),
    scan_status = col_character()
  ),
  na = "",
  progress = FALSE
)

domain_categories <- read_csv(
  "data/processed/categorized-domains.csv",
  col_types = cols(
    domain = col_character(),
    category = col_character()
  ),
  progress = FALSE
)

stopifnot(
  !anyDuplicated(domain_categories$domain),
  all(nzchar(domain_categories$category)),
  setequal(domains$domain, domain_categories$domain)
)

categorized_domains <- domains |>
  left_join(domain_categories, by = "domain")

category_summary <- categorized_domains |>
  group_by(category) |>
  summarise(
    selected_domains = n(),
    complete_scans = sum(scan_status == "complete"),
    resolved_llms_txt = sum(!is.na(has_llms_txt)),
    observed_llms_txt = sum(has_llms_txt, na.rm = TRUE),
    resolved_agent_policy = sum(!is.na(any_ai_bot_restricted)),
    any_agent_restriction = sum(any_ai_bot_restricted, na.rm = TRUE),
    .groups = "drop"
  ) |>
  mutate(
    selected_share = selected_domains / sum(selected_domains),
    complete_scan_share = complete_scans / selected_domains,
    observed_llms_txt_share = if_else(
      resolved_llms_txt > 0,
      observed_llms_txt / resolved_llms_txt,
      NA_real_
    ),
    any_agent_restriction_share = if_else(
      resolved_agent_policy > 0,
      any_agent_restriction / resolved_agent_policy,
      NA_real_
    )
  ) |>
  arrange(desc(selected_domains), category)

dir.create("results/tables", recursive = TRUE, showWarnings = FALSE)
write_csv(
  category_summary,
  "results/tables/category-summary.csv",
  na = ""
)
