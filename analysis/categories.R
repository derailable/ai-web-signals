# Summarize AI-related web signals by ChatGPT-assigned domain category.
suppressPackageStartupMessages({
  library(dplyr)
  library(readr)
})

source("analysis/data.R")

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
  group_by(.data$category) |>
  summarise(
    selected_domains = n(),
    complete_scans = sum(.data$scan_status == "complete"),
    resolved_llms_txt = sum(!is.na(.data$has_llms_txt)),
    observed_llms_txt = sum(.data$has_llms_txt %in% TRUE),
    resolved_agent_policy = sum(!is.na(.data$any_ai_bot_restricted)),
    any_agent_restriction = sum(.data$any_ai_bot_restricted %in% TRUE),
    .groups = "drop"
  ) |>
  mutate(
    selected_share = .data$selected_domains / sum(.data$selected_domains),
    complete_scan_share = .data$complete_scans / .data$selected_domains,
    observed_llms_txt_share = if_else(
      .data$resolved_llms_txt > 0,
      .data$observed_llms_txt / .data$resolved_llms_txt,
      NA_real_
    ),
    any_agent_restriction_share = if_else(
      .data$resolved_agent_policy > 0,
      .data$any_agent_restriction / .data$resolved_agent_policy,
      NA_real_
    )
  ) |>
  arrange(desc(.data$selected_domains), .data$category)

dir.create("results/tables", recursive = TRUE, showWarnings = FALSE)
write_csv(
  category_summary,
  "results/tables/category-summary.csv",
  na = ""
)
