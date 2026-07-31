source("analysis/data.R")

suppressPackageStartupMessages({
  library(dplyr)
  library(stringr)
  library(tidyr)
})


total_domains <- nrow(domains)
failed_domains <- sum(domains$scan_status == "failed")
partial_domains <- sum(domains$scan_status == "partial")
complete_domains <- sum(domains$scan_status == "complete")

metrics <- list(
  domains_analyzed = nrow(domains),
  complete_scan_rate = NULL,
  llms_txt_rate = NULL,
  explicit_ai_policy_rate = NULL,
  any_training_restriction_rate = NULL,
  any_search_restriction_rate = NULL,
  any_user_fetch_restriction_rate = NULL,
  all_training_restricted_rate = NULL,
  no_ai_restrictions_rate = NULL,
  training_restricted_search_allowed_rate = NULL,
  explicit_policy_share = NULL,
  most_restricted_agent = NULL,
  most_restricted_agent_rate = NULL
)

print(paste0("Total domains: ", total_domains))
print(paste0("Failed domains: ", failed_domains))
print(paste0("Partial domains: ", partial_domains))
print(paste0("Complete domains: ", complete_domains))
print(paste0(
  "Complete scan rate: ",
  round((complete_domains) / total_domains * 100, 2),
  "%"
))

domains |>
  count(scan_status)

domains |>
  count(robots_txt_status, sort = TRUE)

domains |>
  count(llms_txt_status, sort = TRUE)

domains |>
  count(
    robots_txt_status,
    llms_txt_status,
    sort = TRUE
  )


domains |>
  filter(
    robots_txt_status == "network_error",
    llms_txt_status == "network_error"
  ) |>
  slice_sample(n = 20) |>
  select(rank, domain)
