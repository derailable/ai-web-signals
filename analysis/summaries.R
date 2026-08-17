# Build report summaries.
library(dplyr)
library(tidyr)

restrictive_policy_states <- c(
  "partial_explicit",
  "partial_wildcard",
  "blocked_explicit",
  "blocked_wildcard"
)

resolved_llms <- !is.na(domains$has_llms_txt)
resolved_explicit <- !is.na(domains$has_explicit_ai_policy)
resolved_restriction <- !is.na(domains$any_ai_bot_restricted)

key_metrics <- tibble::tribble(
  ~metric                                           , ~numerator                             , ~denominator  ,
  "Complete endpoint scans"                         , sum(domains$scan_status == "complete") , nrow(domains) ,
  "Resolved /llms.txt observations"                 , sum(resolved_llms)                     , nrow(domains) ,
  "Observed /llms.txt among resolved observations"  ,
  sum(domains$has_llms_txt, na.rm = TRUE)           ,
  sum(resolved_llms)                                ,
  "Resolved tracked-agent policy observations"      ,
  sum(resolved_restriction)                         ,
  nrow(domains)                                     ,
  "Explicit tracked-agent robots policy"            ,
  sum(domains$has_explicit_ai_policy, na.rm = TRUE) ,
  sum(resolved_explicit)
) |>
  mutate(proportion = numerator / denominator)

restriction_source_summary <- agent_policies |>
  filter(policy %in% restrictive_policy_states) |>
  mutate(
    source = if_else(
      grepl("_explicit$", policy),
      "Explicit agent rule",
      "Wildcard rule"
    )
  ) |>
  count(source, name = "count") |>
  mutate(
    denominator = sum(count),
    proportion = count / denominator
  )

content_signal_states <- c("yes", "no", "unspecified", "invalid", "unknown")

content_summary <- domains |>
  select(
    search = content_signal_search,
    ai_input = content_signal_ai_input,
    ai_train = content_signal_ai_train
  ) |>
  pivot_longer(
    cols = everything(),
    names_to = "purpose",
    values_to = "signal"
  ) |>
  count(purpose, signal, name = "count") |>
  complete(
    purpose,
    signal = content_signal_states,
    fill = list(count = 0L)
  ) |>
  group_by(purpose) |>
  mutate(
    total_domains = sum(count),
    proportion = count / total_domains,
    resolved_results = sum(count[signal != "unknown"]),
    resolved_proportion = if_else(
      signal == "unknown",
      NA_real_,
      count / resolved_results
    )
  ) |>
  ungroup() |>
  mutate(
    purpose = factor(
      purpose,
      levels = c("search", "ai_input", "ai_train"),
      labels = c("Search", "AI input", "AI training")
    ),
    signal = factor(
      signal,
      levels = content_signal_states,
      labels = c("Yes", "No", "Unspecified", "Invalid", "Unknown")
    )
  )

overlap_summary <- domains |>
  filter(!is.na(has_llms_txt), !is.na(any_ai_bot_restricted)) |>
  mutate(
    llms_txt = if_else(has_llms_txt, "Present", "Not present"),
    restriction = if_else(
      any_ai_bot_restricted,
      "Any tracked-agent restriction",
      "No tracked-agent restriction"
    )
  ) |>
  count(llms_txt, restriction, name = "count") |>
  group_by(llms_txt) |>
  mutate(
    denominator = sum(count),
    proportion = count / denominator
  ) |>
  ungroup()

category_summary <- categorized_domains |>
  group_by(category) |>
  summarise(
    selected_domains = n(),
    resolved_llms_txt = sum(!is.na(has_llms_txt)),
    observed_llms_txt = sum(has_llms_txt, na.rm = TRUE),
    resolved_agent_policy = sum(!is.na(any_ai_bot_restricted)),
    any_agent_restriction = sum(any_ai_bot_restricted, na.rm = TRUE),
    .groups = "drop"
  ) |>
  mutate(
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

# Keep category comparisons descriptive and readable. The common floor avoids
# ranking categories from a handful of resolved observations.
category_min_resolved <- 90L

category_plot_data <- category_summary |>
  filter(
    category != "Other / Unknown",
    resolved_llms_txt >= category_min_resolved,
    resolved_agent_policy >= category_min_resolved
  )
