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
resolved_training <- domains$training_bots_restricted != "unknown"
resolved_search <- domains$search_bots_restricted != "unknown"
resolved_user_fetch <- domains$user_fetch_bots_restricted != "unknown"
resolved_training_search <- resolved_training & resolved_search

key_metrics <- tibble::tribble(
  ~metric, ~numerator, ~denominator,
  "Domains selected", nrow(domains), NA_integer_,
  "Complete endpoint scans", sum(domains$scan_status == "complete"), nrow(domains),
  "Resolved /llms.txt observations", sum(resolved_llms), nrow(domains),
  "Observed /llms.txt among resolved observations",
  sum(domains$has_llms_txt %in% TRUE),
  sum(resolved_llms),
  "Resolved tracked-agent policy observations",
  sum(resolved_restriction),
  nrow(domains),
  "Explicit tracked-agent robots policy",
  sum(domains$has_explicit_ai_policy %in% TRUE),
  sum(resolved_explicit),
  "Any declared training/control restriction",
  sum(domains$training_bots_restricted %in% c("some", "all")),
  sum(resolved_training),
  "Any declared AI search restriction",
  sum(domains$search_bots_restricted %in% c("some", "all")),
  sum(resolved_search),
  "Any declared user-triggered fetch restriction",
  sum(domains$user_fetch_bots_restricted %in% c("some", "all")),
  sum(resolved_user_fetch),
  "No declared restriction for tracked agents",
  sum(domains$any_ai_bot_restricted %in% FALSE),
  sum(resolved_restriction),
  "Training/control restricted; AI search unrestricted",
  sum(
    resolved_training_search &
      domains$training_bots_restricted %in% c("some", "all") &
      domains$search_bots_restricted == "none"
  ),
  sum(resolved_training_search)
) |>
  mutate(proportion = .data$numerator / .data$denominator)

restriction_source_summary <- agent_policies |>
  filter(.data$policy %in% restrictive_policy_states) |>
  mutate(
    source = if_else(
      grepl("_explicit$", .data$policy),
      "Explicit agent rule",
      "Wildcard rule"
    )
  ) |>
  count(.data$source, name = "count") |>
  mutate(
    denominator = sum(.data$count),
    proportion = .data$count / .data$denominator
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
  count(.data$purpose, .data$signal, name = "count") |>
  group_by(.data$purpose) |>
  mutate(
    total_domains = sum(.data$count),
    proportion = .data$count / .data$total_domains,
    resolved_results = sum(.data$count[.data$signal != "unknown"]),
    resolved_proportion = if_else(
      .data$signal == "unknown",
      NA_real_,
      .data$count / .data$resolved_results
    )
  ) |>
  ungroup() |>
  mutate(
    purpose = factor(
      .data$purpose,
      levels = c("search", "ai_input", "ai_train"),
      labels = c("Search", "AI input", "AI training")
    ),
    signal = factor(
      .data$signal,
      levels = content_signal_states,
      labels = c("Yes", "No", "Unspecified", "Invalid", "Unknown")
    )
  )

overlap_summary <- domains |>
  filter(!is.na(.data$has_llms_txt), !is.na(.data$any_ai_bot_restricted)) |>
  mutate(
    llms_txt = if_else(.data$has_llms_txt, "Present", "Not present"),
    restriction = if_else(
      .data$any_ai_bot_restricted,
      "Any tracked-agent restriction",
      "No tracked-agent restriction"
    )
  ) |>
  count(.data$llms_txt, .data$restriction, name = "count") |>
  group_by(.data$llms_txt) |>
  mutate(
    denominator = sum(.data$count),
    proportion = .data$count / .data$denominator
  ) |>
  ungroup()
