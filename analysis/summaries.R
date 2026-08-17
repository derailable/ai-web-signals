# Summary logic for AI Web Signals.

suppressPackageStartupMessages({
  library(dplyr)
  library(tidyr)
})

restrictive_policy_states <- c(
  "partial_explicit",
  "partial_wildcard",
  "blocked_explicit",
  "blocked_wildcard"
)

explicit_policy_states <- c(
  "allow_explicit",
  "partial_explicit",
  "blocked_explicit"
)

safe_proportion <- function(numerator, denominator) {
  dplyr::if_else(
    is.na(denominator) | denominator == 0,
    NA_real_,
    as.numeric(numerator) / denominator
  )
}

metric_row <- function(metric, numerator, denominator = NA_integer_) {
  tibble::tibble(
    metric = metric,
    numerator = as.integer(numerator),
    denominator = as.integer(denominator),
    proportion = if (is.na(denominator)) {
      NA_real_
    } else {
      safe_proportion(numerator, denominator)
    }
  )
}

add_rank_bands <- function(domains) {
  domains |>
    mutate(
      rank_band = cut(
        .data$rank,
        breaks = c(0, 100, 1000, 10000, Inf),
        labels = c(
          "1–100",
          "101–1,000",
          "1,001–10,000",
          "10,001–100,000"
        ),
        right = TRUE
      )
    )
}

summarise_scan_quality <- function(domains) {
  domains |>
    count(.data$scan_status, name = "count") |>
    complete(scan_status = scan_states, fill = list(count = 0L)) |>
    mutate(
      scan_status = factor(.data$scan_status, levels = scan_states),
      total_domains = nrow(domains),
      proportion = .data$count / .data$total_domains
    ) |>
    arrange(.data$scan_status)
}

summarise_endpoint_statuses <- function(domains) {
  bind_rows(
    domains |>
      count(status = .data$llms_txt_status, name = "count") |>
      mutate(endpoint = "llms.txt"),
    domains |>
      count(status = .data$robots_txt_status, name = "count") |>
      mutate(endpoint = "robots.txt")
  ) |>
    mutate(
      total_domains = nrow(domains),
      proportion = .data$count / .data$total_domains
    ) |>
    select(endpoint, status, count, total_domains, proportion)
}

summarise_key_metrics <- function(domains) {
  resolved_llms <- !is.na(domains$has_llms_txt)
  resolved_explicit <- !is.na(domains$has_explicit_ai_policy)
  resolved_restriction <- !is.na(domains$any_ai_bot_restricted)
  resolved_training <- domains$training_bots_restricted != "unknown"
  resolved_search <- domains$search_bots_restricted != "unknown"
  resolved_user_fetch <- domains$user_fetch_bots_restricted != "unknown"
  resolved_training_search <- resolved_training & resolved_search

  bind_rows(
    metric_row("Domains selected", nrow(domains)),
    metric_row(
      "Complete endpoint scans",
      sum(domains$scan_status == "complete"),
      nrow(domains)
    ),
    metric_row(
      "Resolved /llms.txt observations",
      sum(resolved_llms),
      nrow(domains)
    ),
    metric_row(
      "Observed /llms.txt among resolved observations",
      sum(domains$has_llms_txt %in% TRUE),
      sum(resolved_llms)
    ),
    metric_row(
      "Resolved tracked-agent policy observations",
      sum(resolved_restriction),
      nrow(domains)
    ),
    metric_row(
      "Explicit tracked-agent robots policy",
      sum(domains$has_explicit_ai_policy %in% TRUE),
      sum(resolved_explicit)
    ),
    metric_row(
      "Any declared training/control restriction",
      sum(domains$training_bots_restricted %in% c("some", "all")),
      sum(resolved_training)
    ),
    metric_row(
      "Any declared AI search restriction",
      sum(domains$search_bots_restricted %in% c("some", "all")),
      sum(resolved_search)
    ),
    metric_row(
      "Any declared user-triggered fetch restriction",
      sum(domains$user_fetch_bots_restricted %in% c("some", "all")),
      sum(resolved_user_fetch)
    ),
    metric_row(
      "No declared restriction for tracked agents",
      sum(domains$any_ai_bot_restricted %in% FALSE),
      sum(resolved_restriction)
    ),
    metric_row(
      "Training/control restricted; AI search unrestricted",
      sum(
        resolved_training_search &
          domains$training_bots_restricted %in% c("some", "all") &
          domains$search_bots_restricted == "none"
      ),
      sum(resolved_training_search)
    )
  )
}

summarise_rank_bands <- function(domains) {
  add_rank_bands(domains) |>
    group_by(.data$rank_band, .drop = FALSE) |>
    summarise(
      total_domains = n(),
      resolved_llms_results = sum(!is.na(.data$has_llms_txt)),
      llms_txt_present = sum(.data$has_llms_txt %in% TRUE),
      llms_txt_proportion = safe_proportion(
        .data$llms_txt_present,
        .data$resolved_llms_results
      ),
      resolved_training_results = sum(
        .data$training_bots_restricted != "unknown"
      ),
      training_restricted = sum(
        .data$training_bots_restricted %in% c("some", "all")
      ),
      training_restricted_proportion = safe_proportion(
        .data$training_restricted,
        .data$resolved_training_results
      ),
      .groups = "drop"
    )
}

summarise_group_restrictions <- function(domains) {
  domains |>
    select(
      training = training_bots_restricted,
      search = search_bots_restricted,
      user_fetch = user_fetch_bots_restricted
    ) |>
    pivot_longer(
      cols = everything(),
      names_to = "purpose_group",
      values_to = "restriction"
    ) |>
    count(.data$purpose_group, .data$restriction, name = "count") |>
    complete(
      purpose_group = c("training", "search", "user_fetch"),
      restriction = restricted_states,
      fill = list(count = 0L)
    ) |>
    group_by(.data$purpose_group) |>
    mutate(
      total_domains = sum(.data$count),
      proportion = .data$count / .data$total_domains
    ) |>
    ungroup() |>
    mutate(
      purpose_group = factor(
        .data$purpose_group,
        levels = c("training", "search", "user_fetch"),
        labels = c("Training/control", "AI search", "User-triggered fetch")
      ),
      restriction = factor(
        .data$restriction,
        levels = restricted_states,
        labels = c("None", "Some", "All", "Unknown")
      )
    )
}

summarise_agent_policies <- function(agent_policies) {
  agent_policies |>
    group_by(.data$purpose_group, .data$agent) |>
    summarise(
      total_domains = n(),
      resolved_results = sum(.data$policy != "unknown"),
      restricted = sum(.data$policy %in% restrictive_policy_states),
      fully_blocked = sum(
        .data$policy %in% c("blocked_explicit", "blocked_wildcard")
      ),
      explicitly_addressed = sum(.data$policy %in% explicit_policy_states),
      unknown = sum(.data$policy == "unknown"),
      restriction_proportion = safe_proportion(
        .data$restricted,
        .data$resolved_results
      ),
      full_block_proportion = safe_proportion(
        .data$fully_blocked,
        .data$resolved_results
      ),
      explicit_proportion = safe_proportion(
        .data$explicitly_addressed,
        .data$resolved_results
      ),
      .groups = "drop"
    ) |>
    mutate(
      purpose_group = factor(
        .data$purpose_group,
        levels = c("training", "search", "user_fetch"),
        labels = c("Training/control", "AI search", "User-triggered fetch")
      ),
      agent = factor(.data$agent, levels = rev(tracked_agents))
    ) |>
    arrange(.data$purpose_group, desc(.data$restriction_proportion))
}

summarise_content_signals <- function(domains) {
  domains |>
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
    complete(
      purpose = c("search", "ai_input", "ai_train"),
      signal = content_signal_states,
      fill = list(count = 0L)
    ) |>
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
}

summarise_llms_restriction_overlap <- function(domains) {
  domains |>
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
    complete(
      llms_txt = c("Present", "Not present"),
      restriction = c(
        "Any tracked-agent restriction",
        "No tracked-agent restriction"
      ),
      fill = list(count = 0L)
    ) |>
    group_by(.data$llms_txt) |>
    mutate(
      denominator = sum(.data$count),
      proportion = safe_proportion(.data$count, .data$denominator)
    ) |>
    ungroup()
}
