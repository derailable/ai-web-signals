# Summary functions and denominator definitions for AI Web Signals.

source("analysis/data.R")

suppressPackageStartupMessages({
  library(dplyr)
  library(stringr)
  library(tidyr)
})

rate_or_na <- function(numerator, denominator) {
  denominator <- rep(denominator, length.out = length(numerator))
  dplyr::if_else(denominator > 0, numerator / denominator, NA_real_)
}

count_known_policy <- function(policy_result) {
  sum(policy_result %in% known_grouped_restriction_values)
}

count_restrictive_policy <- function(policy_result) {
  sum(is_restrictive_policy(policy_result) %in% TRUE)
}

#' Summarise scan status distribution.
summarise_scan_quality <- function(domains) {
  total_domains <- nrow(domains)
  status_levels <- c("complete", "partial", "failed", "unknown")

  domains |>
    dplyr::mutate(
      scan_status = dplyr::if_else(
        is.na(.data$scan_status),
        "unknown",
        .data$scan_status
      ),
      scan_status = factor(.data$scan_status, levels = status_levels)
    ) |>
    dplyr::count(.data$scan_status, .drop = FALSE, name = "count") |>
    dplyr::filter(.data$count > 0 | .data$scan_status != "unknown") |>
    dplyr::mutate(
      total_domains = total_domains,
      proportion = rate_or_na(.data$count, .data$total_domains)
    ) |>
    dplyr::select("scan_status", "total_domains", "count", "proportion")
}

#' Produce headline metrics with explicit numerator and denominator fields.
summarise_key_metrics <- function(domains) {
  total_domains <- nrow(domains)

  complete_scans <- sum(domains$scan_status == "complete", na.rm = TRUE)

  known_llms_results <- sum(!is.na(domains$has_llms_txt))
  observed_llms <- sum(domains$has_llms_txt %in% TRUE)

  training_known <- count_known_policy(domains$training_bots_restricted)
  training_restrictive <- count_restrictive_policy(domains$training_bots_restricted)

  search_known <- count_known_policy(domains$search_bots_restricted)
  search_restrictive <- count_restrictive_policy(domains$search_bots_restricted)

  user_fetch_known <- count_known_policy(domains$user_fetch_bots_restricted)
  user_fetch_restrictive <- count_restrictive_policy(domains$user_fetch_bots_restricted)

  has_explicit_ai_policy_known <- sum(!is.na(domains$has_explicit_ai_policy))
  has_explicit_ai_policy_count <- sum(domains$has_explicit_ai_policy %in% TRUE)

  tibble::tibble(
    metric_id = c(
      "total_domains",
      "complete_scans",
      "complete_scan_rate",
      "known_llms_txt_status",
      "observed_llms_txt",
      "llms_txt_rate_among_known",
      "restrictive_training_policy",
      "restrictive_ai_search_policy",
      "restrictive_user_fetch_policy",
      "explicit_tracked_ai_policy"
    ),
    metric = c(
      "Total domains",
      "Domains with complete scans",
      "Complete scan rate",
      "Domains with known /llms.txt status",
      "Domains with observed /llms.txt",
      "/llms.txt rate among known results",
      "Domains with any restrictive training-bot policy",
      "Domains with any restrictive AI-search policy",
      "Domains with any restrictive user-fetch policy",
      "Domains with an explicit tracked AI policy"
    ),
    numerator = c(
      total_domains,
      complete_scans,
      complete_scans,
      known_llms_results,
      observed_llms,
      observed_llms,
      training_restrictive,
      search_restrictive,
      user_fetch_restrictive,
      has_explicit_ai_policy_count
    ),
    denominator = c(
      NA_integer_,
      NA_integer_,
      total_domains,
      NA_integer_,
      NA_integer_,
      known_llms_results,
      training_known,
      search_known,
      user_fetch_known,
      has_explicit_ai_policy_known
    )
  ) |>
    dplyr::mutate(rate = rate_or_na(.data$numerator, .data$denominator))
}

#' Summarise bot-policy outcomes by crawler purpose.
summarise_bot_policies <- function(domains) {
  purpose_levels <- c("Training", "AI search", "User-triggered retrieval")
  result_levels <- c("None", "Some", "All", "Unknown")

  domains |>
    dplyr::select(
      training = training_bots_restricted,
      ai_search = search_bots_restricted,
      user_triggered_retrieval = user_fetch_bots_restricted
    ) |>
    tidyr::pivot_longer(
      dplyr::everything(),
      names_to = "bot_purpose",
      values_to = "policy_result"
    ) |>
    dplyr::mutate(
      bot_purpose = dplyr::recode(
        .data$bot_purpose,
        training = "Training",
        ai_search = "AI search",
        user_triggered_retrieval = "User-triggered retrieval"
      ),
      bot_purpose = factor(.data$bot_purpose, levels = purpose_levels),
      policy_result = dplyr::if_else(
        is.na(.data$policy_result),
        "unknown",
        .data$policy_result
      ),
      policy_result = stringr::str_to_title(.data$policy_result),
      policy_result = factor(.data$policy_result, levels = result_levels)
    ) |>
    dplyr::count(.data$bot_purpose, .data$policy_result, .drop = FALSE, name = "count") |>
    dplyr::group_by(.data$bot_purpose) |>
    dplyr::mutate(proportion = rate_or_na(.data$count, sum(.data$count))) |>
    dplyr::ungroup()
}

#' Summarise explicit tracked-agent policy declarations.
summarise_explicit_policies <- function(domains) {
  scope_levels <- c(
    "All domains with known explicit-policy status",
    "Domains with at least one restrictive AI-bot policy"
  )
  label_levels <- c(
    "Explicit tracked AI policy",
    "Inherited or non-explicit policy",
    "Unknown"
  )

  classify_policy <- function(has_explicit_ai_policy) {
    dplyr::case_when(
      has_explicit_ai_policy %in% TRUE ~ "Explicit tracked AI policy",
      has_explicit_ai_policy %in% FALSE ~ "Inherited or non-explicit policy",
      TRUE ~ "Unknown"
    )
  }

  has_restrictive_policy <- is_restrictive_policy(domains$training_bots_restricted) %in% TRUE |
    is_restrictive_policy(domains$search_bots_restricted) %in% TRUE |
    is_restrictive_policy(domains$user_fetch_bots_restricted) %in% TRUE

  known_explicit_domains <- domains |>
    dplyr::filter(!is.na(.data$has_explicit_ai_policy)) |>
    dplyr::mutate(scope = "All domains with known explicit-policy status")

  restrictive_domains <- domains |>
    dplyr::filter(has_restrictive_policy) |>
    dplyr::mutate(scope = "Domains with at least one restrictive AI-bot policy")

  dplyr::bind_rows(known_explicit_domains, restrictive_domains) |>
    dplyr::mutate(
      has_explicit_ai_policy_result = classify_policy(.data$has_explicit_ai_policy),
      has_explicit_ai_policy_result = factor(.data$has_explicit_ai_policy_result, levels = label_levels),
      scope = factor(.data$scope, levels = scope_levels)
    ) |>
    dplyr::count(.data$scope, .data$has_explicit_ai_policy_result, .drop = FALSE, name = "count") |>
    tidyr::complete(
      scope = factor(scope_levels, levels = scope_levels),
      has_explicit_ai_policy_result = factor(label_levels, levels = label_levels),
      fill = list(count = 0)
    ) |>
    dplyr::group_by(.data$scope) |>
    dplyr::mutate(
      denominator = sum(.data$count),
      proportion = rate_or_na(.data$count, .data$denominator)
    ) |>
    dplyr::ungroup()
}

#' Summarise coexistence of /llms.txt discovery and restrictive policies.
#'
#' This table uses rows where /llms.txt and all three bot-policy fields are known.
summarise_discovery_and_restriction <- function(domains) {
  known_domains <- domains |>
    dplyr::filter(
      !is.na(.data$has_llms_txt),
      .data$training_bots_restricted %in% known_grouped_restriction_values,
      .data$search_bots_restricted %in% known_grouped_restriction_values,
      .data$user_fetch_bots_restricted %in% known_grouped_restriction_values
    ) |>
    dplyr::mutate(
      discovery_signal = dplyr::if_else(
        .data$has_llms_txt,
        "Publishes /llms.txt",
        "Does not publish /llms.txt"
      ) |>
        factor(levels = c("Publishes /llms.txt", "Does not publish /llms.txt")),
      `Restricts training bots` = is_restrictive_policy(.data$training_bots_restricted),
      `Restricts AI search bots` = is_restrictive_policy(.data$search_bots_restricted),
      `Restricts user-fetch agents` = is_restrictive_policy(.data$user_fetch_bots_restricted)
    )

  signal_levels <- c(
    "Restricts training bots",
    "Restricts AI search bots",
    "Restricts user-fetch agents"
  )

  known_domains |>
    dplyr::select("domain", "discovery_signal", dplyr::all_of(signal_levels)) |>
    tidyr::pivot_longer(
      dplyr::all_of(signal_levels),
      names_to = "policy_signal",
      values_to = "has_policy_signal"
    ) |>
    dplyr::mutate(policy_signal = factor(.data$policy_signal, levels = signal_levels)) |>
    dplyr::group_by(.data$discovery_signal, .data$policy_signal, .drop = FALSE) |>
    dplyr::summarise(
      count = sum(.data$has_policy_signal %in% TRUE),
      denominator = dplyr::n(),
      rate = rate_or_na(.data$count, .data$denominator),
      .groups = "drop"
    ) |>
    dplyr::mutate(
      unknown_values_excluded = nrow(domains) - nrow(known_domains),
      denominator_rule = paste(
        "Rows with known /llms.txt status and known training, AI-search,",
        "and user-fetch policy summaries."
      )
    )
}
