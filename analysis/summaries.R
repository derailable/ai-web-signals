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
  sum(policy_result %in% known_bot_policy_values)
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

  training_known <- count_known_policy(domains$training_bots_blocked)
  training_restrictive <- count_restrictive_policy(domains$training_bots_blocked)

  search_known <- count_known_policy(domains$search_bots_blocked)
  search_restrictive <- count_restrictive_policy(domains$search_bots_blocked)

  user_fetch_known <- count_known_policy(domains$user_fetch_bots_blocked)
  user_fetch_restrictive <- count_restrictive_policy(domains$user_fetch_bots_blocked)

  policy_explicit_known <- sum(!is.na(domains$policy_explicit))
  policy_explicit_count <- sum(domains$policy_explicit %in% TRUE)

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
      policy_explicit_count
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
      policy_explicit_known
    )
  ) |>
    dplyr::mutate(rate = rate_or_na(.data$numerator, .data$denominator))
}

#' Summarise adoption and policy metrics by ordered rank band.
summarise_rank_bands <- function(domains) {
  if (!"rank_band" %in% names(domains)) {
    domains <- add_rank_bands(domains)
  }

  domains |>
    dplyr::group_by(.data$rank_band, .drop = FALSE) |>
    dplyr::summarise(
      total_domains = dplyr::n(),
      complete_scans = sum(.data$scan_status == "complete", na.rm = TRUE),
      known_llms_results = sum(!is.na(.data$has_llms_txt)),
      llms_txt_observed_count = sum(.data$has_llms_txt %in% TRUE),
      training_policy_known = count_known_policy(.data$training_bots_blocked),
      training_restrictive_count = count_restrictive_policy(.data$training_bots_blocked),
      search_policy_known = count_known_policy(.data$search_bots_blocked),
      search_restrictive_count = count_restrictive_policy(.data$search_bots_blocked),
      user_fetch_policy_known = count_known_policy(.data$user_fetch_bots_blocked),
      user_fetch_restrictive_count = count_restrictive_policy(.data$user_fetch_bots_blocked),
      explicit_policy_known = sum(!is.na(.data$policy_explicit)),
      explicit_policy_count = sum(.data$policy_explicit %in% TRUE),
      .groups = "drop"
    ) |>
    dplyr::mutate(
      llms_txt_rate = rate_or_na(.data$llms_txt_observed_count, .data$known_llms_results),
      training_restrictive_rate = rate_or_na(
        .data$training_restrictive_count,
        .data$training_policy_known
      ),
      search_restrictive_rate = rate_or_na(
        .data$search_restrictive_count,
        .data$search_policy_known
      ),
      user_fetch_restrictive_rate = rate_or_na(
        .data$user_fetch_restrictive_count,
        .data$user_fetch_policy_known
      ),
      explicit_policy_rate = rate_or_na(
        .data$explicit_policy_count,
        .data$explicit_policy_known
      )
    )
}

#' Summarise bot-policy outcomes by crawler purpose.
summarise_bot_policies <- function(domains) {
  purpose_levels <- c("Training", "AI search", "User-triggered retrieval")
  result_levels <- c("None", "Some", "All", "Unknown")

  domains |>
    dplyr::select(
      training = training_bots_blocked,
      ai_search = search_bots_blocked,
      user_triggered_retrieval = user_fetch_bots_blocked
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
    "All domains with known policy_explicit",
    "Domains with at least one restrictive AI-bot policy"
  )
  label_levels <- c(
    "Explicit tracked AI policy",
    "Inherited or non-explicit policy",
    "Unknown"
  )

  classify_policy <- function(policy_explicit) {
    dplyr::case_when(
      policy_explicit %in% TRUE ~ "Explicit tracked AI policy",
      policy_explicit %in% FALSE ~ "Inherited or non-explicit policy",
      TRUE ~ "Unknown"
    )
  }

  has_restrictive_policy <- is_restrictive_policy(domains$training_bots_blocked) %in% TRUE |
    is_restrictive_policy(domains$search_bots_blocked) %in% TRUE |
    is_restrictive_policy(domains$user_fetch_bots_blocked) %in% TRUE

  known_explicit_domains <- domains |>
    dplyr::filter(!is.na(.data$policy_explicit)) |>
    dplyr::mutate(scope = "All domains with known policy_explicit")

  restrictive_domains <- domains |>
    dplyr::filter(has_restrictive_policy) |>
    dplyr::mutate(scope = "Domains with at least one restrictive AI-bot policy")

  dplyr::bind_rows(known_explicit_domains, restrictive_domains) |>
    dplyr::mutate(
      policy_explicit_result = classify_policy(.data$policy_explicit),
      policy_explicit_result = factor(.data$policy_explicit_result, levels = label_levels),
      scope = factor(.data$scope, levels = scope_levels)
    ) |>
    dplyr::count(.data$scope, .data$policy_explicit_result, .drop = FALSE, name = "count") |>
    tidyr::complete(
      scope = factor(scope_levels, levels = scope_levels),
      policy_explicit_result = factor(label_levels, levels = label_levels),
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
      .data$training_bots_blocked %in% known_bot_policy_values,
      .data$search_bots_blocked %in% known_bot_policy_values,
      .data$user_fetch_bots_blocked %in% known_bot_policy_values
    ) |>
    dplyr::mutate(
      discovery_signal = dplyr::if_else(
        .data$has_llms_txt,
        "Publishes /llms.txt",
        "Does not publish /llms.txt"
      ) |>
        factor(levels = c("Publishes /llms.txt", "Does not publish /llms.txt")),
      `Restricts training bots` = is_restrictive_policy(.data$training_bots_blocked),
      `Restricts AI search bots` = is_restrictive_policy(.data$search_bots_blocked),
      `Restricts user-fetch agents` = is_restrictive_policy(.data$user_fetch_bots_blocked)
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

#' Summarise overlapping Cloudflare category memberships.
summarise_categories <- function(categories, min_domains = 500) {
  if (!"overlapping_category" %in% names(categories)) {
    stop(
      "`categories` must include an `overlapping_category` column from expand_categories().",
      call. = FALSE
    )
  }

  categories |>
    dplyr::group_by(.data$overlapping_category) |>
    dplyr::summarise(
      category_membership_count = dplyr::n_distinct(.data$domain),
      known_llms_results = sum(!is.na(.data$has_llms_txt)),
      llms_txt_observed_count = sum(.data$has_llms_txt %in% TRUE),
      training_policy_known = count_known_policy(.data$training_bots_blocked),
      training_restrictive_count = count_restrictive_policy(.data$training_bots_blocked),
      search_policy_known = count_known_policy(.data$search_bots_blocked),
      search_restrictive_count = count_restrictive_policy(.data$search_bots_blocked),
      user_fetch_policy_known = count_known_policy(.data$user_fetch_bots_blocked),
      user_fetch_restrictive_count = count_restrictive_policy(.data$user_fetch_bots_blocked),
      .groups = "drop"
    ) |>
    dplyr::filter(.data$category_membership_count >= min_domains) |>
    dplyr::mutate(
      min_domains = min_domains,
      llms_txt_rate = rate_or_na(.data$llms_txt_observed_count, .data$known_llms_results),
      training_restrictive_rate = rate_or_na(
        .data$training_restrictive_count,
        .data$training_policy_known
      ),
      search_restrictive_rate = rate_or_na(
        .data$search_restrictive_count,
        .data$search_policy_known
      ),
      user_fetch_restrictive_rate = rate_or_na(
        .data$user_fetch_restrictive_count,
        .data$user_fetch_policy_known
      )
    ) |>
    dplyr::arrange(
      dplyr::desc(.data$category_membership_count),
      dplyr::desc(.data$llms_txt_rate),
      .data$overlapping_category
    )
}
