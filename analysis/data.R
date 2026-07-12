# Data loading, validation, and deterministic analysis transformations.

suppressPackageStartupMessages({
  library(dplyr)
  library(readr)
  library(stringr)
  library(tidyr)
})

required_domain_columns <- c(
  "rank",
  "domain",
  "categories",
  "has_llms_txt",
  "training_bots_blocked",
  "search_bots_blocked",
  "user_fetch_bots_blocked",
  "policy_explicit",
  "scan_status"
)

bot_policy_values <- c("none", "some", "all", "unknown")
known_bot_policy_values <- c("none", "some", "all")
scan_status_values <- c("complete", "partial", "failed")

#' Load and validate the processed domain dataset.
#'
#' Blank boolean fields are read as missing values, never as FALSE.
load_domains <- function(path = "data/processed/domains.csv") {
  if (!file.exists(path)) {
    stop("Processed domain file does not exist: ", path, call. = FALSE)
  }

  domains <- readr::read_csv(
    path,
    col_types = readr::cols(
      rank = readr::col_integer(),
      domain = readr::col_character(),
      categories = readr::col_character(),
      has_llms_txt = readr::col_logical(),
      training_bots_blocked = readr::col_character(),
      search_bots_blocked = readr::col_character(),
      user_fetch_bots_blocked = readr::col_character(),
      policy_explicit = readr::col_logical(),
      scan_status = readr::col_character()
    ),
    na = c(""),
    progress = FALSE,
    show_col_types = FALSE,
    trim_ws = TRUE
  )

  parse_problems <- readr::problems(domains)
  if (nrow(parse_problems) > 0) {
    first_problem <- parse_problems[1, ]
    stop(
      "Processed domain file contains a value that could not be parsed with ",
      "the expected schema at row ",
      first_problem$row,
      ", column `",
      first_problem$col,
      "`: expected ",
      first_problem$expected,
      ", got `",
      first_problem$actual,
      "`.",
      call. = FALSE
    )
  }

  domains <- domains |>
    dplyr::mutate(
      domain = stringr::str_trim(.data$domain),
      categories = stringr::str_trim(.data$categories),
      dplyr::across(
        dplyr::all_of(c(
          "training_bots_blocked",
          "search_bots_blocked",
          "user_fetch_bots_blocked",
          "scan_status"
        )),
        stringr::str_trim
      )
    )

  validate_domains(domains)

  domains
}

#' Validate the processed domain dataset schema and core value constraints.
validate_domains <- function(domains) {
  if (!is.data.frame(domains)) {
    stop("`domains` must be a data frame or tibble.", call. = FALSE)
  }

  missing_columns <- setdiff(required_domain_columns, names(domains))
  if (length(missing_columns) > 0) {
    stop(
      "Processed domains data is missing required column(s): ",
      paste(missing_columns, collapse = ", "),
      call. = FALSE
    )
  }

  if (nrow(domains) == 0) {
    stop("Processed domains data has zero rows.", call. = FALSE)
  }

  blank_domains <- which(is.na(domains$domain) | stringr::str_trim(domains$domain) == "")
  if (length(blank_domains) > 0) {
    stop(
      "Domain values must not be blank. First offending row: ",
      blank_domains[[1]],
      call. = FALSE
    )
  }

  duplicate_domains <- domains |>
    dplyr::count(.data$domain, name = "rows") |>
    dplyr::filter(.data$rows > 1)

  if (nrow(duplicate_domains) > 0) {
    stop(
      "Duplicate domain value(s) found; expected one row per domain. First duplicate: ",
      duplicate_domains$domain[[1]],
      call. = FALSE
    )
  }

  invalid_ranks <- which(
    !is.na(domains$rank) &
      (domains$rank <= 0 | domains$rank != floor(domains$rank))
  )
  if (length(invalid_ranks) > 0) {
    stop(
      "Non-missing ranks must be positive integers. First offending row: ",
      invalid_ranks[[1]],
      call. = FALSE
    )
  }

  duplicate_ranks <- domains |>
    dplyr::filter(!is.na(.data$rank)) |>
    dplyr::count(.data$rank, name = "rows") |>
    dplyr::filter(.data$rows > 1)

  if (nrow(duplicate_ranks) > 0) {
    stop(
      "Non-missing ranks must be unique. First duplicate rank: ",
      duplicate_ranks$rank[[1]],
      call. = FALSE
    )
  }

  boolean_columns <- c("has_llms_txt", "policy_explicit")
  for (column in boolean_columns) {
    values <- domains[[column]]
    if (!is.logical(values)) {
      stop(
        "Column `", column, "` must contain logical TRUE, FALSE, or NA values.",
        call. = FALSE
      )
    }
  }

  bot_columns <- c(
    "training_bots_blocked",
    "search_bots_blocked",
    "user_fetch_bots_blocked"
  )
  for (column in bot_columns) {
    invalid_values <- unique(domains[[column]][
      !is.na(domains[[column]]) & !domains[[column]] %in% bot_policy_values
    ])
    if (length(invalid_values) > 0) {
      stop(
        "Column `", column, "` contains unsupported value(s): ",
        paste(invalid_values, collapse = ", "),
        ". Expected one of: ",
        paste(bot_policy_values, collapse = ", "),
        ", or NA.",
        call. = FALSE
      )
    }
  }

  invalid_scan_status <- unique(domains$scan_status[
    !is.na(domains$scan_status) & !domains$scan_status %in% scan_status_values
  ])
  if (length(invalid_scan_status) > 0) {
    stop(
      "Column `scan_status` contains unsupported value(s): ",
      paste(invalid_scan_status, collapse = ", "),
      ". Expected one of: ",
      paste(scan_status_values, collapse = ", "),
      ", or NA.",
      call. = FALSE
    )
  }

  invisible(domains)
}

#' Add ordered, non-overlapping rank bands for analysis.
add_rank_bands <- function(domains) {
  rank_band_levels <- c(
    "1-100",
    "101-1,000",
    "1,001-10,000",
    "10,001-100,000",
    "Outside study range",
    "Unknown rank"
  )

  domains |>
    dplyr::mutate(
      rank_band = dplyr::case_when(
        is.na(.data$rank) ~ "Unknown rank",
        .data$rank <= 100 ~ "1-100",
        .data$rank <= 1000 ~ "101-1,000",
        .data$rank <= 10000 ~ "1,001-10,000",
        .data$rank <= 100000 ~ "10,001-100,000",
        TRUE ~ "Outside study range"
      ),
      rank_band = factor(.data$rank_band, levels = rank_band_levels, ordered = TRUE)
    )
}

#' Expand source categories into overlapping domain-category memberships.
expand_categories <- function(domains) {
  analysis_fields <- c(
    "rank",
    "domain",
    "has_llms_txt",
    "training_bots_blocked",
    "search_bots_blocked",
    "user_fetch_bots_blocked",
    "policy_explicit",
    "scan_status",
    "rank_band"
  )

  domains |>
    dplyr::select(dplyr::any_of(c(analysis_fields, "categories"))) |>
    tidyr::separate_longer_delim(categories, delim = ";") |>
    dplyr::mutate(overlapping_category = stringr::str_trim(.data$categories)) |>
    dplyr::filter(!is.na(.data$overlapping_category), .data$overlapping_category != "") |>
    dplyr::select(-"categories") |>
    dplyr::distinct(.data$domain, .data$overlapping_category, .keep_all = TRUE)
}

#' Convert bot-policy summaries into TRUE/FALSE/NA restrictive-policy flags.
is_restrictive_policy <- function(policy_result) {
  dplyr::case_when(
    policy_result %in% c("some", "all") ~ TRUE,
    policy_result == "none" ~ FALSE,
    TRUE ~ NA
  )
}
