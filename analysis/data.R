# Data loading, validation, and deterministic analysis transformations.

suppressPackageStartupMessages({
  library(dplyr)
  library(readr)
  library(stringr)
})

training_policy_columns <- c(
  "gpt_bot_policy",
  "claude_bot_policy",
  "google_extended_policy",
  "applebot_extended_policy",
  "meta_external_agent_policy"
)

search_policy_columns <- c(
  "oai_search_bot_policy",
  "claude_search_bot_policy",
  "perplexity_bot_policy",
  "duck_assist_bot_policy",
  "mistral_ai_index_policy"
)

user_fetch_policy_columns <- c(
  "chatgpt_user_policy",
  "claude_user_policy",
  "perplexity_user_policy",
  "mistral_ai_user_policy"
)

agent_policy_columns <- c(
  training_policy_columns,
  search_policy_columns,
  user_fetch_policy_columns
)

expected_domain_columns <- c(
  "domain",
  "has_llms_txt",
  "llms_txt_status",
  "robots_txt_status",
  "has_explicit_ai_policy",
  "training_bots_restricted",
  "search_bots_restricted",
  "user_fetch_bots_restricted",
  agent_policy_columns,
  "scan_status"
)

domain_col_types <- readr::cols_only(
  domain = readr::col_character(),
  has_llms_txt = readr::col_logical(),
  llms_txt_status = readr::col_character(),
  robots_txt_status = readr::col_character(),
  has_explicit_ai_policy = readr::col_logical(),
  training_bots_restricted = readr::col_character(),
  search_bots_restricted = readr::col_character(),
  user_fetch_bots_restricted = readr::col_character(),
  gpt_bot_policy = readr::col_character(),
  claude_bot_policy = readr::col_character(),
  google_extended_policy = readr::col_character(),
  applebot_extended_policy = readr::col_character(),
  meta_external_agent_policy = readr::col_character(),
  oai_search_bot_policy = readr::col_character(),
  claude_search_bot_policy = readr::col_character(),
  perplexity_bot_policy = readr::col_character(),
  duck_assist_bot_policy = readr::col_character(),
  mistral_ai_index_policy = readr::col_character(),
  chatgpt_user_policy = readr::col_character(),
  claude_user_policy = readr::col_character(),
  perplexity_user_policy = readr::col_character(),
  mistral_ai_user_policy = readr::col_character(),
  scan_status = readr::col_character()
)

grouped_restriction_values <- c("none", "some", "all", "unknown")
known_grouped_restriction_values <- c("none", "some", "all")
scan_status_values <- c("complete", "partial", "failed")
llms_txt_status_values <- c(
  "present",
  "absent",
  "empty",
  "html",
  "non_text",
  "http_error",
  "network_error"
)
robots_txt_status_values <- c(
  "parsed",
  "absent",
  "empty",
  "html",
  "non_text",
  "unparseable",
  "http_error",
  "network_error"
)
agent_policy_values <- c(
  "allow_default",
  "allow_explicit",
  "allow_wildcard",
  "partial_explicit",
  "partial_wildcard",
  "blocked_explicit",
  "blocked_wildcard",
  "unknown"
)

#' Load and validate the processed domain dataset.
#'
#' Blank logical fields are read as missing values, never as FALSE.
load_domains <- function(path = "data/processed/domains.csv") {
  if (!file.exists(path)) {
    stop("Processed domain file does not exist: ", path, call. = FALSE)
  }

  header <- readr::read_csv(
    path,
    n_max = 0,
    col_types = readr::cols(.default = readr::col_character()),
    na = "",
    locale = readr::locale(encoding = "UTF-8"),
    name_repair = "check_unique",
    show_col_types = FALSE,
    progress = FALSE,
    trim_ws = FALSE
  )
  validate_domain_columns(names(header))

  domains <- readr::read_csv(
    path,
    col_types = domain_col_types,
    na = "",
    locale = readr::locale(encoding = "UTF-8"),
    name_repair = "check_unique",
    show_col_types = FALSE,
    progress = FALSE,
    trim_ws = FALSE
  )

  validate_domains(domains, path)

  domains
}

validate_domain_columns <- function(column_names) {
  if (!identical(column_names, expected_domain_columns)) {
    stop(
      "Processed domain columns do not match the expected schema. Expected: ",
      paste(expected_domain_columns, collapse = ", "),
      ". Actual: ",
      paste(column_names, collapse = ", "),
      call. = FALSE
    )
  }
}

#' Validate the processed domain dataset schema and core value constraints.
validate_domains <- function(domains, path = "data/processed/domains.csv") {
  if (!is.data.frame(domains)) {
    stop("`domains` must be a data frame or tibble.", call. = FALSE)
  }

  parse_problems <- readr::problems(domains)
  if (nrow(parse_problems) > 0) {
    first_problem <- parse_problems[1, ]
    stop(
      "Failed to parse ",
      path,
      " with the expected schema. First problem at row ",
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

  validate_domain_columns(names(domains))

  accidental_index_columns <- c("", "index", "row_number", "...1", "x1")
  found_index_columns <- intersect(names(domains), accidental_index_columns)
  if (length(found_index_columns) > 0) {
    stop(
      "Processed domains data contains accidental index column(s): ",
      paste(found_index_columns, collapse = ", "),
      call. = FALSE
    )
  }

  if (nrow(domains) == 0) {
    stop("Processed domains data has zero rows.", call. = FALSE)
  }

  expected_types <- c(
    domain = "character",
    has_llms_txt = "logical",
    llms_txt_status = "character",
    robots_txt_status = "character",
    has_explicit_ai_policy = "logical",
    training_bots_restricted = "character",
    search_bots_restricted = "character",
    user_fetch_bots_restricted = "character",
    stats::setNames(rep("character", length(agent_policy_columns)), agent_policy_columns),
    scan_status = "character"
  )
  for (column in names(expected_types)) {
    if (!is(domains[[column]], expected_types[[column]])) {
      stop(
        "Column `",
        column,
        "` has type `",
        paste(class(domains[[column]]), collapse = "/"),
        "`; expected `",
        expected_types[[column]],
        "`.",
        call. = FALSE
      )
    }
  }

  blank_domains <- which(is.na(domains$domain) | stringr::str_trim(domains$domain) == "")
  if (length(blank_domains) > 0) {
    stop(
      "Domain values must not be blank. First offending row: ",
      blank_domains[[1]],
      call. = FALSE
    )
  }

  if (anyDuplicated(domains$domain)) {
    duplicate_domain <- domains$domain[[which(duplicated(domains$domain))[[1]]]]
    stop(
      "Duplicate domain value found; expected one row per domain: ",
      duplicate_domain,
      call. = FALSE
    )
  }

  validate_enum(
    domains,
    "llms_txt_status",
    llms_txt_status_values
  )
  validate_enum(
    domains,
    "robots_txt_status",
    robots_txt_status_values
  )
  validate_enum(
    domains,
    "scan_status",
    scan_status_values
  )
  for (column in c(
    "training_bots_restricted",
    "search_bots_restricted",
    "user_fetch_bots_restricted"
  )) {
    validate_enum(domains, column, grouped_restriction_values)
  }
  for (column in agent_policy_columns) {
    validate_enum(domains, column, agent_policy_values)
  }

  invisible(domains)
}

validate_enum <- function(domains, column, allowed_values) {
  invalid_values <- unique(domains[[column]][
    !is.na(domains[[column]]) & !domains[[column]] %in% allowed_values
  ])
  if (length(invalid_values) > 0) {
    stop(
      "Column `",
      column,
      "` contains unsupported value(s): ",
      paste(invalid_values, collapse = ", "),
      ". Expected one of: ",
      paste(allowed_values, collapse = ", "),
      ".",
      call. = FALSE
    )
  }
}

#' Convert grouped restriction summaries into TRUE/FALSE/NA flags.
is_restrictive_policy <- function(policy_result) {
  dplyr::case_when(
    policy_result %in% c("some", "all") ~ TRUE,
    policy_result == "none" ~ FALSE,
    TRUE ~ NA
  )
}
