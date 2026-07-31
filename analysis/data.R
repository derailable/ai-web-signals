library(readr)

domain_col_types <- cols(
  rank = col_integer(),
  domain = col_character(),
  has_llms_txt = col_logical(),
  llms_txt_status = col_character(),
  robots_txt_status = col_character(),
  has_explicit_ai_policy = col_logical(),
  any_ai_bot_restricted = col_logical(),
  training_bots_restricted = col_character(),
  search_bots_restricted = col_character(),
  user_fetch_bots_restricted = col_character(),
  scan_status = col_character()
)

domain_columns <- c(
  "rank",
  "domain",
  "has_llms_txt",
  "llms_txt_status",
  "robots_txt_status",
  "has_explicit_ai_policy",
  "any_ai_bot_restricted",
  "training_bots_restricted",
  "search_bots_restricted",
  "user_fetch_bots_restricted",
  "scan_status"
)

llms_statuses <- c(
  "present",
  "absent",
  "empty",
  "html",
  "non_text",
  "http_error",
  "network_error"
)

robots_statuses <- c(
  "parsed",
  "absent",
  "empty",
  "html",
  "non_text",
  "unparseable",
  "http_error",
  "network_error"
)

restricted_states <- c("none", "some", "all", "unknown")
scan_states <- c("complete", "partial", "failed")

removed_policy_columns <- c(
  "gpt_bot_policy",
  "claude_bot_policy",
  "google_extended_policy",
  "applebot_extended_policy",
  "meta_external_agent_policy",
  "oai_search_bot_policy",
  "claude_search_bot_policy",
  "perplexity_bot_policy",
  "duck_assist_bot_policy",
  "mistral_ai_index_policy",
  "chatgpt_user_policy",
  "claude_user_policy",
  "perplexity_user_policy",
  "mistral_ai_user_policy"
)

validate_domains <- function(domains, expected_count = 100000) {
  stopifnot(identical(names(domains), domain_columns))
  stopifnot(nrow(domains) == expected_count)
  stopifnot(identical(domains$rank, seq_len(expected_count)))
  stopifnot(!anyDuplicated(domains$rank))
  stopifnot(!anyDuplicated(domains$domain))
  stopifnot(!any(removed_policy_columns %in% names(domains)))
  stopifnot(all(domains$llms_txt_status %in% llms_statuses))
  stopifnot(all(domains$robots_txt_status %in% robots_statuses))
  stopifnot(all(domains$scan_status %in% scan_states))
  stopifnot(all(domains$training_bots_restricted %in% restricted_states))
  stopifnot(all(domains$search_bots_restricted %in% restricted_states))
  stopifnot(all(domains$user_fetch_bots_restricted %in% restricted_states))
  invisible(domains)
}

load_domains <- function(
  path = "data/processed/domains.csv",
  expected_count = 100000
) {
  domains <- read_csv(
    path,
    col_types = domain_col_types,
    na = "",
    locale = locale(encoding = "UTF-8"),
    name_repair = "check_unique",
    show_col_types = FALSE,
    progress = FALSE
  )
  validate_domains(domains, expected_count = expected_count)
  domains
}

load_tranco_metadata <- function(path = "data/input/tranco-metadata.json") {
  if (!file.exists(path)) {
    return(NULL)
  }
  jsonlite::fromJSON(path)
}

domains <- load_domains()
tranco_metadata <- load_tranco_metadata()
