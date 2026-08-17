# Data contracts and explicit loaders for the processed analysis datasets.

domain_col_types <- readr::cols(
  rank = readr::col_integer(),
  domain = readr::col_character(),
  has_llms_txt = readr::col_logical(),
  llms_txt_status = readr::col_character(),
  robots_txt_status = readr::col_character(),
  content_signal_search = readr::col_character(),
  content_signal_ai_input = readr::col_character(),
  content_signal_ai_train = readr::col_character(),
  has_explicit_ai_policy = readr::col_logical(),
  any_ai_bot_restricted = readr::col_logical(),
  training_bots_restricted = readr::col_character(),
  search_bots_restricted = readr::col_character(),
  user_fetch_bots_restricted = readr::col_character(),
  scan_status = readr::col_character()
)

domain_columns <- c(
  "rank",
  "domain",
  "has_llms_txt",
  "llms_txt_status",
  "robots_txt_status",
  "content_signal_search",
  "content_signal_ai_input",
  "content_signal_ai_train",
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
content_signal_states <- c("yes", "no", "unspecified", "invalid", "unknown")
scan_states <- c("complete", "partial", "failed")
policy_states <- c(
  "allow_default",
  "allow_explicit",
  "allow_wildcard",
  "partial_explicit",
  "partial_wildcard",
  "blocked_explicit",
  "blocked_wildcard",
  "unknown"
)

tracked_agents <- c(
  "GPTBot",
  "ClaudeBot",
  "Google-Extended",
  "Applebot-Extended",
  "meta-externalagent",
  "MistralAI-Training",
  "OAI-SearchBot",
  "Claude-SearchBot",
  "PerplexityBot",
  "DuckAssistBot",
  "MistralAI-Index",
  "ChatGPT-User",
  "Claude-User",
  "Perplexity-User",
  "MistralAI-User"
)

agent_purpose_groups <- c(
  GPTBot = "training",
  ClaudeBot = "training",
  `Google-Extended` = "training",
  `Applebot-Extended` = "training",
  `meta-externalagent` = "training",
  `MistralAI-Training` = "training",
  `OAI-SearchBot` = "search",
  `Claude-SearchBot` = "search",
  PerplexityBot = "search",
  DuckAssistBot = "search",
  `MistralAI-Index` = "search",
  `ChatGPT-User` = "user_fetch",
  `Claude-User` = "user_fetch",
  `Perplexity-User` = "user_fetch",
  `MistralAI-User` = "user_fetch"
)

agent_policy_col_types <- readr::cols(
  rank = readr::col_integer(),
  domain = readr::col_character(),
  agent = readr::col_character(),
  purpose_group = readr::col_character(),
  policy = readr::col_character()
)

agent_policy_columns <- c(
  "rank",
  "domain",
  "agent",
  "purpose_group",
  "policy"
)

removed_policy_columns <- c(
  "gpt_bot_policy",
  "claude_bot_policy",
  "google_extended_policy",
  "applebot_extended_policy",
  "meta_external_agent_policy",
  "mistral_ai_training_policy",
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

abort_validation <- function(dataset, details) {
  cli::cli_abort(c(
    "Can't validate `{dataset}`.",
    "x" = details
  ))
}

assert_valid <- function(condition, dataset, details) {
  if (!isTRUE(condition)) {
    abort_validation(dataset, details)
  }
  invisible(TRUE)
}

assert_allowed_values <- function(values, allowed, dataset, column) {
  invalid <- unique(values[!(values %in% allowed)])
  invalid <- ifelse(is.na(invalid), "NA", as.character(invalid))

  assert_valid(
    length(invalid) == 0,
    dataset,
    paste0(
      "Column `", column, "` contains unsupported value(s): ",
      toString(invalid), "."
    )
  )
}

validate_domains <- function(domains, expected_count = 100000) {
  dataset <- "domains.csv"
  parse_problem_count <- nrow(readr::problems(domains))

  assert_valid(
    identical(names(domains), domain_columns),
    dataset,
    paste0(
      "Columns must match this schema and order: ",
      toString(domain_columns), "."
    )
  )
  assert_valid(
    nrow(domains) == expected_count,
    dataset,
    paste0(
      "Expected ", expected_count, " rows, found ", nrow(domains), "."
    )
  )
  assert_valid(
    parse_problem_count == 0,
    dataset,
    paste0("CSV parsing produced ", parse_problem_count, " problem(s).")
  )
  assert_valid(
    !any(vapply(domains, is.list, logical(1))),
    dataset,
    "Columns must be atomic vectors; list columns are not allowed."
  )
  assert_valid(
    identical(domains$rank, seq_len(expected_count)),
    dataset,
    paste0(
      "Column `rank` must contain every integer from 1 to ",
      expected_count,
      " in order."
    )
  )
  assert_valid(
    !anyDuplicated(domains$rank),
    dataset,
    "Column `rank` must not contain duplicates."
  )
  assert_valid(
    !anyDuplicated(domains$domain),
    dataset,
    "Column `domain` must not contain duplicates."
  )
  assert_valid(
    !any(removed_policy_columns %in% names(domains)),
    dataset,
    "Legacy per-agent policy columns must not be present."
  )

  assert_allowed_values(
    domains$llms_txt_status,
    llms_statuses,
    dataset,
    "llms_txt_status"
  )
  assert_allowed_values(
    domains$robots_txt_status,
    robots_statuses,
    dataset,
    "robots_txt_status"
  )
  assert_allowed_values(
    domains$content_signal_search,
    content_signal_states,
    dataset,
    "content_signal_search"
  )
  assert_allowed_values(
    domains$content_signal_ai_input,
    content_signal_states,
    dataset,
    "content_signal_ai_input"
  )
  assert_allowed_values(
    domains$content_signal_ai_train,
    content_signal_states,
    dataset,
    "content_signal_ai_train"
  )
  assert_allowed_values(
    domains$scan_status,
    scan_states,
    dataset,
    "scan_status"
  )
  assert_allowed_values(
    domains$training_bots_restricted,
    restricted_states,
    dataset,
    "training_bots_restricted"
  )
  assert_allowed_values(
    domains$search_bots_restricted,
    restricted_states,
    dataset,
    "search_bots_restricted"
  )
  assert_allowed_values(
    domains$user_fetch_bots_restricted,
    restricted_states,
    dataset,
    "user_fetch_bots_restricted"
  )

  assert_valid(
    is.logical(domains$has_llms_txt),
    dataset,
    "Column `has_llms_txt` must be logical."
  )
  assert_valid(
    is.logical(domains$has_explicit_ai_policy),
    dataset,
    "Column `has_explicit_ai_policy` must be logical."
  )
  assert_valid(
    is.logical(domains$any_ai_bot_restricted),
    dataset,
    "Column `any_ai_bot_restricted` must be logical."
  )
  invisible(domains)
}

load_domains <- function(
  path = "data/processed/domains.csv",
  expected_count = 100000
) {
  domains <- readr::read_csv(
    path,
    col_types = domain_col_types,
    na = "",
    locale = readr::locale(encoding = "UTF-8"),
    name_repair = "check_unique",
    show_col_types = FALSE,
    progress = FALSE
  )
  validate_domains(domains, expected_count = expected_count)
  domains
}

validate_agent_policies <- function(agent_policies, domains) {
  dataset <- "agent-policies.csv"
  agents_per_domain <- length(tracked_agents)
  expected_count <- nrow(domains) * agents_per_domain
  expected_agents <- rep(tracked_agents, times = nrow(domains))
  parse_problem_count <- nrow(readr::problems(agent_policies))

  assert_valid(
    identical(names(agent_policies), agent_policy_columns),
    dataset,
    paste0(
      "Columns must match this schema and order: ",
      toString(agent_policy_columns), "."
    )
  )
  assert_valid(
    nrow(agent_policies) == expected_count,
    dataset,
    paste0(
      "Expected ", expected_count, " rows, found ",
      nrow(agent_policies), "."
    )
  )
  assert_valid(
    parse_problem_count == 0,
    dataset,
    paste0("CSV parsing produced ", parse_problem_count, " problem(s).")
  )
  assert_valid(
    !any(vapply(agent_policies, is.list, logical(1))),
    dataset,
    "Columns must be atomic vectors; list columns are not allowed."
  )
  assert_valid(
    identical(
      agent_policies$rank,
      rep(domains$rank, each = agents_per_domain)
    ),
    dataset,
    "Column `rank` must repeat each domain rank in canonical agent order."
  )
  assert_valid(
    identical(
      agent_policies$domain,
      rep(domains$domain, each = agents_per_domain)
    ),
    dataset,
    "Column `domain` must repeat each domain in canonical agent order."
  )
  assert_valid(
    identical(agent_policies$agent, expected_agents),
    dataset,
    "Column `agent` must follow the canonical tracked-agent order."
  )
  assert_valid(
    identical(
      agent_policies$purpose_group,
      unname(agent_purpose_groups[expected_agents])
    ),
    dataset,
    "Column `purpose_group` must match each tracked agent."
  )
  assert_allowed_values(
    agent_policies$policy,
    policy_states,
    dataset,
    "policy"
  )
  assert_valid(
    !anyDuplicated(agent_policies[c("domain", "agent")]),
    dataset,
    "Each `domain` and `agent` pair must be unique."
  )
  invisible(agent_policies)
}

load_agent_policies <- function(
  domains,
  path = "data/processed/agent-policies.csv"
) {
  agent_policies <- readr::read_csv(
    path,
    col_types = agent_policy_col_types,
    na = "",
    locale = readr::locale(encoding = "UTF-8"),
    name_repair = "check_unique",
    show_col_types = FALSE,
    progress = FALSE
  )
  validate_agent_policies(agent_policies, domains)
  agent_policies
}

load_tranco_metadata <- function(path = "data/input/tranco-metadata.json") {
  if (!file.exists(path)) {
    return(NULL)
  }
  jsonlite::fromJSON(path)
}
