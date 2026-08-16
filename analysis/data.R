library(readr)

domain_col_types <- cols(
  rank = col_integer(),
  domain = col_character(),
  has_llms_txt = col_logical(),
  llms_txt_status = col_character(),
  robots_txt_status = col_character(),
  content_signal_search = col_character(),
  content_signal_ai_input = col_character(),
  content_signal_ai_train = col_character(),
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

agent_policy_col_types <- cols(
  rank = col_integer(),
  domain = col_character(),
  agent = col_character(),
  purpose_group = col_character(),
  policy = col_character()
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

validate_domains <- function(domains, expected_count = 100000) {
  stopifnot(identical(names(domains), domain_columns))
  stopifnot(nrow(domains) == expected_count)
  stopifnot(nrow(problems(domains)) == 0)
  stopifnot(!any(vapply(domains, is.list, logical(1))))
  stopifnot(identical(domains$rank, seq_len(expected_count)))
  stopifnot(!anyDuplicated(domains$rank))
  stopifnot(!anyDuplicated(domains$domain))
  stopifnot(!any(removed_policy_columns %in% names(domains)))
  stopifnot(all(domains$llms_txt_status %in% llms_statuses))
  stopifnot(all(domains$robots_txt_status %in% robots_statuses))
  stopifnot(all(domains$content_signal_search %in% content_signal_states))
  stopifnot(all(domains$content_signal_ai_input %in% content_signal_states))
  stopifnot(all(domains$content_signal_ai_train %in% content_signal_states))
  stopifnot(all(domains$scan_status %in% scan_states))
  stopifnot(all(domains$training_bots_restricted %in% restricted_states))
  stopifnot(all(domains$search_bots_restricted %in% restricted_states))
  stopifnot(all(domains$user_fetch_bots_restricted %in% restricted_states))
  stopifnot(is.logical(domains$has_llms_txt))
  stopifnot(is.logical(domains$has_explicit_ai_policy))
  stopifnot(is.logical(domains$any_ai_bot_restricted))
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

validate_agent_policies <- function(agent_policies, domains) {
  agents_per_domain <- length(tracked_agents)
  expected_count <- nrow(domains) * agents_per_domain
  expected_agents <- rep(tracked_agents, times = nrow(domains))

  stopifnot(identical(names(agent_policies), agent_policy_columns))
  stopifnot(nrow(agent_policies) == expected_count)
  stopifnot(nrow(problems(agent_policies)) == 0)
  stopifnot(!any(vapply(agent_policies, is.list, logical(1))))
  stopifnot(identical(
    agent_policies$rank,
    rep(domains$rank, each = agents_per_domain)
  ))
  stopifnot(identical(
    agent_policies$domain,
    rep(domains$domain, each = agents_per_domain)
  ))
  stopifnot(identical(agent_policies$agent, expected_agents))
  stopifnot(identical(
    agent_policies$purpose_group,
    unname(agent_purpose_groups[expected_agents])
  ))
  stopifnot(all(agent_policies$policy %in% policy_states))
  stopifnot(!anyDuplicated(agent_policies[c("domain", "agent")]))
  invisible(agent_policies)
}

load_agent_policies <- function(
  path = "data/processed/agent-policies.csv",
  domains = load_domains()
) {
  agent_policies <- read_csv(
    path,
    col_types = agent_policy_col_types,
    na = "",
    locale = locale(encoding = "UTF-8"),
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

domains <- load_domains()
tranco_metadata <- load_tranco_metadata()
