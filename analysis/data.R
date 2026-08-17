# Load processed data.
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

agent_policy_col_types <- cols(
  rank = col_integer(),
  domain = col_character(),
  agent = col_character(),
  purpose_group = col_character(),
  policy = col_character()
)

domain_category_col_types <- cols_only(
  domain = col_character(),
  category = col_character()
)

domains <- read_csv(
  "data/processed/domains.csv",
  col_types = domain_col_types,
  na = "",
  progress = FALSE
)

agent_policies <- read_csv(
  "data/processed/agent-policies.csv",
  col_types = agent_policy_col_types,
  na = "",
  progress = FALSE
)

domain_categories <- read_csv(
  "data/processed/categorized-domains.csv",
  col_types = domain_category_col_types,
  progress = FALSE
)

stopifnot(
  !anyDuplicated(domain_categories$domain),
  all(nzchar(domain_categories$category)),
  setequal(domains$domain, domain_categories$domain)
)

categorized_domains <- domains |>
  left_join(domain_categories, by = "domain")
