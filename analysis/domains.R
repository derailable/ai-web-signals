library(readr)

read_csv(
  "data/processed/domains.csv",
  col_select = domain,
  show_col_types = FALSE,
  progress = FALSE
) |>
  write_csv("data/processed/domain-list.csv")
