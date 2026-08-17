# Write the same category summary used by the report as a standalone task.
suppressPackageStartupMessages({
  library(dplyr)
  library(readr)
  library(tidyr)
})

source("analysis/data.R")
source("analysis/summaries.R")

dir.create("results/tables", recursive = TRUE, showWarnings = FALSE)
write_csv(
  category_summary,
  "results/tables/category-summary.csv",
  na = ""
)
