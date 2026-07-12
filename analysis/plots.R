# Presentation logic for AI Web Signals figures.

suppressPackageStartupMessages({
  library(dplyr)
  library(forcats)
  library(ggplot2)
  library(scales)
  library(stringr)
})

policy_result_colors <- c(
  None = "#4C78A8",
  Some = "#F58518",
  All = "#E45756",
  Unknown = "#9D9D9D"
)

explicit_policy_colors <- c(
  "Explicit tracked AI policy" = "#4C78A8",
  "Inherited or non-explicit policy" = "#72B7B2",
  Unknown = "#9D9D9D"
)

#' Project ggplot theme.
theme_ai_web_signals <- function(base_size = 12) {
  ggplot2::theme_minimal(base_size = base_size, base_family = "sans") +
    ggplot2::theme(
      plot.title = ggplot2::element_text(face = "bold", size = base_size + 5),
      plot.subtitle = ggplot2::element_text(size = base_size + 1, margin = ggplot2::margin(b = 8)),
      plot.caption = ggplot2::element_text(
        size = base_size - 2,
        color = "grey35",
        hjust = 0,
        margin = ggplot2::margin(t = 10)
      ),
      panel.grid.minor = ggplot2::element_blank(),
      panel.grid.major.x = ggplot2::element_blank(),
      axis.title = ggplot2::element_text(size = base_size),
      axis.text = ggplot2::element_text(color = "grey20"),
      legend.title = ggplot2::element_text(face = "bold"),
      legend.position = "bottom",
      strip.text = ggplot2::element_text(face = "bold", hjust = 0),
      plot.background = ggplot2::element_rect(fill = "white", color = NA),
      panel.background = ggplot2::element_rect(fill = "white", color = NA)
    )
}

empty_plot <- function(message) {
  ggplot2::ggplot() +
    ggplot2::annotate("text", x = 0, y = 0, label = message, size = 4) +
    ggplot2::theme_void(base_family = "sans")
}

#' Plot /llms.txt adoption by rank band.
plot_llms_by_rank <- function(rank_summary) {
  plot_data <- rank_summary |>
    dplyr::filter(.data$total_domains > 0) |>
    dplyr::mutate(
      plot_rate = dplyr::coalesce(.data$llms_txt_rate, 0),
      denominator_label = paste0("known n=", scales::comma(.data$known_llms_results)),
      rate_label = dplyr::if_else(
        is.na(.data$llms_txt_rate),
        "No known results",
        scales::percent(.data$llms_txt_rate, accuracy = 0.1)
      ),
      label = paste(.data$rate_label, .data$denominator_label, sep = "\n"),
      label_y = dplyr::if_else(
        is.na(.data$llms_txt_rate),
        0.05,
        pmin(.data$plot_rate + 0.055, 0.96)
      )
    )

  if (nrow(plot_data) == 0) {
    return(empty_plot("No rank-band data available."))
  }

  ggplot2::ggplot(plot_data, ggplot2::aes(x = .data$rank_band, y = .data$plot_rate)) +
    ggplot2::geom_col(width = 0.72, fill = "#4C78A8") +
    ggplot2::geom_text(
      ggplot2::aes(y = .data$label_y, label = .data$label),
      lineheight = 0.95,
      size = 3.4,
      color = "grey15"
    ) +
    ggplot2::scale_y_continuous(
      labels = scales::percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = ggplot2::expansion(mult = c(0, 0.02))
    ) +
    ggplot2::labs(
      title = "/llms.txt adoption by rank band",
      subtitle = "Rates use domains with known /llms.txt results as the denominator.",
      x = NULL,
      y = "Domains with observed /llms.txt",
      caption = "Rank bands are non-overlapping. Unknown /llms.txt results are excluded from rate denominators."
    ) +
    theme_ai_web_signals()
}

#' Plot policy-result distributions by bot purpose.
plot_bot_policy_distribution <- function(bot_summary) {
  label_data <- bot_summary |>
    dplyr::filter(.data$proportion >= 0.07) |>
    dplyr::mutate(label = scales::percent(.data$proportion, accuracy = 1))

  ggplot2::ggplot(
    bot_summary,
    ggplot2::aes(x = .data$bot_purpose, y = .data$proportion, fill = .data$policy_result)
  ) +
    ggplot2::geom_col(width = 0.72, color = "white", linewidth = 0.3) +
    ggplot2::geom_text(
      data = label_data,
      ggplot2::aes(label = .data$label),
      position = ggplot2::position_stack(vjust = 0.5),
      color = "white",
      size = 3.4,
      fontface = "bold"
    ) +
    ggplot2::scale_fill_manual(values = policy_result_colors, drop = FALSE) +
    ggplot2::scale_y_continuous(
      labels = scales::percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = ggplot2::expansion(mult = c(0, 0))
    ) +
    ggplot2::labs(
      title = "AI bot policy summaries by crawler purpose",
      subtitle = "`Some` and `All` indicate restrictive rules; unknown results remain visible.",
      x = NULL,
      y = "Share of domains",
      fill = "Policy result",
      caption = "robots.txt expresses declared crawler policy; this chart does not measure enforcement."
    ) +
    theme_ai_web_signals()
}

#' Plot explicit tracked-agent policy summaries.
plot_explicit_policy <- function(explicit_summary) {
  plot_data <- explicit_summary |>
    dplyr::mutate(
      plot_proportion = dplyr::coalesce(.data$proportion, 0),
      label = dplyr::if_else(
        .data$denominator > 0,
        paste0(
          scales::percent(.data$proportion, accuracy = 1),
          "\n",
          scales::comma(.data$count),
          " of ",
          scales::comma(.data$denominator)
        ),
        "No rows"
      )
    )

  ggplot2::ggplot(
    plot_data,
    ggplot2::aes(
      x = .data$policy_explicit_result,
      y = .data$plot_proportion,
      fill = .data$policy_explicit_result
    )
  ) +
    ggplot2::geom_col(width = 0.7) +
    ggplot2::geom_text(
      ggplot2::aes(label = .data$label),
      vjust = -0.2,
      size = 3.2,
      lineheight = 0.95
    ) +
    ggplot2::facet_wrap(ggplot2::vars(.data$scope), ncol = 1) +
    ggplot2::scale_fill_manual(values = explicit_policy_colors, drop = FALSE) +
    ggplot2::scale_y_continuous(
      labels = scales::percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = ggplot2::expansion(mult = c(0, 0.12))
    ) +
    ggplot2::labs(
      title = "Explicit tracked-agent policy declarations",
      subtitle = "Non-explicit policies may still affect AI agents through wildcard rules.",
      x = NULL,
      y = "Share of domains",
      fill = NULL
    ) +
    ggplot2::coord_cartesian(clip = "off") +
    theme_ai_web_signals() +
    ggplot2::theme(
      axis.text.x = ggplot2::element_text(angle = 18, hjust = 1),
      legend.position = "none"
    )
}

#' Plot the relationship between discovery and restrictive policy signals.
plot_discovery_and_restriction <- function(discovery_summary) {
  if (nrow(discovery_summary) == 0) {
    return(empty_plot("No rows have all required known values."))
  }

  plot_data <- discovery_summary |>
    dplyr::mutate(
      label = paste0(
        scales::percent(.data$rate, accuracy = 1),
        "\n",
        scales::comma(.data$count),
        " of ",
        scales::comma(.data$denominator)
      )
    )

  ggplot2::ggplot(
    plot_data,
    ggplot2::aes(x = .data$policy_signal, y = .data$discovery_signal, fill = .data$rate)
  ) +
    ggplot2::geom_tile(color = "white", linewidth = 1) +
    ggplot2::geom_text(ggplot2::aes(label = .data$label), size = 3.5, lineheight = 0.95) +
    ggplot2::scale_fill_gradient(
      low = "#F5F5F5",
      high = "#4C78A8",
      labels = scales::percent_format(accuracy = 1),
      limits = c(0, 1),
      na.value = "grey90"
    ) +
    ggplot2::labs(
      title = "Discovery and restriction signals can coexist",
      subtitle = "Rows with unknown /llms.txt or bot-policy results are excluded from this comparison.",
      x = NULL,
      y = NULL,
      fill = "Restriction rate"
    ) +
    theme_ai_web_signals() +
    ggplot2::theme(
      axis.text.x = ggplot2::element_text(angle = 18, hjust = 1),
      panel.grid.major = ggplot2::element_blank()
    )
}

#' Optionally plot category-level /llms.txt rates.
plot_category_rates <- function(category_summary, max_categories = 15) {
  if (nrow(category_summary) == 0) {
    return(empty_plot("No categories meet the configured minimum size threshold."))
  }

  plot_data <- category_summary |>
    dplyr::filter(.data$known_llms_results > 0) |>
    dplyr::arrange(dplyr::desc(.data$llms_txt_rate), dplyr::desc(.data$category_membership_count)) |>
    dplyr::slice_head(n = max_categories) |>
    dplyr::mutate(
      category_label = forcats::fct_reorder(.data$overlapping_category, .data$llms_txt_rate),
      label = paste0(
        scales::percent(.data$llms_txt_rate, accuracy = 0.1),
        " (n=",
        scales::comma(.data$known_llms_results),
        ")"
      )
    )

  if (nrow(plot_data) == 0) {
    return(empty_plot("No category rows have known /llms.txt denominators."))
  }

  ggplot2::ggplot(plot_data, ggplot2::aes(x = .data$llms_txt_rate, y = .data$category_label)) +
    ggplot2::geom_col(fill = "#4C78A8", width = 0.72) +
    ggplot2::geom_text(ggplot2::aes(label = .data$label), hjust = -0.05, size = 3.2) +
    ggplot2::scale_x_continuous(
      labels = scales::percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = ggplot2::expansion(mult = c(0, 0.1))
    ) +
    ggplot2::labs(
      title = "/llms.txt adoption by overlapping category",
      subtitle = "Only categories meeting the configured minimum size threshold are shown.",
      x = "Observed /llms.txt rate among known results",
      y = NULL,
      caption = "Cloudflare categories can overlap; domains may appear in multiple category rows."
    ) +
    theme_ai_web_signals()
}

#' Save a plot under results/figures with reproducible defaults.
save_publication_plot <- function(
  plot,
  filename,
  width = 10,
  height = 6,
  dpi = 320,
  bg = "white",
  ...
) {
  if (!stringr::str_detect(filename, "\\.png$")) {
    filename <- paste0(filename, ".png")
  }

  output_path <- file.path("results", "figures", filename)
  dir.create(dirname(output_path), recursive = TRUE, showWarnings = FALSE)

  ggplot2::ggsave(
    output_path,
    plot = plot,
    width = width,
    height = height,
    dpi = dpi,
    bg = bg,
    ...
  )

  invisible(output_path)
}
