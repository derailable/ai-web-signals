# Presentation logic for AI Web Signals figures.

suppressPackageStartupMessages({
  library(dplyr)
  library(forcats)
  library(ggplot2)
  library(scales)
})

restriction_colors <- c(
  None = "#4C78A8",
  Some = "#F2A541",
  All = "#D1495B",
  Unknown = "#A0A0A0"
)

content_signal_colors <- c(
  Yes = "#4C78A8",
  No = "#D1495B",
  Unspecified = "#D9D9D9",
  Invalid = "#F2A541",
  Unknown = "#8C8C8C"
)

theme_ai_web_signals <- function(base_size = 12) {
  theme_minimal(base_size = base_size, base_family = "sans") +
    theme(
      plot.title = element_text(face = "bold", size = base_size + 4),
      plot.subtitle = element_text(margin = margin(b = 8)),
      plot.caption = element_text(
        size = base_size - 2,
        color = "grey35",
        hjust = 0,
        margin = margin(t = 10)
      ),
      panel.grid.minor = element_blank(),
      panel.grid.major.x = element_blank(),
      legend.position = "bottom",
      legend.title = element_text(face = "bold"),
      strip.text = element_text(face = "bold"),
      axis.text = element_text(color = "grey20")
    )
}

plot_llms_by_rank <- function(rank_summary) {
  plot_data <- rank_summary |>
    mutate(
      label = paste0(
        percent(.data$llms_txt_proportion, accuracy = 0.1),
        "\nresolved n=",
        comma(.data$resolved_llms_results)
      )
    )

  ggplot(plot_data, aes(x = .data$rank_band, y = .data$llms_txt_proportion)) +
    geom_col(fill = "#4C78A8", width = 0.72) +
    geom_text(
      aes(label = .data$label),
      vjust = -0.25,
      size = 3.3,
      lineheight = 0.95
    ) +
    scale_y_continuous(
      labels = percent_format(accuracy = 1),
      limits = c(
        0,
        max(0.05, max(plot_data$llms_txt_proportion, na.rm = TRUE) * 1.2)
      ),
      expand = expansion(mult = c(0, 0.02))
    ) +
    labs(
      title = "Observed /llms.txt presence by Tranco rank band",
      subtitle = paste(
        "Descriptive proportions use domains with a resolved",
        "/llms.txt result."
      ),
      x = NULL,
      y = "Share with an observed /llms.txt",
      caption = paste(
        "Network and HTTP failures are excluded from denominators;",
        "response completeness varies across rank bands."
      )
    ) +
    theme_ai_web_signals()
}

plot_group_restrictions <- function(group_summary) {
  label_data <- group_summary |>
    filter(.data$proportion >= 0.055) |>
    mutate(label = percent(.data$proportion, accuracy = 1))

  ggplot(
    group_summary,
    aes(x = .data$purpose_group, y = .data$proportion, fill = .data$restriction)
  ) +
    geom_col(width = 0.72, color = "white", linewidth = 0.3) +
    geom_text(
      data = label_data,
      aes(label = .data$label),
      position = position_stack(vjust = 0.5),
      color = "white",
      fontface = "bold",
      size = 3.3
    ) +
    scale_fill_manual(values = restriction_colors, drop = FALSE) +
    scale_y_continuous(
      labels = percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = expansion(mult = c(0, 0))
    ) +
    labs(
      title = "Tracked-agent restrictions by purpose",
      subtitle = paste(
        "All selected domains are shown, including unresolved",
        "policy observations."
      ),
      x = NULL,
      y = "Share of all domains",
      fill = "Agents restricted",
      caption = paste(
        "‘All’ means every tracked agent in the group has some",
        "restriction;",
        "it does not mean every path is blocked."
      )
    ) +
    theme_ai_web_signals()
}

plot_agent_restrictions <- function(agent_summary) {
  plot_data <- agent_summary |>
    mutate(
      agent = forcats::fct_reorder(.data$agent, .data$restriction_proportion),
      label = paste0(
        percent(.data$restriction_proportion, accuracy = 0.1),
        "  (resolved n=",
        comma(.data$resolved_results),
        ")"
      )
    )

  ggplot(plot_data, aes(x = .data$restriction_proportion, y = .data$agent)) +
    geom_col(fill = "#D1495B", width = 0.68) +
    geom_text(aes(label = .data$label), hjust = -0.03, size = 3) +
    facet_grid(.data$purpose_group ~ ., scales = "free_y", space = "free_y") +
    scale_x_continuous(
      labels = percent_format(accuracy = 1),
      limits = c(
        0,
        max(
          0.05,
          max(plot_data$restriction_proportion, na.rm = TRUE) * 1.25
        )
      ),
      expand = expansion(mult = c(0, 0.02))
    ) +
    labs(
      title = "Observed restriction proportions for tracked agents",
      subtitle = paste(
        "Partial and full restrictions count as restrictive in",
        "the resolved subset."
      ),
      x = "Share of resolved policy observations",
      y = NULL,
      caption = paste(
        "Descriptive results are conditional on a resolved robots.txt policy;",
        "they do not demonstrate crawler compliance or enforcement."
      )
    ) +
    theme_ai_web_signals() +
    theme(
      strip.text.y = element_text(angle = 0),
      panel.grid.major.y = element_blank()
    )
}

plot_content_signals <- function(content_summary) {
  label_data <- content_summary |>
    filter(.data$proportion >= 0.055) |>
    mutate(
      label = percent(.data$proportion, accuracy = 1),
      label_color = if_else(.data$signal == "Unspecified", "grey20", "white")
    )

  ggplot(
    content_summary,
    aes(x = .data$purpose, y = .data$proportion, fill = .data$signal)
  ) +
    geom_col(width = 0.72, color = "white", linewidth = 0.3) +
    geom_text(
      data = label_data,
      aes(label = .data$label, color = .data$label_color),
      position = position_stack(vjust = 0.5),
      fontface = "bold",
      size = 3.3
    ) +
    scale_color_identity() +
    scale_fill_manual(values = content_signal_colors, drop = FALSE) +
    scale_y_continuous(
      labels = percent_format(accuracy = 1),
      limits = c(0, 1),
      expand = expansion(mult = c(0, 0))
    ) +
    labs(
      title = "Site-wide Content-Signal declarations",
      subtitle = paste(
        "All selected domains are shown; unspecified and",
        "unresolved are distinct."
      ),
      x = NULL,
      y = "Share of all domains",
      fill = "Declaration",
      caption = paste(
        "Content Signals express published preferences;",
        "they are separate from crawler access rules."
      )
    ) +
    theme_ai_web_signals()
}

plot_llms_restriction_overlap <- function(overlap_summary) {
  plot_data <- overlap_summary |>
    mutate(
      label = paste0(
        percent(.data$proportion, accuracy = 0.1),
        "\n",
        comma(.data$count),
        " of ",
        comma(.data$denominator)
      )
    )

  ggplot(
    plot_data,
    aes(x = .data$restriction, y = .data$llms_txt, fill = .data$proportion)
  ) +
    geom_tile(color = "white", linewidth = 1) +
    geom_text(aes(label = .data$label), size = 3.5, lineheight = 0.95) +
    scale_fill_gradient(
      low = "#F3F6F8",
      high = "#4C78A8",
      labels = percent_format(accuracy = 1),
      limits = c(0, 1)
    ) +
    labs(
      title = paste(
        "Observed /llms.txt files and tracked-agent restrictions",
        "can coexist"
      ),
      subtitle = paste(
        "Each row is normalized within the subset where both",
        "signals were resolved."
      ),
      x = NULL,
      y = NULL,
      fill = "Within-row share",
      caption = paste(
        "This descriptive comparison excludes unresolved observations",
        "and does not imply an association in the full domain population."
      )
    ) +
    theme_ai_web_signals() +
    theme(panel.grid = element_blank())
}

save_publication_plot <- function(
  plot,
  filename,
  width = 10,
  height = 6,
  dpi = 320,
  bg = "white"
) {
  if (!grepl("\\.png$", filename)) {
    filename <- paste0(filename, ".png")
  }

  output_path <- file.path("results", "figures", filename)
  dir.create(dirname(output_path), recursive = TRUE, showWarnings = FALSE)
  ggsave(
    output_path,
    plot = plot,
    width = width,
    height = height,
    dpi = dpi,
    bg = bg
  )
  invisible(output_path)
}
