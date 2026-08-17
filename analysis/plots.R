# Build report plots.
library(dplyr)
library(ggplot2)
library(scales)

plot_theme <- theme_minimal(base_size = 12, base_family = "sans") +
  theme(
    plot.title = element_text(face = "bold", size = 16),
    plot.subtitle = element_text(margin = margin(b = 8)),
    plot.caption = element_text(
      size = 10,
      color = "grey35",
      hjust = 0,
      margin = margin(t = 10)
    ),
    panel.grid.minor = element_blank(),
    panel.grid.major.x = element_blank(),
    legend.position = "bottom",
    legend.title = element_text(face = "bold"),
    axis.text = element_text(color = "grey20")
  )

llms_result <- key_metrics |>
  filter(metric == "Observed /llms.txt among resolved observations")

llms_presence_data <- tibble::tibble(
  status = factor(
    c("Observed", "Not observed"),
    levels = c("Not observed", "Observed")
  ),
  count = c(
    llms_result$numerator,
    llms_result$denominator - llms_result$numerator
  )
) |>
  mutate(
    proportion = count / llms_result$denominator,
    label = paste0(
      percent(proportion, accuracy = 0.1),
      "\n",
      comma(count)
    ),
    label_color = if_else(status == "Observed", "white", "grey20")
  )

llms_presence_plot <- ggplot(
  llms_presence_data,
  aes(x = "", y = proportion, fill = status)
) +
  geom_col(width = 0.55, color = "white") +
  geom_text(
    aes(label = label, color = label_color),
    position = position_stack(vjust = 0.5),
    fontface = "bold",
    lineheight = 0.95
  ) +
  coord_flip() +
  scale_color_identity() +
  scale_fill_manual(
    values = c("Observed" = "#4C78A8", "Not observed" = "#D9D9D9")
  ) +
  scale_y_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    expand = expansion(mult = c(0, 0))
  ) +
  labs(
    title = "Observed /llms.txt presence",
    subtitle = paste(comma(llms_result$denominator), "resolved endpoint results"),
    x = NULL,
    y = NULL,
    fill = NULL,
    caption = paste(
      "Plausible presence only; semantic quality and provider use",
      "were not assessed."
    )
  ) +
  plot_theme +
  theme(
    axis.text.y = element_blank(),
    panel.grid = element_blank()
  )

overlap_plot_data <- overlap_summary |>
  mutate(
    label = paste0(
      percent(proportion, accuracy = 0.1),
      "\n",
      comma(count),
      " of ",
      comma(denominator)
    )
  )

overlap_plot <- ggplot(
  overlap_plot_data,
  aes(x = restriction, y = llms_txt, fill = proportion)
) +
  geom_tile(color = "white", linewidth = 1) +
  geom_text(aes(label = label), size = 3.5, lineheight = 0.95) +
  scale_fill_gradient(
    low = "#F3F6F8",
    high = "#4C78A8",
    labels = percent_format(accuracy = 1),
    limits = c(0, 1)
  ) +
  labs(
    title = "Publishing /llms.txt does not imply unrestricted access",
    subtitle = paste(
      "Among domains where both endpoints resolved; rules may be",
      "explicit or wildcard."
    ),
    x = NULL,
    y = NULL,
    fill = "Within-row share",
    caption = paste(
      "Any partial or full rule applicable to at least one tracked agent.",
      "This does not measure permission, compliance, or enforcement."
    )
  ) +
  plot_theme +
  theme(panel.grid = element_blank())

restriction_source_data <- restriction_source_summary |>
  mutate(
    source = factor(
      source,
      levels = c("Wildcard rule", "Explicit agent rule")
    ),
    label = paste0(
      percent(proportion, accuracy = 0.1),
      "  (n=",
      comma(count),
      ")"
    ),
    label_hjust = if_else(proportion > 0.75, 1.04, -0.04),
    label_color = if_else(proportion > 0.75, "white", "grey20")
  )

restriction_source_plot <- ggplot(
  restriction_source_data,
  aes(x = proportion, y = source)
) +
  geom_col(fill = "#D1495B", width = 0.62) +
  geom_text(
    aes(
      label = label,
      hjust = label_hjust,
      color = label_color
    ),
    size = 3.5
  ) +
  scale_color_identity() +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    expand = expansion(mult = c(0, 0.02))
  ) +
  labs(
    title = "Most applicable restrictions come from wildcard rules",
    subtitle = paste0(
      "Among ",
      comma(unique(restriction_source_data$denominator)),
      " restrictive domain-agent observations."
    ),
    x = "Share of restrictive observations",
    y = NULL,
    caption = paste(
      "A wildcard rule is inherited from User-agent: *;",
      "partial and full restrictions are included."
    )
  ) +
  plot_theme +
  theme(
    legend.position = "none",
    panel.grid.major.y = element_blank()
  )

content_plot_data <- content_summary |>
  filter(signal %in% c("Yes", "No")) |>
  mutate(label = percent(resolved_proportion, accuracy = 0.1))

content_labels <- content_plot_data |>
  filter(count > 0)

unspecified_range <- content_summary |>
  filter(signal == "Unspecified") |>
  pull(resolved_proportion) |>
  range(na.rm = TRUE)

content_signals_plot <- ggplot(
  content_plot_data,
  aes(
    x = resolved_proportion,
    y = purpose,
    fill = signal
  )
) +
  geom_col(position = position_dodge(width = 0.72), width = 0.64) +
  geom_text(
    data = content_labels,
    aes(label = label),
    position = position_dodge(width = 0.72),
    hjust = -0.12,
    size = 3.2
  ) +
  scale_fill_manual(
    values = c("Yes" = "#4C78A8", "No" = "#D1495B"),
    drop = FALSE
  ) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, max(content_plot_data$resolved_proportion) * 1.22),
    expand = expansion(mult = c(0, 0.02))
  ) +
  labs(
    title = "Explicit Content Signals remain rare",
    subtitle = paste0(
      percent(unspecified_range[[1]], accuracy = 0.1),
      " to ",
      percent(unspecified_range[[2]], accuracy = 0.1),
      " of resolved observations were unspecified."
    ),
    x = "Share of resolved observations",
    y = NULL,
    fill = "Preference",
    caption = paste(
      "Site-wide declarations only. Invalid results remain in the",
      "exported table."
    )
  ) +
  plot_theme +
  theme(panel.grid.major.y = element_blank())
