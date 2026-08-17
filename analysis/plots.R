# Build publication-ready report plots.
library(dplyr)
library(ggplot2)
library(scales)

signal_blue <- "#2F6FA3"
restriction_red <- "#C94C4C"
ink <- "#17212B"
muted_ink <- "#52606D"
light_fill <- "#DDE3E8"
grid_color <- "#E7EBEF"

plot_theme <- theme_minimal(base_size = 12, base_family = "sans") +
  theme(
    plot.title = element_text(
      face = "bold",
      size = 17,
      color = ink,
      margin = margin(b = 5)
    ),
    plot.subtitle = element_text(
      size = 12,
      color = muted_ink,
      margin = margin(b = 14)
    ),
    plot.caption = element_text(
      size = 9.5,
      color = muted_ink,
      hjust = 0,
      lineheight = 1.1,
      margin = margin(t = 12)
    ),
    plot.title.position = "plot",
    plot.caption.position = "plot",
    plot.margin = margin(12, 22, 10, 12),
    panel.grid.minor = element_blank(),
    panel.grid.major.y = element_blank(),
    panel.grid.major.x = element_line(color = grid_color, linewidth = 0.35),
    legend.position = "bottom",
    legend.title = element_text(face = "bold", color = ink),
    legend.text = element_text(color = ink),
    axis.title = element_text(color = ink),
    axis.text = element_text(color = ink)
  )

overall_llms_rate <- key_metrics |>
  filter(metric == "Observed /llms.txt among resolved observations") |>
  pull(proportion)
overall_restriction_rate <- mean(domains$any_ai_bot_restricted, na.rm = TRUE)

category_order <- category_plot_data |>
  arrange(observed_llms_txt_share) |>
  pull(category)

category_comparison_data <- bind_rows(
  category_plot_data |>
    transmute(
      category,
      signal = "/llms.txt present",
      value = observed_llms_txt_share
    ),
  category_plot_data |>
    transmute(
      category,
      signal = "Tracked-agent restriction",
      value = any_agent_restriction_share
    )
) |>
  mutate(
    signal = factor(
      signal,
      levels = c("/llms.txt present", "Tracked-agent restriction")
    ),
    category = factor(category, levels = category_order),
    label = percent(value, accuracy = 0.1)
  )

category_reference_data <- tibble::tibble(
  signal = factor(
    c("/llms.txt present", "Tracked-agent restriction"),
    levels = levels(category_comparison_data$signal)
  ),
  value = c(overall_llms_rate, overall_restriction_rate)
)

category_comparison_plot <- ggplot(
  category_comparison_data,
  aes(x = value, y = category, color = signal)
) +
  geom_vline(
    data = category_reference_data,
    aes(xintercept = value),
    color = muted_ink,
    linewidth = 0.6,
    linetype = "22",
    inherit.aes = FALSE
  ) +
  geom_segment(
    aes(x = 0, xend = value, yend = category),
    color = light_fill,
    linewidth = 1
  ) +
  geom_point(size = 3.2) +
  geom_label(
    aes(label = label),
    hjust = -0.1,
    size = 2.9,
    color = ink,
    fill = "white",
    label.size = 0,
    label.padding = grid::unit(0.03, "lines")
  ) +
  facet_grid(. ~ signal, scales = "free_x") +
  scale_color_manual(values = c(
    "/llms.txt present" = signal_blue,
    "Tracked-agent restriction" = restriction_red
  )) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    expand = expansion(mult = c(0, 0.28))
  ) +
  labs(
    title = "Categories signal discovery and restriction differently",
    subtitle = "Ten categories, ordered by /llms.txt rate",
    x = "Share of resolved observations",
    y = NULL,
    caption = paste0(
      "ChatGPT-assigned categories with at least ",
      comma(category_min_resolved),
      " resolved checks for both signals; Other / Unknown omitted.",
      "\nDashed lines show all-domain rates."
    )
  ) +
  plot_theme +
  theme(
    legend.position = "none",
    panel.spacing.x = grid::unit(2.5, "lines"),
    strip.text = element_text(face = "bold", color = ink, size = 11),
    strip.background = element_rect(fill = "#F4F6F8", color = NA)
  )

overlap_plot_data <- overlap_summary |>
  filter(restriction == "Any tracked-agent restriction") |>
  mutate(
    llms_txt = factor(
      llms_txt,
      levels = c("Not present", "Present"),
      labels = c("No /llms.txt", "Has /llms.txt")
    ),
    label = paste0(
      percent(proportion, accuracy = 0.1),
      "  |  ",
      comma(count),
      " of ",
      comma(denominator)
    )
  )

overlap_present_rate <- overlap_plot_data |>
  filter(llms_txt == "Has /llms.txt") |>
  pull(proportion)

overlap_absent_rate <- overlap_plot_data |>
  filter(llms_txt == "No /llms.txt") |>
  pull(proportion)

overlap_plot <- ggplot(overlap_plot_data, aes(y = llms_txt)) +
  geom_col(aes(x = 1), fill = light_fill, width = 0.58) +
  geom_col(aes(x = proportion), fill = restriction_red, width = 0.58) +
  geom_text(
    aes(x = proportion, label = label),
    hjust = 1.08,
    color = "white",
    fontface = "bold",
    size = 3.5
  ) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    breaks = seq(0, 1, 0.25),
    expand = expansion(mult = c(0, 0))
  ) +
  labs(
    title = "Publishing /llms.txt coincides with more restrictions",
    subtitle = paste0(
      percent(overlap_present_rate, accuracy = 0.1),
      " vs ",
      percent(overlap_absent_rate, accuracy = 0.1),
      " where both endpoints resolved"
    ),
    x = "Share with any partial or full tracked-agent restriction",
    y = NULL,
    caption = paste(
      "Partial and full rules; explicit or inherited.",
      "Signals do not establish permission or enforcement."
    )
  ) +
  plot_theme +
  theme(legend.position = "none")

content_plot_data <- content_summary |>
  filter(signal %in% c("Yes", "No")) |>
  mutate(label = percent(resolved_proportion, accuracy = 0.1))

unspecified_range <- content_summary |>
  filter(signal == "Unspecified") |>
  pull(resolved_proportion) |>
  range(na.rm = TRUE)

content_dodge <- position_dodge(width = 0.48)

content_signals_plot <- ggplot(
  content_plot_data,
  aes(x = resolved_proportion, y = purpose, color = signal)
) +
  geom_point(size = 4, position = content_dodge) +
  geom_text(
    aes(label = label),
    position = content_dodge,
    hjust = -0.35,
    size = 3.3,
    show.legend = FALSE
  ) +
  scale_color_manual(values = c("Yes" = signal_blue, "No" = restriction_red)) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(-0.002, max(content_plot_data$resolved_proportion) * 1.18),
    expand = expansion(mult = c(0, 0))
  ) +
  labs(
    title = "Content Signals are nearly absent except for training refusals",
    subtitle = paste0(
      percent(unspecified_range[[1]], accuracy = 0.1),
      " to ",
      percent(unspecified_range[[2]], accuracy = 0.1),
      " of resolved declarations were unspecified"
    ),
    x = "Share of resolved observations",
    y = NULL,
    color = "Declared preference",
    caption = paste(
      "Site-wide declarations. AI-training 'No' reached 5.7%;",
      "all other explicit responses stayed below 1%."
    )
  ) +
  plot_theme
