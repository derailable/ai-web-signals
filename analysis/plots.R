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

llms_result <- key_metrics |>
  filter(metric == "Observed /llms.txt among resolved observations")

llms_presence_data <- tibble::tibble(
  status = c("Observed", "Not observed"),
  count = c(
    llms_result$numerator,
    llms_result$denominator - llms_result$numerator
  )
) |>
  mutate(
    proportion = count / llms_result$denominator,
    xmax = cumsum(proportion),
    xmin = lag(xmax, default = 0),
    xmid = (xmin + xmax) / 2,
    label = paste0(
      status,
      "\n",
      percent(proportion, accuracy = 0.1),
      "  |  ",
      comma(count)
    ),
    label_color = if_else(status == "Observed", "white", ink)
  )

llms_presence_plot <- ggplot(llms_presence_data) +
  geom_rect(
    aes(xmin = xmin, xmax = xmax, ymin = 0.72, ymax = 1.28, fill = status)
  ) +
  geom_text(
    aes(x = xmid, y = 1, label = label, color = label_color),
    fontface = "bold",
    lineheight = 0.95,
    size = 3.8
  ) +
  scale_color_identity() +
  scale_fill_manual(values = c("Observed" = signal_blue, "Not observed" = light_fill)) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    breaks = seq(0, 1, 0.25),
    expand = expansion(mult = c(0, 0))
  ) +
  scale_y_continuous(limits = c(0.58, 1.42), expand = expansion(mult = 0)) +
  labs(
    title = "Only one in eight resolved domains published /llms.txt",
    subtitle = paste(comma(llms_result$denominator), "resolved /llms.txt checks"),
    x = NULL,
    y = NULL,
    caption = paste(
      "Plausible presence only; semantic quality and provider use",
      "were not assessed."
    )
  ) +
  plot_theme +
  theme(
    axis.text.y = element_blank(),
    axis.ticks.y = element_blank(),
    panel.grid.major.y = element_blank(),
    legend.position = "none"
  )

overall_llms_rate <- llms_result$proportion
overall_restriction_rate <- mean(domains$any_ai_bot_restricted, na.rm = TRUE)

category_caption <- paste0(
  "ChatGPT-assigned categories with at least ",
  comma(category_min_resolved),
  " resolved observations for both signals; Other / Unknown omitted.",
  "\nThe dashed line is the all-domain resolved rate."
)

category_llms_data <- category_plot_data |>
  mutate(
    label = paste0(
      percent(observed_llms_txt_share, accuracy = 0.1),
      "  ",
      comma(observed_llms_txt),
      "/",
      comma(resolved_llms_txt)
    ),
    category_order = reorder(category, observed_llms_txt_share)
  )

category_llms_plot <- ggplot(
  category_llms_data,
  aes(x = observed_llms_txt_share, y = category_order)
) +
  geom_vline(
    xintercept = overall_llms_rate,
    color = muted_ink,
    linewidth = 0.6,
    linetype = "22"
  ) +
  geom_segment(
    aes(x = 0, xend = observed_llms_txt_share, yend = category_order),
    color = light_fill,
    linewidth = 1.1
  ) +
  geom_point(color = signal_blue, size = 3.5) +
  geom_label(
    aes(label = label),
    hjust = -0.12,
    size = 3.2,
    color = ink,
    fill = "white",
    label.size = 0,
    label.padding = grid::unit(0.04, "lines")
  ) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, max(category_llms_data$observed_llms_txt_share) * 1.38),
    expand = expansion(mult = c(0, 0))
  ) +
  labs(
    title = "Software and finance lead /llms.txt adoption",
    subtitle = "Plausible files among resolved /llms.txt checks, by domain category",
    x = "Share with /llms.txt",
    y = NULL,
    caption = category_caption
  ) +
  plot_theme

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
      "Rules may be explicit or inherited from User-agent: *.",
      "This does not measure permission, compliance, or enforcement."
    )
  ) +
  plot_theme +
  theme(legend.position = "none")

category_restriction_data <- category_plot_data |>
  mutate(
    label = paste0(
      percent(any_agent_restriction_share, accuracy = 0.1),
      "  ",
      comma(any_agent_restriction),
      "/",
      comma(resolved_agent_policy)
    ),
    label_hjust = if_else(any_agent_restriction_share > 0.82, 1.14, -0.12),
    category_order = reorder(category, any_agent_restriction_share)
  )

category_restriction_plot <- ggplot(
  category_restriction_data,
  aes(x = any_agent_restriction_share, y = category_order)
) +
  geom_vline(
    xintercept = overall_restriction_rate,
    color = muted_ink,
    linewidth = 0.6,
    linetype = "22"
  ) +
  geom_segment(
    aes(x = 0, xend = any_agent_restriction_share, yend = category_order),
    color = light_fill,
    linewidth = 1.1
  ) +
  geom_point(color = restriction_red, size = 3.5) +
  geom_label(
    aes(label = label, hjust = label_hjust),
    size = 3.2,
    color = ink,
    fill = "white",
    label.size = 0,
    label.padding = grid::unit(0.04, "lines")
  ) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    breaks = seq(0, 1, 0.25),
    expand = expansion(mult = c(0, 0))
  ) +
  labs(
    title = "Publishing and retail most often restrict tracked agents",
    subtitle = "Any applicable partial or full robots.txt restriction, by domain category",
    x = "Share with a tracked-agent restriction",
    y = NULL,
    caption = category_caption
  ) +
  plot_theme

restriction_source_data <- restriction_source_summary |>
  mutate(
    source = factor(source, levels = c("Wildcard rule", "Explicit agent rule"))
  ) |>
  arrange(source) |>
  mutate(
    xmax = cumsum(proportion),
    xmin = lag(xmax, default = 0),
    xmid = (xmin + xmax) / 2,
    label = paste0(
      if_else(source == "Wildcard rule", "Wildcard rule", "Explicit rule"),
      "\n",
      percent(proportion, accuracy = 0.1),
      "\n",
      comma(count)
    ),
    label_color = if_else(source == "Wildcard rule", "white", ink)
  )

restriction_source_plot <- ggplot(restriction_source_data) +
  geom_rect(
    aes(xmin = xmin, xmax = xmax, ymin = 0.72, ymax = 1.28, fill = source)
  ) +
  geom_text(
    aes(x = xmid, y = 1, label = label, color = label_color),
    fontface = "bold",
    lineheight = 0.95,
    size = 3.25
  ) +
  scale_color_identity() +
  scale_fill_manual(
    values = c("Wildcard rule" = restriction_red, "Explicit agent rule" = light_fill)
  ) +
  scale_x_continuous(
    labels = percent_format(accuracy = 1),
    limits = c(0, 1),
    breaks = seq(0, 1, 0.25),
    expand = expansion(mult = c(0, 0))
  ) +
  scale_y_continuous(limits = c(0.58, 1.42), expand = expansion(mult = 0)) +
  labs(
    title = "Nine in ten applicable restrictions are inherited",
    subtitle = paste0(
      comma(unique(restriction_source_data$denominator)),
      " restrictive domain-agent observations"
    ),
    x = NULL,
    y = NULL,
    caption = paste(
      "Wildcard rules are inherited from User-agent: *;",
      "partial and full restrictions are included."
    )
  ) +
  plot_theme +
  theme(
    axis.text.y = element_blank(),
    axis.ticks.y = element_blank(),
    panel.grid.major.y = element_blank(),
    legend.position = "none"
  )

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
    title = "Content Signals are nearly absent, with one exception",
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
      "AI-training refusals reached 5.7%; every other explicit",
      "yes/no declaration remained below 1%. Site-wide declarations only."
    )
  ) +
  plot_theme
