// --- Helpers ---

function formatPercent(value) {
  if (value == null) return "N/A";
  return `${(value * 100).toFixed(1)}%`;
}

function weightArrow(weightCategory) {
  switch (weightCategory) {
    case "2":  return "↑↑";
    case "1":  return " ↑";
    case "0":  return "←→";
    case "-1": return " ↓";
    default:   return "←→";
  }
}

const CATEGORY_ICONS = {
  Chatter:           ":speech_balloon:",
  "Exploit Code":    ":computer:",
  Exploitation:      ":zap:",
  References:        ":link:",
  "Threat Intel":    ":shield:",
  Vendor:            ":office:",
  "Vuln Attributes": ":gear:",
};

const CATEGORY_ORDER = [
  "Chatter",
  "Exploit Code",
  "Exploitation",
  "References",
  "Threat Intel",
  "Vendor",
  "Vuln Attributes",
];

function formatPlatforms(platforms) {
  if (!platforms?.length) return "_No platforms listed_";

  const grouped = {};
  for (const p of platforms) {
    if (!grouped[p.vendor]) grouped[p.vendor] = [];
    grouped[p.vendor].push(p.product);
  }

  const vendors = Object.keys(grouped).slice(0, 5);
  const lines = vendors.map((vendor) => {
    const products = grouped[vendor].slice(0, 5);
    const extra =
      grouped[vendor].length > 5
        ? ` _+${grouped[vendor].length - 5} more_`
        : "";
    return `*${vendor}:* ${products.join(", ")}${extra}`;
  });

  const totalVendors = Object.keys(grouped).length;
  const totalPlatforms = platforms.length;
  if (totalVendors > 5) {
    lines.push(
      `_+${totalVendors - 5} more vendors (${totalPlatforms} platforms total)_`
    );
  }

  return lines.join("\n");
}

function buildIndicatorFields(indicators) {
  if (!indicators?.length) return null;

  const global = indicators.find((i) => i.scoring_model === "global");
  if (!global?.critical_indicators_data) return null;

  const data = global.critical_indicators_data;

  const fields = CATEGORY_ORDER
    .filter((cat) => data[cat])
    .map((cat) => {
      const info = data[cat];
      const arrow = weightArrow(info.weight_category);
      const icon = CATEGORY_ICONS[cat] || "";
      return {
        type: "mrkdwn",
        text: `${arrow}  ${icon}  *${cat}*`,
      };
    });

  return fields.length > 0 ? fields : null;
}

function formatIndicatorsCompact(indicators) {
  if (!indicators?.length) return null;

  const global = indicators.find((i) => i.scoring_model === "global");
  if (!global?.critical_indicators_data) return null;

  const data = global.critical_indicators_data;
  const parts = CATEGORY_ORDER
    .filter((cat) => data[cat] && data[cat].weight_category !== "0")
    .map((cat) => `${weightArrow(data[cat].weight_category).trim()} ${cat}`);

  return parts.length > 0 ? parts.join(" · ") : null;
}

function formatExploitationWindows(activity) {
  if (!activity) return null;
  const lines = [];
  if (activity["0_to_7_days"])    lines.push("• Within past 7 days");
  if (activity["8_to_30_days"])   lines.push("• 8 to 30 days ago");
  if (activity["31_to_365_days"]) lines.push("• 31 to 365 days ago");
  if (activity["366_plus_days"])  lines.push("• Over 1 year ago");
  return lines.length > 0 ? lines.join("\n") : null;
}

function truncate(str, max) {
  if (str.length <= max) return str;
  return str.slice(0, max - 3) + "...";
}

// --- Card builders ---

function buildCveCard(cve, criticalIndicators) {
  const globalScore = cve.scores?.global;

  const blocks = [
    // Header
    {
      type: "header",
      text: { type: "plain_text", text: cve.identifier, emoji: true },
    },
    // Global Score
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Global Score:*  ${globalScore?.score != null ? `${formatPercent(globalScore.score)}  (${formatPercent(globalScore.percentile)} percentile)` : "N/A"}`,
      },
    },
    // Summary
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Summary*\n${truncate(cve.description || "No description available.", 2900)}`,
      },
    },
    { type: "divider" },
  ];

  // Critical Indicators — 2-column grid using section.fields
  const ciFields = buildIndicatorFields(criticalIndicators);
  if (ciFields) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: "*Critical Indicators*" },
    });
    // Slack renders fields in a 2-column grid
    blocks.push({
      type: "section",
      fields: ciFields,
    });
    blocks.push({ type: "divider" });
  }

  // Exploitation Activity
  const windows = formatExploitationWindows(cve.exploitation_activity);
  blocks.push({
    type: "section",
    text: {
      type: "mrkdwn",
      text: `*Known Exploitation Activity:*  ${cve.has_exploitation_activity ? "Yes" : "None observed"}${windows ? "\n" + windows : ""}`,
    },
  });
  blocks.push({ type: "divider" });

  // Vendors & Products
  blocks.push({
    type: "section",
    text: {
      type: "mrkdwn",
      text: `*Vendors and Products*\n${formatPlatforms(cve.platforms)}`,
    },
  });

  // Action button
  blocks.push({ type: "divider" });
  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "View on Empirical Security" },
        url: `https://app.empiricalsecurity.com/cves/${cve.identifier}`,
        action_id: "view_empirical",
      },
    ],
  });

  return blocks;
}

function buildSearchResultsBlocks(results, query, criticalIndicatorsMap) {
  if (!results || results.length === 0) {
    return [
      {
        type: "section",
        text: { type: "mrkdwn", text: `No results found for: \`${query}\`` },
      },
    ];
  }

  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `Search Results (${results.length})` },
    },
    {
      type: "context",
      elements: [{ type: "mrkdwn", text: `Query: \`${query}\`` }],
    },
    { type: "divider" },
  ];

  const displayed = results.slice(0, 10);

  for (const cve of displayed) {
    const globalScore = cve.scores?.global;
    const ci = criticalIndicatorsMap?.[cve.identifier];
    const ciCompact = formatIndicatorsCompact(ci);

    const lines = [
      `*<https://app.empiricalsecurity.com/cves/${cve.identifier}|${cve.identifier}>*  —  Global: ${globalScore?.score != null ? formatPercent(globalScore.score) : "N/A"}`,
      truncate(cve.description || "No description.", 200),
      `Exploitation: ${cve.has_exploitation_activity ? "Yes" : "None"} — ${formatExploitationWindows(cve.exploitation_activity) ? formatExploitationWindows(cve.exploitation_activity).replace(/\n/g, ", ").replace(/• /g, "") : "None observed"}`,
    ];

    if (ciCompact) {
      lines.push(`Indicators: ${ciCompact}`);
    }

    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: lines.join("\n") },
    });
    blocks.push({ type: "divider" });
  }

  if (results.length > 10) {
    blocks.push({
      type: "context",
      elements: [
        {
          type: "mrkdwn",
          text: `_Showing 10 of ${results.length} results. Refine your query to narrow results._`,
        },
      ],
    });
  }

  return blocks;
}

module.exports = { buildCveCard, buildSearchResultsBlocks };
