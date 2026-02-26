function severityEmoji(score) {
  if (score == null) return ":white_circle:";
  if (score >= 9.0) return ":red_circle:";
  if (score >= 7.0) return ":large_orange_circle:";
  if (score >= 4.0) return ":large_yellow_circle:";
  return ":green_circle:";
}

function severityLabel(score) {
  if (score == null) return "N/A";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

function formatPercent(value) {
  if (value == null) return "N/A";
  return `${(value * 100).toFixed(1)}%`;
}

function formatExploitationActivity(activity) {
  if (!activity) return "None observed";
  const windows = [];
  if (activity["0_to_7_days"]) windows.push("Last 7 days");
  if (activity["8_to_30_days"]) windows.push("8–30 days");
  if (activity["31_to_365_days"]) windows.push("31–365 days");
  if (activity["366_plus_days"]) windows.push("366+ days");
  return windows.length > 0 ? windows.join(", ") : "None observed";
}

function buildCveCard(cve) {
  const cvss = cve.cvss?.[0];
  const cvssScore = cvss?.score;
  const globalScore = cve.scores?.global;
  const epssScore = cve.scores?.epss_v4 || cve.scores?.epss_v3;

  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${cve.identifier}`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: truncate(cve.description || "No description available.", 2900),
      },
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*CVSS Score*\n${severityEmoji(cvssScore)} ${cvssScore != null ? `${cvssScore} (${severityLabel(cvssScore)})` : "N/A"}`,
        },
        {
          type: "mrkdwn",
          text: `*CVSS Version*\n${cvss?.version || "N/A"}`,
        },
        {
          type: "mrkdwn",
          text: `*Global Score*\n${globalScore?.score != null ? `${formatPercent(globalScore.score)} (${formatPercent(globalScore.percentile)} percentile)` : "N/A"}`,
        },
        {
          type: "mrkdwn",
          text: `*EPSS Score*\n${epssScore?.score != null ? `${formatPercent(epssScore.score)} (${formatPercent(epssScore.percentile)} percentile)` : "N/A"}`,
        },
      ],
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*Exploitation Activity*\n${cve.has_exploitation_activity ? ":warning: Yes" : "No"}\n${formatExploitationActivity(cve.exploitation_activity)}`,
        },
        {
          type: "mrkdwn",
          text: `*CISA KEV*\n${cve.cisa_kev_added_at ? `:rotating_light: Added ${cve.cisa_kev_added_at}` : "Not listed"}`,
        },
      ],
    },
  ];

  // Tags section
  const tags = cve.tags;
  if (tags) {
    const tagParts = [];
    if (tags.actor?.length) tagParts.push(`*Actors:* ${tags.actor.join(", ")}`);
    if (tags.keywords?.length)
      tagParts.push(`*Keywords:* ${tags.keywords.join(", ")}`);
    if (tags.component?.length)
      tagParts.push(`*Components:* ${tags.component.join(", ")}`);

    if (tagParts.length > 0) {
      blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: tagParts.join("\n"),
        },
      });
    }
  }

  // Platforms
  if (cve.platforms?.length) {
    const platformText = cve.platforms
      .slice(0, 10)
      .map((p) => `${p.vendor} — ${p.product}`)
      .join("\n");
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Affected Platforms*\n${platformText}${cve.platforms.length > 10 ? `\n_...and ${cve.platforms.length - 10} more_` : ""}`,
      },
    });
  }

  // Exploits
  const exploitCount =
    (cve.exploits?.metasploit?.length || 0) +
    (cve.exploits?.exploitdb?.length || 0) +
    (cve.exploits?.github?.length || 0);
  if (exploitCount > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*Public Exploits:* ${exploitCount} known (Metasploit: ${cve.exploits?.metasploit?.length || 0}, ExploitDB: ${cve.exploits?.exploitdb?.length || 0}, GitHub: ${cve.exploits?.github?.length || 0})`,
      },
    });
  }

  // Dates
  blocks.push({ type: "divider" });
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: [
          cve.published_at && `Published: ${cve.published_at}`,
          cve.last_updated_at && `Updated: ${cve.last_updated_at}`,
        ]
          .filter(Boolean)
          .join("  |  "),
      },
    ],
  });

  // Link to Empirical Security
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

function buildSearchResultsBlocks(results, query) {
  if (!results || results.length === 0) {
    return [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `No results found for: \`${query}\``,
        },
      },
    ];
  }

  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `Search Results (${results.length})`,
      },
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: `Query: \`${query}\`` },
      ],
    },
    { type: "divider" },
  ];

  const displayed = results.slice(0, 10);

  for (const cve of displayed) {
    const cvss = cve.cvss?.[0];
    const cvssScore = cvss?.score;
    const globalScore = cve.scores?.global;

    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: [
          `*<https://app.empiricalsecurity.com/cves/${cve.identifier}|${cve.identifier}>*`,
          truncate(cve.description || "No description.", 200),
          `${severityEmoji(cvssScore)} CVSS: ${cvssScore ?? "N/A"} | Global: ${globalScore?.score != null ? formatPercent(globalScore.score) : "N/A"} | ${cve.has_exploitation_activity ? ":warning: Exploited" : "No exploitation observed"}`,
        ].join("\n"),
      },
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

function truncate(str, max) {
  if (str.length <= max) return str;
  return str.slice(0, max - 3) + "...";
}

module.exports = { buildCveCard, buildSearchResultsBlocks };
