require("dotenv").config();
const { App } = require("@slack/bolt");
const { getCve, searchCves, getCriticalIndicators } = require("./empirical");
const { buildCveCard, buildSearchResultsBlocks } = require("./blocks");

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  signingSecret: process.env.SLACK_SIGNING_SECRET,
  socketMode: true,
  appToken: process.env.SLACK_APP_TOKEN,
  port: Number(process.env.PORT) || 3000,
});

const clientId = process.env.EMPIRICAL_CLIENT_ID;
const clientSecret = process.env.EMPIRICAL_CLIENT_SECRET;

app.command("/cve", async ({ command, ack, respond }) => {
  await ack();

  const input = command.text.trim();

  if (!input) {
    await respond({
      response_type: "ephemeral",
      text: [
        "*Usage:*",
        "• `/cve CVE-2023-49103` — Look up a specific CVE",
        "• `/cve search score:>90 vendor:microsoft` — Search CVEs",
        "• `/cve search exp_activity:true` — Find actively exploited CVEs",
        "",
        "*Search syntax examples:*",
        "• `score:>90` — High global exploitation score",
        "• `vendor:microsoft` — Filter by vendor",
        "• `exp_activity:true` — Has exploitation activity",
        "• `cisa_kev:true` — In CISA KEV catalog",
      ].join("\n"),
    });
    return;
  }

  try {
    if (CVE_PATTERN.test(input)) {
      const cveId = input.toUpperCase();
      const [cve, ci] = await Promise.all([
        getCve(cveId, clientId, clientSecret),
        getCriticalIndicators(cveId, clientId, clientSecret).catch(() => null),
      ]);
      await respond({
        response_type: "in_channel",
        blocks: buildCveCard(cve, ci),
        text: `CVE details for ${cveId}`,
      });
    } else if (input.toLowerCase().startsWith("search ")) {
      const query = input.slice(7).trim();
      if (!query) {
        await respond({
          response_type: "ephemeral",
          text: "Please provide a search query. Example: `/cve search score:>90 vendor:microsoft`",
        });
        return;
      }
      const results = await searchCves(query, clientId, clientSecret);
      const cves = Array.isArray(results) ? results : results?.data || [];
      const displayed = cves.slice(0, 10);
      const ciEntries = await Promise.all(
        displayed.map((c) =>
          getCriticalIndicators(c.identifier, clientId, clientSecret)
            .then((ci) => [c.identifier, ci])
            .catch(() => [c.identifier, null])
        )
      );
      const ciMap = Object.fromEntries(ciEntries);
      await respond({
        response_type: "in_channel",
        blocks: buildSearchResultsBlocks(cves, query, ciMap),
        text: `Search results for: ${query}`,
      });
    } else {
      // Try to interpret as a CVE ID with flexible matching
      const normalized = input.toUpperCase();
      if (/^CVE-\d{4}-\d+$/.test(normalized)) {
        const [cve, ci] = await Promise.all([
          getCve(normalized, clientId, clientSecret),
          getCriticalIndicators(normalized, clientId, clientSecret).catch(() => null),
        ]);
        await respond({
          response_type: "in_channel",
          blocks: buildCveCard(cve, ci),
          text: `CVE details for ${normalized}`,
        });
      } else {
        // Fall back to search
        const results = await searchCves(input, clientId, clientSecret);
        const cves = Array.isArray(results) ? results : results?.data || [];
        const displayed = cves.slice(0, 10);
        const ciEntries = await Promise.all(
          displayed.map((c) =>
            getCriticalIndicators(c.identifier, clientId, clientSecret)
              .then((ci) => [c.identifier, ci])
              .catch(() => [c.identifier, null])
          )
        );
        const ciMap = Object.fromEntries(ciEntries);
        await respond({
          response_type: "in_channel",
          blocks: buildSearchResultsBlocks(cves, input, ciMap),
          text: `Search results for: ${input}`,
        });
      }
    }
  } catch (err) {
    console.error("Error handling /cve command:", err);
    await respond({
      response_type: "ephemeral",
      text: `:x: Error: ${err.message}`,
    });
  }
});

// Acknowledge button clicks (no-op, the URL opens externally)
app.action("view_empirical", async ({ ack }) => {
  await ack();
});

(async () => {
  await app.start();
  console.log("⚡ Empirical Security Slack app is running");
})();
