#!/usr/bin/env node

// Local test script — verifies Empirical Security API connection and previews card output.
// Usage:
//   node test-local.js CVE-2023-49103
//   node test-local.js search "score:>90 vendor:microsoft"

const { getCve, searchCves } = require("./src/empirical");
const { buildCveCard, buildSearchResultsBlocks } = require("./src/blocks");

const clientId = process.env.EMPIRICAL_CLIENT_ID;
const clientSecret = process.env.EMPIRICAL_CLIENT_SECRET;

if (!clientId || !clientSecret) {
  console.error(
    "Missing EMPIRICAL_CLIENT_ID or EMPIRICAL_CLIENT_SECRET.\n" +
      "Run with: source .env && node test-local.js CVE-2023-49103\n" +
      "Or:       export EMPIRICAL_CLIENT_ID=... EMPIRICAL_CLIENT_SECRET=... && node test-local.js CVE-2023-49103"
  );
  process.exit(1);
}

async function main() {
  const [, , mode, ...rest] = process.argv;

  if (!mode) {
    console.log("Usage:");
    console.log("  node test-local.js CVE-2023-49103");
    console.log('  node test-local.js search "score:>90 vendor:microsoft"');
    process.exit(0);
  }

  if (mode.toLowerCase() === "search") {
    const query = rest.join(" ");
    console.log(`Searching: ${query}\n`);
    const results = await searchCves(query, clientId, clientSecret);
    const cves = Array.isArray(results) ? results : results?.data || [];
    console.log(`Got ${cves.length} results.\n`);

    // Print summary
    for (const cve of cves.slice(0, 5)) {
      const cvss = cve.cvss?.[0]?.score ?? "N/A";
      const global = cve.scores?.global?.score;
      console.log(
        `  ${cve.identifier}  CVSS=${cvss}  Global=${global != null ? (global * 100).toFixed(1) + "%" : "N/A"}  Exploited=${cve.has_exploitation_activity ?? false}`
      );
    }

    console.log("\n--- Slack blocks (JSON) ---");
    console.log(JSON.stringify(buildSearchResultsBlocks(cves, query), null, 2));
  } else {
    const cveId = mode.toUpperCase();
    console.log(`Looking up: ${cveId}\n`);
    const cve = await getCve(cveId, clientId, clientSecret);

    // Print key fields
    console.log(`Description: ${cve.description?.slice(0, 200)}`);
    console.log(`CVSS: ${cve.cvss?.[0]?.score ?? "N/A"} (${cve.cvss?.[0]?.version ?? "?"})`);
    console.log(`Global Score: ${cve.scores?.global?.score != null ? (cve.scores.global.score * 100).toFixed(1) + "%" : "N/A"}`);
    console.log(`Exploitation Activity: ${cve.has_exploitation_activity}`);
    console.log(`CISA KEV: ${cve.cisa_kev_added_at || "Not listed"}`);
    console.log(`Platforms: ${cve.platforms?.map((p) => `${p.vendor}/${p.product}`).join(", ") || "None"}`);

    console.log("\n--- Slack blocks (JSON) ---");
    console.log(JSON.stringify(buildCveCard(cve), null, 2));
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
