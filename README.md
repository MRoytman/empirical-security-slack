# Empirical Security Slack App

A Slack app that lets you look up CVEs and search vulnerability data from [Empirical Security](https://app.empiricalsecurity.com) directly in Slack using the `/cve` slash command.

## Features

- **CVE lookup** — `/cve CVE-2023-49103` returns a rich card with CVSS scores, exploitation activity, EPSS/Global scores, affected platforms, public exploits, and more
- **Search** — `/cve search score:>90 vendor:microsoft` queries the Empirical Security search API and returns a summary of matching CVEs
- **Fallback search** — any input that isn't a CVE ID is treated as a search query

## Setup

### 1. Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** → **From scratch**
2. Name it (e.g. "Empirical Security") and select your workspace
3. Under **Socket Mode**, enable it and generate an App-Level Token with `connections:write` scope — save this as `SLACK_APP_TOKEN`
4. Under **Slash Commands**, create a new command:
   - Command: `/cve`
   - Description: "Look up CVE details from Empirical Security"
   - Usage hint: `CVE-2023-49103` or `search score:>90`
5. Under **OAuth & Permissions**, add the `chat:write` and `commands` bot token scopes
6. Install the app to your workspace and save the **Bot User OAuth Token** as `SLACK_BOT_TOKEN`
7. Under **Basic Information**, copy the **Signing Secret** as `SLACK_SIGNING_SECRET`

### 2. Get Empirical Security API Credentials

1. Log into [app.empiricalsecurity.com](https://app.empiricalsecurity.com)
2. Go to **Settings → API Clients**
3. Create a new client and save the **Client ID** and **Client Secret** immediately (the secret is only shown once)

### 3. Configure and Run

```bash
# Clone the repo
git clone <your-repo-url>
cd empirical-security-slack

# Install dependencies
npm install

# Copy the example env file and fill in your credentials
cp .env.example .env
# Edit .env with your values

# Run the app
npm start
```

For development with auto-reload:

```bash
npm run dev
```

## Usage

| Command | Description |
|---------|-------------|
| `/cve` | Show usage help |
| `/cve CVE-2023-49103` | Look up a specific CVE |
| `/cve search score:>90` | Search for high-score CVEs |
| `/cve search vendor:microsoft exp_activity:true` | Search with multiple filters |
| `/cve search cisa_kev:true` | Find CISA KEV entries |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SLACK_BOT_TOKEN` | Slack Bot User OAuth Token (`xoxb-...`) |
| `SLACK_SIGNING_SECRET` | Slack app signing secret |
| `SLACK_APP_TOKEN` | Slack app-level token for Socket Mode (`xapp-...`) |
| `EMPIRICAL_CLIENT_ID` | Empirical Security API client ID |
| `EMPIRICAL_CLIENT_SECRET` | Empirical Security API client secret |
| `PORT` | Server port (default: 3000) |

## Architecture

- `src/app.js` — Slack Bolt app with `/cve` command handler
- `src/empirical.js` — Empirical Security API client with OAuth 2.0 token management
- `src/blocks.js` — Slack Block Kit card builders for CVE details and search results
