# @fipsign/mcp

[![npm](https://img.shields.io/npm/v/@fipsign/mcp)](https://www.npmjs.com/package/@fipsign/mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue)](https://csrc.nist.gov/pubs/fips/204/final)

MCP server for [FIPSign](https://fipsign.dev) — post-quantum digital signing via **ML-DSA-44/65/87** (NIST FIPS 204).

Gives Claude Desktop, Claude Code, and any MCP-compatible AI agent full access to the FIPSign API without writing code: sign payloads, verify tokens, issue and revoke post-quantum certificates, and monitor usage.

---

## Tools

| Tool | Description | Token cost |
|---|---|---|
| `fipsign_health` | Check service status | free |
| `fipsign_public_key` | Get the project's ML-DSA public key (requires API key) | free |
| `fipsign_sign` | Sign any payload | 1 token |
| `fipsign_verify` | Verify a signed token | 1 token |
| `fipsign_revoke` | Permanently revoke a token | 1 token |
| `fipsign_usage` | Get token balance and usage history | free |
| `fipsign_generate_key_pair` | Generate an ML-DSA-65 key pair locally | free |
| `fipsign_ca_issue` | Issue a post-quantum certificate | 1 token |
| `fipsign_ca_revoke_cert` | Revoke a certificate | 1 token |
| `fipsign_ca_get_cert` | Get certificate status by ID | free |
| `fipsign_ca_get_crl` | Get the Certificate Revocation List | free |

---

## Prerequisites

1. Node.js 18 or later
2. A FIPSign account and API key — [create one free at app.fipsign.dev](https://app.fipsign.dev)
3. For CA tools: a CA created inside your project from the dashboard

---

## Local testing before publishing

### Level 1 — MCP Inspector (no Claude Desktop required)

The Inspector opens a browser UI where you can call each tool manually and inspect responses without Claude Desktop.

```bash
git clone https://github.com/fipsign/fipsign-mcp
cd fipsign-mcp
npm install
npm run build
export FIPSIGN_API_KEY=pqa_your_real_key
npx @modelcontextprotocol/inspector node dist/index.js
```

Open the URL shown in the terminal (typically `http://localhost:5173`). Select a tool, fill in the parameters, and run it.

### Level 2 — Claude Desktop with local code (without publishing to npm)

Build first, then point Claude Desktop at the local `dist/index.js`:

```bash
npm run build
```

Add to your `claude_desktop_config.json` (see path below):

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "node",
      "args": ["/absolute/path/to/fipsign-mcp/dist/index.js"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

### Level 3 — Claude Desktop with published package (production)

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "npx",
      "args": ["-y", "@fipsign/mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

---

## Installation for Claude Desktop

`claude_desktop_config.json` is located at:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Add the `fipsign` entry inside `mcpServers` (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "npx",
      "args": ["-y", "@fipsign/mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config. You should see the FIPSign tools available in the tools panel.

---

## Installation for Claude Code

```bash
claude mcp add fipsign -- env FIPSIGN_API_KEY=pqa_your_real_key npx -y @fipsign/mcp
```

Or manually in your project's `.claude/mcp.json`:

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "npx",
      "args": ["-y", "@fipsign/mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FIPSIGN_API_KEY` | Yes (for most tools) | — | Your FIPSign API key. Format: `pqa_` + 64 lowercase hex chars. Get one at app.fipsign.dev. |
| `FIPSIGN_BASE_URL` | No | `https://api.fipsign.dev` | Override API base URL (useful for self-hosted instances or local dev). |

`fipsign_health` and `fipsign_generate_key_pair` work without an API key. `fipsign_public_key` requires an API key — it returns the public key for the project associated with that key.

---

## Usage examples

Once configured, you can ask Claude:

**Signing:**
- *"Sign a token for user_123 with role admin that expires in 1 hour"*
- *"Verify this token: { payload: '...', signature: '...', algorithm: 'ML-DSA-65', issuedAt: 123 }"* *(algorithm may be ML-DSA-44, ML-DSA-65, or ML-DSA-87 depending on the project)*
- *"Revoke this token because the user logged out"*

**Certificates:**
- *"Generate a key pair for a new IoT device"*
- *"Issue a certificate for device-serial-00123 using the public key I just generated, valid for 1 year"*
- *"Check the revocation status of cert_abc123"*
- *"Get the full CRL for our CA"*
- *"Revoke certificate cert_abc123 — device was reported stolen"*

**Monitoring:**
- *"How many tokens do I have left this month?"*

---

## Publishing to npm

```bash
npm run build
npm publish --access public
```

Requires an npm account with publish rights to the `@fipsign` scope.

---

## Links

- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- JS SDK: [npmjs.com/package/fipsign-sdk](https://www.npmjs.com/package/fipsign-sdk)
- Python SDK: [pypi.org/project/fipsign-sdk](https://pypi.org/project/fipsign-sdk/)
- Python MCP: [pypi.org/project/fipsign-mcp](https://pypi.org/project/fipsign-mcp/)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
