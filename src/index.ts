#!/usr/bin/env node
/**
 * @fipsign/mcp — MCP server for FIPSign post-quantum signing API
 *
 * Exposes 11 tools covering the full FIPSign runtime API:
 * signing, verification, revocation, usage, CA certificate lifecycle,
 * and key pair generation.
 *
 * Configuration:
 *   FIPSIGN_API_KEY  — required for most tools (pqa_ + 64 hex chars)
 *   FIPSIGN_BASE_URL — optional, defaults to https://api.fipsign.dev
 *
 * Transport: stdio (compatible with Claude Desktop and Claude Code)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

// ─── Configuration ────────────────────────────────────────────────────────────

const API_KEY = process.env.FIPSIGN_API_KEY ?? "";
const BASE_URL = (process.env.FIPSIGN_BASE_URL ?? "https://api.fipsign.dev").replace(/\/$/, "");

// ─── HTTP helper ──────────────────────────────────────────────────────────────

async function apiRequest(
  method: string,
  path: string,
  body?: unknown
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    data = { success: false, error: `HTTP ${response.status} — non-JSON response` };
  }

  return { ok: response.ok, status: response.status, data };
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// ─── Tool result helpers ──────────────────────────────────────────────────────

function ok(data: unknown): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

function err(message: string, detail?: unknown): { content: Array<{ type: "text"; text: string }>; isError: true } {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { error: message, ...(detail !== undefined ? { detail } : {}) },
          null,
          2
        ),
      },
    ],
    isError: true,
  };
}

function missingApiKey() {
  return err(
    "FIPSIGN_API_KEY is not set. Export it before starting the server: export FIPSIGN_API_KEY=pqa_..."
  );
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS: Tool[] = [
  // ── Infrastructure ──────────────────────────────────────────────────────────

  {
    name: "fipsign_health",
    description:
      "Check the health of the FIPSign service. Returns the service status, algorithm (ML-DSA-65), NIST standard, and version. No API key required. Use this to verify the service is reachable before running other operations.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  {
    name: "fipsign_public_key",
    description:
      "Get the current ML-DSA-65 public key of the FIPSign server. Returns a base64-encoded 1952-byte public key. Use this when you need to verify token signatures independently without calling the /verify endpoint (e.g. for offline verification or third-party auditing). No API key required.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  // ── Core signing ─────────────────────────────────────────────────────────────

  {
    name: "fipsign_sign",
    description:
      "Sign any payload with ML-DSA-65 (NIST FIPS 204). The only required field is 'sub' — any string identifying the entity being signed: a user ID, order ID, document hash, device serial, AI agent action, or anything else. All other fields are stored in the payload and returned on verify. Costs 1 token. Returns the signed token object (payload, signature, algorithm, issuedAt) plus usage info.",
    inputSchema: {
      type: "object",
      properties: {
        sub: {
          type: "string",
          description: "Required. Entity identifier. Max 128 characters. Examples: 'user_123', 'order_456', 'doc_hash_abc', 'device_serial_001', 'agent_action_summarize'.",
        },
        expiresInSeconds: {
          type: "number",
          description: "Token lifetime in seconds. Default: 3600 (1 hour). Pass a larger value for long-lived tokens (e.g. document signatures: 365 * 24 * 3600).",
        },
      },
      required: ["sub"],
      additionalProperties: {
        description: "Any additional custom fields to embed in the payload. Max 10 extra fields, string values max 256 chars.",
      },
    },
  },

  {
    name: "fipsign_verify",
    description:
      "Verify a FIPSign token signed with ML-DSA-65. Checks the cryptographic signature, expiry, and revocation list. Returns valid:true with the decoded payload on success, or valid:false with an error message on failure. Never throws — always returns a result. Costs 1 token.",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "object",
          description: "The token object returned by fipsign_sign. Must have: payload (string), signature (string), algorithm (string), issuedAt (number).",
          properties: {
            payload:   { type: "string" },
            signature: { type: "string" },
            algorithm: { type: "string" },
            issuedAt:  { type: "number" },
          },
          required: ["payload", "signature", "algorithm", "issuedAt"],
        },
      },
      required: ["token"],
    },
  },

  {
    name: "fipsign_revoke",
    description:
      "Permanently revoke a token. Once revoked, all future verify() calls will reject the token even if its signature is valid and it has not expired. Idempotent: revoking an already-revoked token returns success without consuming an extra token. Costs 1 token. Note: calling this on an already-expired token returns an error (400).",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "object",
          description: "The token object to revoke. Must have: payload, signature, algorithm, issuedAt.",
          properties: {
            payload:   { type: "string" },
            signature: { type: "string" },
            algorithm: { type: "string" },
            issuedAt:  { type: "number" },
          },
          required: ["payload", "signature", "algorithm", "issuedAt"],
        },
        reason: {
          type: "string",
          description: "Optional human-readable reason stored server-side. Examples: 'user logged out', 'order cancelled', 'suspicious activity detected'.",
        },
      },
      required: ["token"],
    },
  },

  // ── Account ──────────────────────────────────────────────────────────────────

  {
    name: "fipsign_usage",
    description:
      "Get the current token balance and 6-month usage history for this API key's account. Returns free tokens remaining (resets monthly), pack tokens remaining (never expire), total remaining, and a monthly breakdown. Free — no token cost. Use before batch operations to confirm sufficient balance.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  // ── Key generation ───────────────────────────────────────────────────────────

  {
    name: "fipsign_generate_key_pair",
    description:
      "Generate an ML-DSA-65 key pair locally (no API call, no token cost). Returns a base64-encoded public key (1952 bytes) and secret key (4032 bytes). Use the publicKey when calling fipsign_ca_issue to certify a device or entity. SECURITY WARNING: the secretKey is sensitive — store it securely on the device and never send it to any server. The secretKey will appear in this tool's response; treat it like a private key.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },

  // ── Certificate Authority ─────────────────────────────────────────────────────

  {
    name: "fipsign_ca_issue",
    description:
      "Issue a post-quantum certificate signed by the project's CA. The certificate certifies that the entity identified by 'subject' controls the given ML-DSA-65 public key. Supports both PQCert (native JSON) and X.509 (standard PEM) CA formats — the format is determined by which CA type was created in the dashboard. For PQCert CAs, the response includes a certificate JSON object. For X.509 CAs, it includes a PEM string. Costs 1 token.\n\nRequired: subject (entity name/ID), publicKey (base64 ML-DSA-65 public key — generate with fipsign_generate_key_pair), expiresInSeconds (min 60, max 157680000 = 5 years).\n\nOptional: meta (up to 10 key-value pairs — PQCert CAs only; passing meta to an X.509 CA returns a 400 error).\n\nThe returned certId (in meta.certId) is what you need for fipsign_ca_revoke_cert and fipsign_ca_get_cert.",
    inputSchema: {
      type: "object",
      properties: {
        subject: {
          type: "string",
          description: "Entity identifier to certify. Examples: 'device-serial-00123', 'service-payment-processor', 'lock-v3-batch-2026'. Max 256 characters.",
        },
        publicKey: {
          type: "string",
          description: "Base64-encoded ML-DSA-65 public key of the entity to certify (1952 bytes decoded). Generate with fipsign_generate_key_pair.",
        },
        expiresInSeconds: {
          type: "number",
          description: "Certificate lifetime in seconds. Min: 60 (1 minute). Max: 157680000 (5 years). Example: 31536000 = 1 year.",
        },
        meta: {
          type: "object",
          description: "Optional custom key-value pairs to embed in the certificate (PQCert CAs only — returns 400 for X.509 CAs). Max 10 keys. Example: {\"model\": \"lock-v3\", \"batch\": \"2026-05\"}.",
          additionalProperties: true,
        },
      },
      required: ["subject", "publicKey", "expiresInSeconds"],
    },
  },

  {
    name: "fipsign_ca_revoke_cert",
    description:
      "Revoke a certificate immediately. From this point on, the certificate will appear in the CRL returned by fipsign_ca_get_crl. Use fipsign_ca_get_cert to check real-time revocation status of a single certificate. Costs 1 token. Returns 409 if the certificate is already revoked.",
    inputSchema: {
      type: "object",
      properties: {
        certId: {
          type: "string",
          description: "The certificate ID to revoke (cert_...). For PQCert: the 'id' field of the certificate object. For X.509: the 'certId' field from meta returned by fipsign_ca_issue.",
        },
        reason: {
          type: "string",
          description: "Optional reason for revocation. Max 256 characters. Examples: 'device decommissioned', 'device reported stolen', 'key compromise'.",
        },
      },
      required: ["certId"],
    },
  },

  {
    name: "fipsign_ca_get_cert",
    description:
      "Get a certificate by ID and its current real-time status (revoked, expired, revokedAt, expiresAt). Use this for single certificate checks before authorizing high-value operations. For bulk offline revocation checks across many certificates, use fipsign_ca_get_crl instead. Free — no token cost.",
    inputSchema: {
      type: "object",
      properties: {
        certId: {
          type: "string",
          description: "The certificate ID (cert_...). For PQCert: certificate.id. For X.509: meta.certId from fipsign_ca_issue.",
        },
      },
      required: ["certId"],
    },
  },

  {
    name: "fipsign_ca_get_crl",
    description:
      "Get the Certificate Revocation List (CRL) for this project's CA. Returns all revoked certificate IDs with their revocation timestamps and reasons. Use this to check revocation status of multiple certificates offline — download once, check locally. For a single certificate's real-time status use fipsign_ca_get_cert instead. Free — no token cost. For X.509 CAs the CRL is signed with ML-DSA-65 and includes the full signed object in the 'raw' field.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// ─── Tool handlers ────────────────────────────────────────────────────────────

async function handleTool(name: string, args: Record<string, unknown>) {
  // Tools that don't require API key
  if (name === "fipsign_health") {
    const { data } = await apiRequest("GET", "/health");
    return ok(data);
  }

  if (name === "fipsign_public_key") {
    const { data } = await apiRequest("GET", "/public-key");
    return ok(data);
  }

  if (name === "fipsign_generate_key_pair") {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const keys = ml_dsa65.keygen(seed);
    seed.fill(0);
    return ok({
      publicKey: toBase64(keys.publicKey),
      secretKey: toBase64(keys.secretKey),
      algorithm: "ML-DSA-65",
      standard: "NIST FIPS 204",
      sizes: {
        publicKeyBytes: keys.publicKey.length,
        secretKeyBytes: keys.secretKey.length,
      },
      note: "Store secretKey securely on the device. Never send it to any server. Pass publicKey to fipsign_ca_issue.",
    });
  }

  // All remaining tools require API key
  if (!API_KEY) return missingApiKey();

  switch (name) {
    // ── Core signing ──────────────────────────────────────────────────────────

    case "fipsign_sign": {
      const { sub, expiresInSeconds, ...rest } = args;
      if (!sub || typeof sub !== "string") {
        return err('"sub" is required and must be a string');
      }
      const body: Record<string, unknown> = { sub, ...rest };
      if (expiresInSeconds !== undefined) body.expiresInSeconds = expiresInSeconds;
      const { ok: success, data } = await apiRequest("POST", "/sign", body);
      if (!success) return err("Sign failed", data);
      return ok(data);
    }

    case "fipsign_verify": {
      const { token } = args;
      if (!token || typeof token !== "object") {
        return err('"token" is required and must be the token object returned by fipsign_sign');
      }
      const { ok: success, data } = await apiRequest("POST", "/verify", { token });
      return ok(data);
    }

    case "fipsign_revoke": {
      const { token, reason } = args;
      if (!token || typeof token !== "object") {
        return err('"token" is required and must be the token object returned by fipsign_sign');
      }
      const body: Record<string, unknown> = { token };
      if (reason !== undefined) body.reason = reason;
      const { ok: success, data } = await apiRequest("POST", "/revoke", body);
      if (!success) return err("Revoke failed", data);
      return ok(data);
    }

    // ── Account ───────────────────────────────────────────────────────────────

    case "fipsign_usage": {
      const { ok: success, data } = await apiRequest("GET", "/usage");
      if (!success) return err("Usage request failed", data);
      return ok(data);
    }

    // ── Certificate Authority ─────────────────────────────────────────────────

    case "fipsign_ca_issue": {
      const { subject, publicKey, expiresInSeconds, meta } = args;
      if (!subject || typeof subject !== "string") {
        return err('"subject" is required');
      }
      if (!publicKey || typeof publicKey !== "string") {
        return err('"publicKey" is required — generate one with fipsign_generate_key_pair');
      }
      if (typeof expiresInSeconds !== "number") {
        return err('"expiresInSeconds" is required and must be a number (min 60, max 157680000)');
      }
      const body: Record<string, unknown> = { subject, publicKey, expiresInSeconds };
      if (meta !== undefined) body.meta = meta;
      const { ok: success, data } = await apiRequest("POST", "/ca/issue", body);
      if (!success) return err("CA issue failed", data);
      return ok(data);
    }

    case "fipsign_ca_revoke_cert": {
      const { certId, reason } = args;
      if (!certId || typeof certId !== "string") {
        return err('"certId" is required');
      }
      const body: Record<string, unknown> = { certId };
      if (reason !== undefined) body.reason = reason;
      const { ok: success, data } = await apiRequest("POST", "/ca/revoke", body);
      if (!success) return err("CA revoke failed", data);
      return ok(data);
    }

    case "fipsign_ca_get_cert": {
      const { certId } = args;
      if (!certId || typeof certId !== "string") {
        return err('"certId" is required');
      }
      const { ok: success, data } = await apiRequest("GET", `/ca/certificate/${encodeURIComponent(certId)}`);
      if (!success) return err("CA get cert failed", data);
      return ok(data);
    }

    case "fipsign_ca_get_crl": {
      const { ok: success, data } = await apiRequest("GET", "/ca/crl");
      if (!success) return err("CA get CRL failed", data);
      return ok(data);
    }

    default:
      return err(`Unknown tool: ${name}`);
  }
}

// ─── Server setup ─────────────────────────────────────────────────────────────

const server = new Server(
  {
    name: "fipsign-mcp",
    version: process.env.npm_package_version ?? "0.1.2",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    return await handleTool(name, args as Record<string, unknown>);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Unexpected error in tool '${name}': ${message}`);
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
