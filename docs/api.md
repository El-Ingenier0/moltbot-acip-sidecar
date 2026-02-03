# ACIP Sidecar API (draft)

## POST /v1/acip/ingest_source

Purpose: ingest *untrusted* external content and return **fenced** content + tool gating.

### Request headers

- `Content-Type: application/json`

Optional auth headers:
- `X-ACIP-Token: <token>`
  - Required when the server is configured to require a token.
  - Token value is read from the environment variable named by `security.token_env` (default: `ACIP_AUTH_TOKEN`).

Optional tool authorization:
- `X-ACIP-Allow-Tools: true`
  - Opt-in only. Even with this header, markup inputs (HTML/SVG) are hard-capped to `tools_allowed=false`.

### Token requirement behavior

Token requirement is controlled by config:

```toml
[security]
require_token = true
allow_insecure_loopback = true   # if true, loopback requests may omit token
token_env = "ACIP_AUTH_TOKEN"
```

#### Auth matrix (normative)

This table is the canonical spec. No tribal knowledge.

- **Loopback request** means the client connects to a loopback address (`127.0.0.1`) or a local unix socket.
- **Non-loopback request** means anything else.

| require_token | allow_insecure_loopback | Loopback request | Non-loopback request |
|---|---|---|---|
| false | (any) | Token not required | Token not required |
| true  | true  | Token optional | Token required |
| true  | false | Token required | Token required |

Notes:
- To force token auth even on loopback, set `allow_insecure_loopback=false` and `require_token=true`.
- `X-ACIP-Token` is matched against the value in environment variable `security.token_env`.

### Request (JSON)
```json
{
  "source_id": "string",
  "source_type": "html|pdf|tweet|file|clipboard|other",
  "content_type": "text/plain|text/html|application/pdf|...",
  "url": "https://... (optional)",
  "title": "optional",
  "turn_id": "optional",

  "text": "...optional...",
  "bytes_b64": "...optional..."
}
```
Exactly one of `text` or `bytes_b64` is required.

### Policy
- If extracted text length <= 9000 chars: include whole.
- Else include head 4000 + tail 4000 chars.
- Optionally include detected instruction-dense sections.

### Response (JSON)
```json
{
  "digest": { "sha256": "...", "length": 12345 },
  "truncated": true,
  "policy": { "head": 4000, "tail": 4000, "full_if_lte": 9000 },

  "original_length_chars": 12345,
  "model_length_chars": 12000,
  "normalized": true,
  "normalization_steps": ["html_to_text", "strip_active_html_blocks"],

  "tools_allowed": false,
  "risk_level": "low|medium|high",
  "action": "allow|sanitize|block|needs_review",

  "fenced_content": "```external\n...\n```",
  "reasons": ["..."],
  "detected_patterns": ["..."]
}
```

### Notes
- `bytes_b64` currently must decode to UTF-8 (PDF extraction/rendering is not implemented yet).
- For HTML/SVG inputs, the sidecar builds a `model_text` (normalized) used for sentry decisions; `raw` is retained for digest/audit.
- **Safety invariant**: for HTML/SVG inputs, `tools_allowed` is hard-capped to `false` regardless of model decision.
- **Tool authorization**: even for non-markup content, `tools_allowed` is hard-capped to `false` unless the caller explicitly sets `X-ACIP-Allow-Tools: true`.
- The sidecar validates model output against a strict JSON schema.
- If L1 fails validation, it retries with L2.
