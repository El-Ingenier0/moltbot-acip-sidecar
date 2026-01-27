# ACIP Sidecar API (draft)

## POST /v1/acip/ingest_source

Purpose: ingest *untrusted* external content and return **fenced** content + tool gating.

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
  "policy": { "head": 4000, "tail": 4000 },

  "tools_allowed": false,
  "risk_level": "low|medium|high",
  "action": "allow|sanitize|block|needs_review",

  "fenced_content": "```external\n...\n```",
  "reasons": ["..."],
  "detected_patterns": ["..."]
}
```

### Notes
- The sidecar must validate model output against a strict JSON schema.
- If L1 fails validation, retry with L2 (Haiku).
