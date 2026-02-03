# CHANGE_LOG

> This project’s changes are tracked here as a chronological, append-only log.
> Format: ISO-8601 timestamp (local), short hash, subject.
>
> Source: `git log --date=iso-strict --pretty=format:'%H\t%ad\t%s'`

## 2026-02-03

- 2026-02-03T17:06:29-06:00 261103c install/docs: add docker-default installer entrypoint; add --sentry-mode; require explicit models for live; add json logs TODO
- 2026-02-03T16:51:15-06:00 4aed046 docs: update installation docs for installer flags, model env, privileged ports
- 2026-02-03T16:50:01-06:00 65f8ac1 install: if --port <1024, setcap CAP_NET_BIND_SERVICE on binary
- 2026-02-03T16:48:32-06:00 ddbb712 install: add --port/--user/--group for system install (defaults), set systemd drop-in
- 2026-02-03T16:42:15-06:00 111abde install: add --l1-model/--l2-model; infer provider; write systemd drop-ins
- 2026-02-03T16:39:37-06:00 774d089 install: prompt for secrets on first install (hidden input, 0600)
- 2026-02-03T15:57:22-06:00 0d4b8032eff5 tests: accept bracketed IPv6 host_str behavior
- 2026-02-03T15:56:23-06:00 f474cd5bb681 Merge PR-5: resolve ingest.rs test conflicts
- 2026-02-03T15:41:47-06:00 f4a9ee270068 Merge PR-3C: adversarial markup scan + cap tightening
- 2026-02-03T15:41:34-06:00 005168401ba9 Add adversarial HTML scan and tightening
- 2026-02-03T15:32:01-06:00 cf793377a929 chore: silence unused html_to_text wrapper
- 2026-02-03T15:29:04-06:00 a401aabe9675 chore: remove unused Arc import
- 2026-02-03T15:28:36-06:00 d7e95c13d9d5 tests: update server_config_more_tests for normalize section
- 2026-02-03T15:27:44-06:00 4e1c67154250 tests: update Config initializer for normalize section
- 2026-02-03T15:27:02-06:00 7b6c6596ef8f Merge PR-3A: resolve ingest.rs test conflicts
- 2026-02-03T15:25:12-06:00 a62d2942dbc2 Merge PR-6: sentry JSON parsing tolerant default, strict opt-in
- 2026-02-03T15:24:23-06:00 0065d8cae9a5 Merge PR-2: dedupe ingest (main.rs glue, ingest.rs source of truth)
- 2026-02-03T15:23:33-06:00 ec00647db3ba Merge PR-4: atomic reputation persistence + quarantine
- 2026-02-03T15:22:43-06:00 65fbc6bb41cb Merge PR-1: extractor tempfile protocol
- 2026-02-03T15:22:06-06:00 4aadfcd16ec2 Fix macOS compatibility for extractor tempfiles
- 2026-02-03T15:20:48-06:00 e1e6f5f47d42 Fix reputation store atomic persistence
- 2026-02-03T15:19:47-06:00 90bab3433312 Default Sentry JSON parsing to tolerant
- 2026-02-03T15:19:41-06:00 78c312a084c2 Add URL host parsing docs and tests
- 2026-02-03T14:18:45-06:00 cfc33ad6d811 Implement html5ever HTML normalization
- 2026-02-03T14:13:33-06:00 8c2f19edd888 Add robust URL host parsing for reputation
- 2026-02-03T14:10:53-06:00 ac2dc3c2e3ef Tighten sentry JSON parsing
- 2026-02-03T14:06:09-06:00 78735c7dfdf5 Add normalization windowing caps for markup
- 2026-02-03T13:46:26-06:00 a1e595dfbcf6 Implement atomic reputation store persistence
- 2026-02-03T13:45:18-06:00 c579b471dc17 Use tempfile for extractor output
- 2026-02-03T13:42:48-06:00 e47037c1d7a5 Deduplicate ingest handler
- 2026-02-03T13:02:46-06:00 102dbc52a4d0 docs: add auth matrix, docker live-mode note, extractor overview
- 2026-02-03T12:39:22-06:00 56f595840f3c chore: update Cargo.lock
- 2026-02-03T12:39:10-06:00 a149eb011355 docs: docker compose quickstart, auth headers, troubleshooting, acipctl reference
- 2026-02-03T11:37:41-06:00 6650a19a5047 docs: document secrets sources + precedence (no tribal knowledge)
- 2026-02-03T11:24:38-06:00 725ef88a097d acipctl: persist config set/unset to file; restart by default (docker-compose prints cmd)
- 2026-02-03T11:12:36-06:00 6f1a006b24ae docs: reorder install mode preference by blast radius
- 2026-02-03T11:10:06-06:00 1210ec344723 docs: add install mode decision tree
- 2026-02-03T10:32:48-06:00 65012699812c ACIP sidecar: rename units, add unix socket + acip_user drop-privs, add acipctl
