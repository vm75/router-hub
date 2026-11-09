# Security Analytics

Security Analytics is an optional, router-side view of whether Router Hub's Ban Shield controls are detecting and enforcing protection over time. It is **disabled by default**, and the optional external AI review is a second, independent opt-in.

## Data flow

The normal analytics path reuses Ban Shield state and events instead of rereading attack logs or rerunning rule regexes:

1. Ban Shield emits small match/ban/promotion/unban events into a bounded queue.
2. The analytics consumer aggregates counters and a bounded set of sanitized samples in memory.
3. Every status-sampling interval, analytics reads the existing firewall-engine snapshot to calculate rule, health, timeout, dropped-line and eviction deltas.
4. At a low frequency, analytics reads Router Hub-owned iptables/ip6tables chain counters and ipset membership to verify enforcement and measure packets/bytes dropped before nginx or a forwarded backend sees them.
5. Hourly compact rollups are written atomically and daily summaries are rebuilt from retained hourly data.

The Security Analytics tab shows the last-24-hour protection summary, local findings, engine/enforcement health, bounded overhead counters, rule activity, and retained hourly/daily history.

## Performance gates

Defaults are deliberately conservative for an Asuswrt-Merlin router:

- analytics disabled until explicitly enabled;
- 128-entry non-blocking engine-event queue (`try_send`), with drops counted rather than blocking Ban Shield;
- 5-minute engine-state sampling;
- 2-hour kernel verification interval;
- one hourly persisted rollup;
- 14 days of hourly history and 90 days of daily history;
- 32 sanitized event samples per hour;
- 64 KiB maximum serialized rollup;
- 768 KiB serialized history memory budget;
- 30 saved AI review records maximum.

With both INPUT and FORWARD protection enabled, a normal kernel verification uses four owned-chain reads plus two ipset reads. At the default two-hour interval this averages **3 external process launches per hour**, below the feature target of four per hour. Normal persistence is one history write per hour; settings and manual/AI actions can add user-initiated writes.

When analytics is disabled, the periodic task waits for a settings notification and the Ban Shield hot path performs only an atomic enabled check before returning.

The UI exposes cumulative analytics processing time, estimated memory use, disk bytes written, external command launches, event/sample drops, and AI request/byte counters so router overhead can be inspected directly.

## Local findings

Local deterministic checks do not require AI. They can flag, among other conditions:

- Ban Shield entering a degraded or stopped state;
- active-ban state diverging from the engine's enforcement-set count;
- kernel ipset membership diverging from active bans plus allowlist exceptions;
- missing/unreadable Router Hub-owned DROP chains during kernel verification;
- increasing firewall command timeouts;
- dropped log input;
- ban-set capacity approaching its configured limit;
- high-volume rules that produce no ban transitions;
- one rule dominating recent ban transitions.

Kernel packet/byte counters are treated as cumulative counters. Counter resets or chain recreation produce a zero delta rather than a false spike.

## Strict privacy mode

External AI review supports only `strict` privacy mode. The outbound data model contains aggregate counters, sanitized rule names, local findings and a bounded number of sanitized samples. Router Hub does not intentionally include raw log lines or real source IP addresses.

Before a sample can be included:

- source IPs are replaced with stable, keyed local pseudonyms (`SRC_*` or `LAN_*`);
- query strings and fragments are removed;
- numeric IDs, UUIDs, IP-address path segments, email-like path segments and token-like long identifiers are replaced;
- method/status values are allowlisted/validated;
- unsafe rule names are replaced with keyed pseudonyms.

Before any external request leaves the router, Router Hub serializes the **exact OpenAI-compatible JSON request body**, applies the configured payload-size limit (with a 64 KiB hard ceiling), and secret-scans that final byte sequence. The request is rejected locally if it contains common credential/header patterns or a configured Router Hub/AI secret supplied to the scanner.

Use **Preview AI payload** in the UI to inspect that exact JSON request body before enabling or manually invoking AI analysis. The preview does not include the HTTP `Authorization` bearer header or the stored API key.

## External AI integration

AI review is provider-neutral. Configure the exact OpenAI-compatible chat-completions endpoint and model in the UI. This also supports OpenRouter through its normal OpenAI-compatible endpoint; Router Hub contains no OpenRouter-specific code path.

Transport safeguards include:

- HTTPS required for non-private endpoints;
- redirects disabled;
- bounded request timeout;
- bounded streamed response body;
- bounded model output shape/counts/text sizes;
- sensitive custom transport headers (`Authorization`, cookies, token/key/secret-style headers, `Host`, etc.) rejected.

The API key is write-only: configuration responses report only whether a key is configured. It is not returned to the UI after saving and is not included in normal analytics logs.

AI findings and policy suggestions are **advisory only**. The AI path has no operation that applies firewall-policy changes, modifies bans, or changes nginx/router configuration automatically.

## Persistent files

Under the configured Router Hub `data_dir`:

- `analytics-settings.json` — analytics and AI settings, private file permissions;
- `analytics-history.json` — bounded hourly/daily rollups and saved AI review results;
- `analytics-pseudonym.key` — private local key used for stable source/rule pseudonyms.

Writes use a private temporary file, `fsync`, atomic rename, and parent-directory sync. Retention and a serialized history budget keep storage bounded.

## Authenticated API

All analytics endpoints are under the existing authenticated `/api` router:

- `GET /api/analytics/status`
- `GET /api/analytics/history`
- `GET /api/analytics/config`
- `PUT /api/analytics/config`
- `GET /api/analytics/ai/preview`
- `POST /api/analytics/ai/analyze`

No analytics endpoint is added to the unauthenticated health/version surface.
