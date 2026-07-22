# Guardian Gateway Protocol Contract v1

Status: G2 protocol contract implemented by the G3 single-route core; routing and
circuit breaking remain outside this contract.

## 1. Verified Client Envelope

The isolated probe covers `codex-cli 0.144.1` on Windows 11 with Python
`3.12.13`. A G2 report is green only for that exact Codex version; a client
upgrade requires this probe to be rerun and the contract to be reviewed. The
success probe sent exactly one request with this shape:

- `POST /v1/responses`
- `Content-Type: application/json`
- `Authorization: Bearer <local fixture token>`
- `stream: true`
- `model: gpt-guardian-g2-fixture`
- `input` is an array
- body keys observed: `client_metadata`, `include`, `input`, `instructions`,
  `model`, `parallel_tool_calls`, `prompt_cache_key`, `reasoning`, `store`,
  `stream`, `tool_choice`, and `tools`

The probe provider sets both `request_max_retries = 0` and
`stream_max_retries = 0`. Guardian owns the only permitted primary/backup
attempt budget; Codex provider retries must not add hidden attempts.

All request fields are snapshotted and replayed transparently. A Gateway may
replace only the destination, upstream authentication, and hop-by-hop transport
headers. It must not rewrite the model, input, tools, tool choice, reasoning,
or other business fields.

The local provider also exposes `GET /v1/models`. The probe requires HTTP 200,
`application/json`, an OpenAI-compatible list object, and exactly one entry for
the fixture model. Serving the local model catalog must not create an upstream
Responses request.

## 2. Response Completion

### Streaming Responses

Accepted streaming media type: `text/event-stream`, with optional parameters.
The parser operates on incremental UTF-8 bytes and supports LF, CRLF, comments,
unknown extension fields, multi-line `data:`, and arbitrary network chunk
boundaries.

A stream is complete only after all of the following are true:

1. HTTP status is 2xx and the media type is accepted.
2. `response.created` was observed once and the response ID never changed.
3. Every event `data:` value is valid JSON with a string `type`; an optional
   `event:` value must match it.
4. Sequence numbers, when present, increase.
5. Every opened output/content item is closed.
6. Every function call has one unique call ID, a matching
   `response.function_call_arguments.done`, valid complete JSON arguments, and
   a matching completed output item.
7. Exactly one terminal event is observed: `response.completed`,
   `response.failed`, or `response.incomplete`, with the matching response
   status.
8. The terminal SSE event has an explicit blank-line delimiter and the HTTP
   body reaches EOF without another event or damaged tail.

The terminal `response.output` must reconcile with the output item lifecycle
already observed in the stream. A mismatch remains fail-closed. Internal
diagnostics distinguish missing streamed items, terminal-only items, item ID
identity drift, item-type drift, item-status drift, tool-field drift, and
message-text drift.
These diagnostics are fixed codes only: they never include response/item IDs,
text, tool arguments, or raw event bodies.

The standard adapter remains strict. A provider-specific compatibility probe
may opt into accepting an omitted or empty terminal `response.output` only
after every streamed output/content item has already closed and all tool
arguments and completed item fields have passed normal validation. This mode
does not accept terminal-only items, partial item sets, ID drift, state drift,
tool-field drift, or text drift, and it is not a global fallback.

A separate provider-specific probe may allow terminal output items to omit
their redundant `id` field. In that mode, Guardian matches the terminal array
to already validated stream items only by the unique, contiguous
`output_index` lifecycle captured from `response.output_item.added/done`.
Item count, type, status, text, call ID, function name, and arguments must still
match exactly. Mixed present/missing terminal IDs, sparse or duplicate output
indexes, and all other drift remain fail-closed.

A further provider-specific probe may allow the terminal item to omit its
redundant `status` only after the matching streamed item has closed with a
validated final status. An explicitly present but different status remains a
hard failure. This option is independent, default-off, and does not relax item
type, text, tool fields, item count, identity, or lifecycle validation.

A provider-specific probe may also allow
`response.function_call_arguments.done` to omit its redundant `name` only
after the function name was captured from the matching opened output item.
The completed output item and terminal output must still repeat the same
function name, call ID, and arguments. An explicitly present but different
`done.name` remains a hard failure. This option is independent and default-off.

`response.failed` and `response.incomplete` are complete model results, not
transport truncation. A typed `error`, invalid UTF-8/JSON, `[DONE]` without a
Responses terminal, missing/duplicate terminal, open tool arguments, or data
after terminal invalidates the entire attempt.

For an `incomplete` terminal, an output message may itself have status
`incomplete`; the same item is invalid under `response.completed`. Response
IDs are non-empty and identical from `response.created` through the terminal.
`response.function_call_arguments.done.name` must match the opened tool name.

An unknown event with no output/tool lifecycle fields is preserved in its
original position. An unknown event that may open, mutate, or close output or
tool state fails closed until a newer adapter contract recognizes it.

### Non-streaming Responses

Accepted media type: `application/json`, with optional parameters. The body
must be one valid response object with a non-empty ID and terminal status
`completed`, `failed`, or `incomplete`. Function-call items must already be
complete and contain valid JSON object arguments.

## 3. Commit Boundary

Before completion validation and upstream EOF, the downstream receives zero
HTTP response bytes: no status line, headers, SSE comments, keepalive events,
model events, or fake tokens. A failed attempt buffer is destroyed. Exactly one
validated buffer from one upstream source may be committed.

HTTP transport admission is the explicit boundary before a request snapshot or
upstream attempt exists. The server disables aiohttp's automatic
`100 Continue`: any request carrying `Expect` is rejected with one final `417`
response, zero interim responses, zero upstream requests, and zero model events.
Framework-level HTTP parse/admission rejection is therefore not a model commit.
After transport admission succeeds, every `/v1/responses` application success
or structured error uses the request's single `Committer`; no router or handler
may write application response bytes directly. Raw-socket tests lock both the
normal zero-byte wait and the `Expect` rejection behavior.

The raw-socket G2 probe held a partial upstream stream for 15 seconds and
observed zero downstream bytes and zero commit records. After the terminal and
EOF, the complete SSE was replayed and Codex returned a random response nonce
that was absent from the request prompt and body. This
proves compatibility for the tested 15-second no-header window; longer
production limits require the same probe before defaults are raised.

After commit begins, a downstream disconnect is `delivery_uncertain`. It must
never re-enter routing or start another upstream attempt. A pre-commit client
cancel cancels the active attempt, discards the buffer, and does not call the
backup or affect breaker health.

The isolated Codex tool probe returns a completed `shell_command` call with the
read-only fixture command `Write-Output G2_TOOL_EXECUTED`. Codex executes it,
then sends one second Responses request containing exactly one matching
`function_call_output` with the same call ID and execution marker. The relay
commits both complete turns once; the final random response nonce is absent
from both requests. Two upstream requests here are the expected tool
round-trip, not retries.

## 4. State and Replay Safety

Self-contained requests may use the normal bounded failover policy. Requests
with `previous_response_id` or another adapter-declared server-state dependency
may fail over only when capability evidence is exactly `SHARED`.

`SHARED` requires both P1-to-P2 and P2-to-P1 continuation to pass and the
evidence to match the active config revision, both route fingerprints, adapter
contract, and model. One-way success is insufficient because a response
delivered by P2 can later be continued after automatic recovery to P1.

`UNKNOWN`, `INCOMPATIBLE`, stale evidence, or mismatched fingerprints must
return `guardian_state_reference_not_portable` (or the more specific unknown
diagnostic) before any breaker admission or upstream request. The Gateway must
not drop the reference, set it to null, create a replacement conversation, or
persist full chat content to reconstruct it.

The G2 state harness proves both shared and isolated fixture behavior. It does
not prove that the user's real P1/P2 providers share state. Real-route
capability therefore remains `UNKNOWN` until a separately authorized minimal
probe succeeds in both directions.

Requests that may execute non-idempotent server-side tools are not replayable
without a verified idempotency or deduplication contract. Developer function
events are buffered only; Guardian never executes Codex tools.

## 5. Public Errors and Privacy

Gateway errors use a fixed envelope:

```json
{
  "error": {
    "type": "guardian_gateway_error",
    "code": "guardian_all_routes_failed",
    "message": "A fixed localized public message.",
    "request_id": "gw_redacted_id"
  }
}
```

The envelope must not contain Authorization, cookies, upstream error bodies,
request/response content, tool arguments, full URLs with query strings, or
server-state reference values. G2 fixtures use only fake tokens and fictional
content.

The 503 probe checks the public error envelope directly on the wire, then runs
the real isolated Codex CLI against a fresh relay. It requires one relay
record, one primary attempt, one actual upstream POST, a non-zero Codex exit,
and no retry. Retry evidence comes from captured request counts, not repeated
console text.

## 6. Evidence and Sources

Automated entry points:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_gateway_protocol_probe -v
.\.venv\Scripts\python.exe -B tools\gateway_protocol_probe.py --gate-seconds 15 --report _tmp\g2-protocol-report.json
```

The second command uses a temporary repo-local `CODEX_HOME`, `--ephemeral`, a
fake environment key, a loopback mock, and no real model request. The temporary
home is removed after each success, error, and tool probe. Report schema 2
binds evidence to the full Git HEAD, path-scoped `git status --porcelain`, and
SHA-256 of the contract, production validator, mock, tests, and probe script.
The overall report is green only when this G2 source set is clean and the same source binding is
observed again after every probe, so a report cannot claim a baseline commit
tested uncommitted or concurrently changing G2 bytes.

Official references used to lock this contract:

- <https://developers.openai.com/api/docs/guides/streaming-responses>
- <https://developers.openai.com/api/docs/guides/migrate-to-responses#7-update-streaming-consumers>
- <https://developers.openai.com/api/reference/resources/responses/streaming-events>
- <https://learn.chatgpt.com/docs/config-file/config-reference#configtoml>
- <https://developers.openai.com/codex/config-schema.json>
