# EP-3404: Capability Observability

- Issue: [#3404](https://github.com/agentgateway/agentgateway/issues/3404)
- Status: proposed
- Date: 9/10/2026

> **Note:** This design reflects the proposal as of the date above. The current implementation may differ as the design
> is implemented, reviewed, or revised.

## Summary

Agentgateway records that a request happened, not which capability it exercised. The access log emits one record per
HTTP request, but authorization is evaluated per capability, and the two do not line up. A single MCP `tools/list`
evaluates authorization once for every advertised tool, prompt and resource — many decisions, one access log record —
and a tool the caller may not use is filtered out of the listing silently, so the request succeeds and nothing says a
capability was withheld.

This proposal emits one record per authorization decision, describing the capability that was evaluated and how it was
decided, and identifies that capability by a deterministic id derived only from the capability itself.

The id is the substance of the proposal. Everything else follows from it.

## Background

Three mechanisms record authorization today, and none of them answers "which capabilities did this principal exercise,
and which were denied".

The request log is per request. Adding fields to it cannot describe a listing that evaluated two hundred decisions,
because there is only one record to put them on.

`dtrace` (`crates/agentgateway/src/proxy/dtrace.rs`) does carry per-rule detail, including which rules matched. It is an
opt-in local debugging facility attached to a single traced request, not an export path.

Metrics record guardrail verdicts (`agentgateway_guardrail_checks_total`) and request outcomes, but HTTP authorization
decisions, MCP RBAC decisions and LLM guardrail verdicts are shaped differently enough that they cannot be counted
together or joined.

## Goals

- Give every authorization decision a stable capability identity that is comparable across restarts, config reloads and
  gateway replicas.
- Make denials visible, including denials that today manifest only as an absence in a listing.
- Attribute decisions to a principal without carrying credentials.
- Keep metric cardinality bounded, and keep the feature free when it is off.

## Non-Goals

- Changing any authorization outcome. This observes decisions; it does not make them.
- Adding an enforcement surface or a policy type.
- Carrying request or response content on the record.
- Covering network authorization. `network_authorization` in `crates/agentgateway/src/proxy/gateway.rs` rejects a
  connection before any request exists, so there is no action against a resource to describe — only a pair of
  addresses. Forcing it into this model would dilute what a capability means.

## Capability Identity

A capability is an action against a resource:

```text
action           tools/call, get, llm:chat, ...
resource type    mcp.tool, mcp.prompt, mcp.resource, mcp.task, http.path, llm.model
resource target  the MCP server, LLM provider, or, for HTTP, namespace/gateway/listener
resource id      the tool, prompt, resource or model name, or the request path
```

Its identity is the SHA-256 digest, lowercase hex, of a canonical string built from exactly that tuple:

```text
agentgateway-capability:v1|<len>:<action>|<len>:<resource_type>|<len>:<resource_target>|<len>:<resource_id>
```

`action` and `resource_type` are lowercased before hashing, because they are vocabulary rather than data.
`resource_target` and `resource_id` keep the case they were configured with, because an MCP server that advertises
`getUser` and one that advertises `getuser` are advertising different things. An absent target is hashed as an empty
field rather than skipped, so a missing value cannot be confused with a present one.

Each field is prefixed with its byte length, which is what makes the encoding injective. Not every field is chosen by
this gateway — a model name arrives in the request body and a tool name comes from the upstream MCP server — so a
value is free to contain the separator. Without the length prefix, `("a|b", "c")` and `("a", "b|c")` would produce the
same digest, and a caller able to pick a model name could make one capability's usage record under another's identity.

`v1` is a compatibility marker, not decoration. Any change to what goes into the string or how it is normalized changes
every id derived from it, which would silently split one capability's history in two; the marker exists so that such a
change is a visible version bump instead.

The id carries no request state — no timestamp, no principal, no outcome, no route instance. That is what makes it
useful:

- the same capability yields the same id after a restart, after a config reload, and on every replica;
- an allow and a deny of the same capability carry the same id, so denials are comparable with grants rather than
  living in a separate universe;
- the set of capabilities a gateway advertises and the set it has actually served become two sets that can be
  subtracted, which is how questions like "what has never been called" and "what stopped being reachable last Tuesday"
  get answered.

A consumer that would rather group by the raw tuple can do so; the tuple is on the record too. The id is what makes
grouping cheap and consistent between consumers that would otherwise each invent their own key.

Because the id is a pure function of the tuple, what goes in the tuple has to be stable for the same reasons the id is.
For HTTP that ruled out the route: gateway-scope authorization runs before route selection, so keying on the route gave
one request two different ids depending on which authorization point decided it, and renaming or splitting a route in
config would have changed the id of every capability under it while the capability itself was unchanged. The listener
is known at every authorization point and is the addressable surface the caller actually reached, so an HTTP capability
is a method and a path on a listener. Which route served it is a handling detail, and it is already a label on the
gateway's existing HTTP metrics.

The listener is named in full, as `<namespace>/<gateway>/<listener>`. A listener name is local to its gateway, and an
unnamed listener defaults to `listener<index>`, so the bare name would merge the capabilities of two gateways that both
happen to have a `listener0`.

## Runtime Design

An observation is emitted at each authorization decision point, if and only if the feature is enabled:

- HTTP authorization, on both the request-policy and backend-policy paths
  (`crates/agentgateway/src/http/authorization.rs`);
- MCP RBAC, through `McpAuthorizationSet::validate_observed` (`crates/agentgateway/src/mcp/rbac.rs`), reached from the
  listing filters in `mcp/handler.rs` and the call paths in `mcp/session.rs`;
- LLM guardrails (`crates/agentgateway/src/llm/policy/`), for request guards, buffered response guards, streamed
  response guards and the realtime websocket proxy;
- model authorization (`model_authorized` in `crates/agentgateway/src/llm/model_router.rs`), which decides whether a
  caller may use a model at all. It runs inside the router, which has no request log in scope, so the observer reaches
  it through the request extensions, the same way the MCP router hands one to RBAC;
- API-key model access (`api_key_model_authorized`, in the same file), which is the second and independent way a model
  is withheld: the caller's key carries its own list of permitted models, so a model the route's policy allows can
  still be refused here. No CEL rules back that decision, so the record names the API key as its basis and carries no
  policy refs. A request with no such policy took no decision at all and is not observed.

The last three share a shape worth naming: a denied model, like a denied MCP tool, is filtered out of a listing rather
than reported, so the request succeeds and the denial exists nowhere but in the observation.

Model decisions carry a decision point that says which of the two they are. Building a listing observes each configured
model once, against the route policy, and each virtual model once, against the API key policy; those name `model
listing` and `api key model listing`. Authorizing an actual request names `model authorization` and `api key model
authorization`. A dashboard counting model usage wants the latter two; the former two are an inventory of what the
caller could see.

Two model filters remain unobserved. A key's patterns also narrow which configured models are *discoverable* in a
listing, expanding or intersecting names rather than deciding a single yes or no, so there is no one decision to
record. And a request that matches several routes evaluates them in order until one authorizes it, so a denial on an
earlier candidate can precede an allow on a later one within the same request, under the same capability id and
decision point. Both are per-decision truths rather than per-request ones: a consumer asking whether a request was
ultimately refused should correlate on the trace, not on a single record.

The two also describe different things, which is why they observe different resource ids. A route name may be a pattern
such as `provider/*`, so authorizing a request observes the concrete model the caller named rather than the pattern
that matched it -- otherwise a glob would enter the capability catalog, and the route policy and the API key policy
would describe the same request under two identities. A listing has no requested model and observes the configured name
as it stands.

A decision that was never taken is never observed: a route with no authorization policy, or a request whose API key
carries no model access policy, returns early and emits nothing rather than reporting an allow.

One deviation from the original proposal is deliberate here. It asks for the resource actually sent upstream rather
than the name the client used, and a request observation carries the requested model, since alias and provider
resolution happen further down the pipeline than the authorization decision being described. Observing the requested
name is still an improvement on observing the route pattern that matched it, which is what a glob-named route would
otherwise have contributed to the catalog.

One HTTP request passes several of these points -- gateway, route and backend authorization are separate applications
of the same policy type -- so it can produce several records. They would otherwise be identical, since they describe the
same action on the same route, so each record names the point that produced it in `capability.decision.point`. The
counter carries it as a label too, which means a count is per decision, not per request.

Emission is strictly non-blocking and cannot change a decision: the record is handed to the OTLP batch exporter, which
drops rather than blocks when its queue is full, and every step of building it is infallible.

### Two Tiers

The fields that are useful and the fields that are safe as metric labels are not the same set, so there are two
outputs.

The counter `agentgateway_capability_observations_total` carries only `outcome`, `decision_point`, `action`,
`resource_type` and `resource_target`. Each is drawn from a bounded set: a vocabulary, an HTTP method, an MCP method
name, or a configured listener, server or provider name. The request-derived values — resource id, principal,
observation id, capability id — are deliberately excluded, since any one of them would make cardinality a function of
traffic.

The log record carries everything, including those excluded fields, and is emitted through the OTLP access-log path.

Because the OTLP access logger is a per-listener policy rather than part of this feature's config, the two tiers are
gated separately: the counter is recorded whenever the feature is on, and the record is built only when a sink exists.
Enabling the flag on a deployment with no OTLP access log therefore still yields rates and alerting, rather than
silently yielding nothing.

### Record Attributes

Emitted with log level `info` and target `capability`.

| Attribute | Always present | Value |
| --- | --- | --- |
| `event.name` | yes | Constant `agentgateway.capability.observation` |
| `capability.observation.id` | yes | UUIDv7, unique to this observation |
| `capability.action` | yes | Lowercased HTTP method, MCP method name, or an `llm:*` verb |
| `capability.resource.type` | yes | `http.path`, `mcp.tool`, `mcp.prompt`, `mcp.resource`, `mcp.task`, `llm.model` |
| `capability.resource.target` | yes | `<namespace>/<gateway>/<listener>` for HTTP, MCP server name, or LLM provider |
| `capability.resource.id` | yes | Request path, tool/prompt/resource/task name, or model name |
| `capability.id` | yes | The capability identity described above |
| `capability.decision.point` | yes | Which application point decided: `gateway authorization`, `authorization`, `backend authorization`, `model authorization`, `model listing`, `api key model authorization`, `api key model listing`, `mcp authorization`, `llm guardrail` |
| `capability.observation.outcome` | yes | `allow` or `deny` |
| `capability.observation.authorization_basis` | yes | `cel_policy`, `default`, `guardrail`, or `api_key` |
| `capability.policy.refs` | yes | JSON array of `{name, effect, matched}`, serialized into a string |
| `capability.principal.type` | no | `jwt` or `api_key` |
| `capability.principal.id` | no | JWT `sub` claim, or the API key's configured name |
| `trace.id`, `span.id` | no | Present when a span is active |

The `llm:*` vocabulary is derived from the typed request format, not from the request path: `llm:embed`, `llm:rerank`,
`llm:realtime`, `llm:count_tokens`, `llm:decisions` (Decisions and SystemOne), and `llm:chat` for every chat-shaped
format. A passthrough request uses the operation the router detected from its path (`llm:image`, `llm:ocr`,
`llm:transcribe`, `llm:speech`, `llm:compact`, or one of the above), and `llm:unknown` when it detected none. Model
authorization uses
`llm:select_model`, since it decides eligibility to use a model rather than describing a turn against it, and it runs
before a provider is chosen -- which is why its resource carries the model name with no target. The mapping is
exhaustive over `InputFormat`, so a new request format is a compile error rather than a request silently reported as
chat.

`authorization_basis` records what produced the decision: a CEL policy set evaluated it, no policies were configured so
the default applied, an LLM guardrail produced it, or the model access policy on the caller's API key did. Only the
first two come from the CEL policy engine, which is why the engine's own narrower basis enum converts into this one
rather than being it.

Multi-word values are spelled `snake_case`, following the OpenTelemetry convention this repository already applies to
OTel attribute values such as `gen_ai.token.type`, rather than the `camelCase` used for CEL-visible fields like the
guardrail log's `failOpen`.

### Principal

The principal is the JWT `sub` claim, or, failing that, the configured name of the API key from its metadata. A
credential is never carried. The API key's own value is not part of the metadata that is read.

HTTP and MCP decisions read it from the live request extensions. LLM guardrail decisions read it from the request
snapshot instead, because the guard pipeline no longer holds the request — and that snapshot is only taken when some
CEL expression asked for one, so an LLM observation on a gateway with no such expression carries no principal at all.
The provider and model had the same problem and are now read from the typed request; the principal is left as a
follow-up because the response-side guards have no request in scope, and `RequestLog` carries only `jwt_sub`, which
would attribute JWT callers while silently leaving API-key callers unattributed. Splitting the two is worse than the
present gap, which at least is uniform.

### Three Deliberate Inconsistencies

Each of the following looks like a defect to a reader who does not know why it is there.

**Outcome case differs between the two tiers.** The metric label reads `Allow` and `Deny`; the log record reads `allow`
and `deny`. This follows what the repository already does with `GuardrailAction`, whose metric label is the Rust
variant name — `Reject` — while the same verdict is hand-mapped to `reject` for the guardrail log. Metric labels come
from the `EncodeLabelValue` derive, which spells the variant as written and which no label enum here overrides; log and
CEL-visible fields are written lowercase to match the rest of that surface. Spelling both tiers identically would break
one of those two conventions, so the split is kept and consumers joining a metric series to a log record normalize
case. Absence is spelled differently for the same reason: a metric label with no value reads `unknown`, following the
repository-wide `DefaultedUnknown` convention, while the record carries an empty attribute.

**`capability.policy.refs` carries policy source text.** Each entry names the rule that contributed to the decision,
and that name is the rule's original CEL expression. It is the field that answers "why was this denied", and it is also
the field that moves operator-authored configuration into a log backend. Deployments where the policy expressions are
themselves sensitive should weigh that before enabling the feature. Whether the field should be a native OTel array
attribute rather than a JSON string embedded in one is an open question below.

**A streamed response yields one observation, not one per window.** Streaming guardrails evaluate a response window by
window, but all windows of one response exercise the same capability; only the verdict differs. The observation is
therefore folded to one per guard per response, carrying the strongest verdict any window produced, since
`GuardrailAction` is ordered by severity. The boundary is explicit — `StreamingEvaluator::finish_response`, called at
SSE end of body, on a guardrail block, and on `response.done` in the realtime websocket proxy — with `Drop` as an
idempotent backstop for streams that end without one, such as a client disconnect. A boundary with no evaluated window
emits nothing.

This is where the granularity of the two telemetries deliberately diverges. `agentgateway_guardrail_checks_total` keeps
its pre-existing per-evaluator-lifetime semantics, which on a realtime websocket means one trip per connection; the
capability observation is per response, because a realtime connection carries many responses through one evaluator.
Realtime *request* guards observe per message, since each message is its own prompt.

## API

One new field, off by default:

```yaml
config:
  logging:
    capabilityObservations: true
```

Off by default because the volume follows the number of decisions, not the number of requests, and MCP listings
evaluate every advertised tool, prompt and resource individually.

The flag gates cost, not just output. Building `capability.policy.refs` requires re-evaluating every allow, deny and
require rule without short-circuiting, which is strictly more work than deciding the request. That second pass runs
only when an observer exists and has a sink to emit to, so a deployment with the flag off — including one already
running OTLP access logs — pays nothing.

## Controller and xDS

None. The flag is static gateway configuration parsed from the config file; there is no new resource, no proto change,
and no controller translation.

## Policy Attachment

None. Observations are emitted from the existing authorization and guardrail evaluation paths and do not attach to
anything themselves.

## Compatibility and Migration

The feature is off by default and adds no field to existing records, so no existing user is affected and nothing needs
migrating. Turning it on adds one metric family and, where an OTLP access log backend is configured, one log record per
authorization decision.

## Risks and Tradeoffs

The volume is the main risk, and it is why the flag exists. An MCP listing produces one observation per advertised
capability, so a server advertising several hundred tools produces several hundred records for one request. Overhead is
unmeasured.

Extension HTTP methods widen the `action` label beyond the standard set. That is the same exposure the gateway's
existing HTTP metrics already have.

Two alternatives were considered and rejected. Adding fields to the access log cannot represent a request that made
many decisions. Exporting `dtrace` output would carry far more than the capability and is shaped for one traced request
rather than for aggregate consumption.

## Test Plan

Unit tests in `crates/agentgateway/src/telemetry/capability.rs` cover the identity: determinism, that the action and
resource type are case-normalized while target and id are not, that an absent target stays unambiguous, that a value
carrying the field separator cannot shift a field boundary, and that
observation ids are unique. They also cover principal extraction from both credential types, the bounded label set — a
scrape asserting the resource id, principal and capability id never appear as labels — and that the counter is recorded
with no OTLP sink present.

Tests in `crates/agentgateway/src/http/authorization.rs` assert that the diagnostic rule pass is skipped when nothing
consumes it and populated when it is requested, which is the contract that keeps the feature free when it is off.

Tests in `crates/agentgateway/src/mcp/rbac.rs` assert that observing changes neither an allow nor a deny outcome, and
that the counter carries the bounded labels only.

Tests in `crates/agentgateway/src/llm/policy/tests.rs` assert the streaming fold: one observation per stream through
the `Drop` backstop, one per response across an explicit boundary, nothing for a boundary with no evaluated window, and
no double count when both fire.

End-to-end tests in `crates/agentgateway/tests/tests/policy.rs` run a denied request through a proxy and assert the
counter appears with the flag on and no series exists with it off.

## Open Questions

- Should `capability.policy.refs` be a native OTel array attribute rather than a JSON string in one attribute, and
  should carrying CEL source text be separately opt-in?
- Is model-level authorization worth wiring up in this proposal rather than deferring it?
- Should the capability id be emitted at all, or should consumers group by the raw tuple and derive their own key?
