//! Capability observability: emit OpenTelemetry log records describing the
//! capability (action + resource) evaluated at authorization decision points.
//!
//! Emission is strictly non-blocking and must never change an authorization
//! outcome: records are handed to the OTLP batch exporter, which drops them
//! rather than blocking when its queue is full.

use std::cell::OnceCell;
use std::sync::Arc;

use agent_core::metrics::DefaultedUnknown;
use agent_core::strng::{RichStrng, Strng};
use agent_core::telemetry::{ValueBag, display};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use serde::Serialize;

use crate::proxy::dtrace::{AuthorizationRuleMode, AuthorizationRuleResult};
use crate::telemetry::log::{OtelAccessLogger, RequestLog};
use crate::telemetry::metrics::Metrics;

/// The OTel event name emitted for every capability observation.
pub const EVENT_NAME: &str = "agentgateway.capability.observation";
/// The OTel log target used for capability observations.
pub const LOG_TARGET: &str = "capability";

/// The resource a capability acts upon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
	pub resource_type: Strng,
	pub resource_target: Strng,
	pub resource_id: Strng,
}

impl Resource {
	pub fn new(
		resource_type: impl Into<Strng>,
		resource_target: impl Into<Strng>,
		resource_id: impl Into<Strng>,
	) -> Self {
		Self {
			resource_type: resource_type.into(),
			resource_target: resource_target.into(),
			resource_id: resource_id.into(),
		}
	}
}

/// Deterministic, case-normalized capability identifier: the lowercase SHA-256
/// hex digest of `agentgateway-capability:v1` followed by the four fields, each
/// written as `|<byte length>:<value>`.
///
/// `action` and `resource_type` are lowercased; `resource_target` and
/// `resource_id` preserve their case.
///
/// The length prefixes are what make the encoding injective. Two of the fields
/// carry values this gateway does not choose — a model name comes from the
/// request body, an MCP tool name from the upstream server — so a value
/// containing the separator must not be able to shift a field boundary and make
/// `("a|b", "c")` hash the same as `("a", "b|c")`.
pub fn capability_id(action: &str, resource: &Resource) -> Strng {
	use std::fmt::Write;

	let mut canonical = String::from("agentgateway-capability:v1");
	let mut field = |value: &str| {
		// Infallible: writing to a String never fails.
		let _ = write!(canonical, "|{}:{}", value.len(), value);
	};
	field(&action.to_lowercase());
	field(&resource.resource_type.to_lowercase());
	field(&resource.resource_target);
	field(&resource.resource_id);

	let digest = crate::crypto::digest::sha256(canonical.as_bytes());
	Strng::from(hex::encode(digest))
}

/// The outcome of a capability evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default, Serialize, EncodeLabelValue)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
	#[default]
	Allow,
	Deny,
}

impl std::fmt::Display for Outcome {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Outcome::Allow => f.write_str("allow"),
			Outcome::Deny => f.write_str("deny"),
		}
	}
}

/// Why an authorization decision was made.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationBasis {
	/// A CEL policy set produced the decision.
	CelPolicy,
	/// No policies were configured, so the default outcome applied.
	Default,
	/// An LLM guardrail produced the decision.
	Guardrail,
	/// The model access policy attached to the caller's API key produced the decision.
	ApiKey,
}

impl std::fmt::Display for AuthorizationBasis {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AuthorizationBasis::CelPolicy => f.write_str("cel_policy"),
			AuthorizationBasis::Default => f.write_str("default"),
			AuthorizationBasis::Guardrail => f.write_str("guardrail"),
			AuthorizationBasis::ApiKey => f.write_str("api_key"),
		}
	}
}

impl From<crate::http::authorization::DecisionBasis> for AuthorizationBasis {
	fn from(basis: crate::http::authorization::DecisionBasis) -> Self {
		match basis {
			crate::http::authorization::DecisionBasis::CelPolicy => AuthorizationBasis::CelPolicy,
			crate::http::authorization::DecisionBasis::Default => AuthorizationBasis::Default,
		}
	}
}

/// A single policy that contributed to the decision.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyRef {
	pub name: Strng,
	pub effect: AuthorizationRuleMode,
	pub matched: bool,
}

impl PolicyRef {
	pub fn new(name: impl Into<Strng>, effect: AuthorizationRuleMode, matched: bool) -> Self {
		Self {
			name: name.into(),
			effect,
			matched,
		}
	}
}

impl From<&AuthorizationRuleResult> for PolicyRef {
	fn from(rule: &AuthorizationRuleResult) -> Self {
		PolicyRef::new(rule.name.as_str(), rule.mode.clone(), rule.matched)
	}
}

/// The principal on whose behalf the capability was evaluated.
///
/// `type_` is `"jwt"` (JWT `sub` claim) or `"api_key"` (API-key name). Never
/// carry raw credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
	pub type_: Strng,
	pub id: Strng,
}

impl Principal {
	pub fn new(type_: impl Into<Strng>, id: impl Into<Strng>) -> Self {
		Self {
			type_: type_.into(),
			id: id.into(),
		}
	}
}

/// A complete capability observation.
///
/// `capability_id` and `observation_id` are only carried on the log record, so
/// they are computed on first use: an observation that only feeds the bounded
/// counter never hashes or allocates for them. This matters for MCP listings,
/// which produce one observation per advertised tool, prompt, and resource.
#[derive(Clone, Debug)]
pub struct CapabilityObservation {
	pub action: Strng,
	pub resource: Resource,
	/// Which application point produced this decision. One HTTP request passes
	/// several authorization points, and without this their records are identical.
	pub decision_point: Strng,
	pub outcome: Outcome,
	pub basis: AuthorizationBasis,
	pub policy_refs: Vec<PolicyRef>,
	pub principal: Option<Principal>,
	capability_id: OnceCell<Strng>,
	observation_id: OnceCell<Strng>,
}

impl CapabilityObservation {
	pub fn new(
		action: impl Into<Strng>,
		resource: Resource,
		outcome: Outcome,
		basis: AuthorizationBasis,
		decision_point: impl Into<Strng>,
	) -> Self {
		Self {
			action: action.into(),
			resource,
			decision_point: decision_point.into(),
			outcome,
			basis,
			policy_refs: Vec::new(),
			principal: None,
			capability_id: OnceCell::new(),
			observation_id: OnceCell::new(),
		}
	}

	/// The deterministic capability identifier, computed on first use.
	pub fn capability_id(&self) -> &Strng {
		self
			.capability_id
			.get_or_init(|| capability_id(&self.action, &self.resource))
	}

	/// The unique identifier of this observation, generated on first use.
	pub fn observation_id(&self) -> &Strng {
		self
			.observation_id
			.get_or_init(|| Strng::from(uuid::Uuid::now_v7().to_string()))
	}

	pub fn with_policy_refs(mut self, policy_refs: Vec<PolicyRef>) -> Self {
		self.policy_refs = policy_refs;
		self
	}

	pub fn with_principal(mut self, principal: Option<Principal>) -> Self {
		self.principal = principal;
		self
	}
}

/// Builds the OTel log record for `obs` and hands it to the OTLP access logger.
///
/// Every step here is infallible, and the logger enqueues the record on a batch
/// exporter without blocking, so this never fails and never propagates back into
/// the authorization decision.
pub fn emit(
	obs: &CapabilityObservation,
	logger: &OtelAccessLogger,
	trace: Option<&(Strng, Strng)>,
) {
	// `Outcome`/`AuthorizationBasis` are `Display`-only, and the policy refs are
	// carried as a JSON blob; everything else is a `Strng` we can borrow.
	let outcome = obs.outcome.to_string();
	let basis = obs.basis.to_string();
	let policy_refs = serde_json::to_string(&obs.policy_refs).unwrap_or_else(|_| "[]".to_string());

	let mut kv: Vec<(&str, Option<ValueBag>)> = vec![
		("event.name", Some(display(&EVENT_NAME))),
		(
			"capability.observation.id",
			Some(display(obs.observation_id())),
		),
		("capability.action", Some(display(&obs.action))),
		(
			"capability.resource.type",
			Some(display(&obs.resource.resource_type)),
		),
		(
			"capability.resource.target",
			Some(display(&obs.resource.resource_target)),
		),
		(
			"capability.resource.id",
			Some(display(&obs.resource.resource_id)),
		),
		("capability.id", Some(display(obs.capability_id()))),
		(
			"capability.decision.point",
			Some(display(&obs.decision_point)),
		),
		("capability.observation.outcome", Some(display(&outcome))),
		(
			"capability.observation.authorization_basis",
			Some(display(&basis)),
		),
		("capability.policy.refs", Some(display(&policy_refs))),
	];

	if let Some(principal) = &obs.principal {
		kv.push(("capability.principal.type", Some(display(&principal.type_))));
		kv.push(("capability.principal.id", Some(display(&principal.id))));
	}

	if let Some((trace_id, span_id)) = trace {
		kv.push(("trace.id", Some(display(trace_id))));
		kv.push(("span.id", Some(display(span_id))));
	}

	logger.emit("info", LOG_TARGET, &kv);
}

/// Metric labels for `agentgateway_capability_observations_total`.
///
/// Every label here MUST be drawn from a bounded set: `action` is an HTTP method,
/// an MCP method name, or an `llm:*` verb, and `resource_target` is a configured
/// route/server/provider name. Request-derived values (resource_id, principal_id,
/// observation_id, capability_id) are deliberately excluded -- they are carried on
/// the log record only. A non-standard extension HTTP method would widen the
/// `action` label, but that is the same exposure the gateway's existing HTTP
/// metrics already have.
#[derive(Clone, Hash, Default, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct ObservationLabels {
	pub outcome: Outcome,
	pub decision_point: DefaultedUnknown<RichStrng>,
	pub action: DefaultedUnknown<RichStrng>,
	pub resource_type: DefaultedUnknown<RichStrng>,
	pub resource_target: DefaultedUnknown<RichStrng>,
}

/// Increment the bounded-cardinality observations counter.
pub fn record_observation(metrics: &Metrics, obs: &CapabilityObservation) {
	metrics
		.capability_observations
		.get_or_create(&ObservationLabels {
			outcome: obs.outcome,
			decision_point: obs.decision_point.clone().into(),
			action: obs.action.clone().into(),
			resource_type: obs.resource.resource_type.clone().into(),
			resource_target: obs.resource.resource_target.clone().into(),
		})
		.inc();
}

/// Extracts a principal from JWT `sub` (or API-key name) stored in request
/// extensions, without exposing raw credentials.
pub fn principal_from_extensions(extensions: &::http::Extensions) -> Option<Principal> {
	if let Some(claims) = extensions.get::<crate::http::jwt::Claims>()
		&& let Some(serde_json::Value::String(sub)) = claims.inner.get("sub")
	{
		return Some(Principal::new("jwt", sub.clone()));
	}
	if let Some(claims) = extensions.get::<crate::http::apikey::Claims>()
		&& let Some(name) = claims.metadata.get("name").and_then(|v| v.as_str())
		&& !name.is_empty()
	{
		return Some(Principal::new("api_key", name));
	}
	None
}

/// A cheaply-cloneable handle threading the OTLP logger, metrics, and trace
/// context to decision points that do not have a `RequestLog` in scope.
///
/// The logger is optional: it comes from a per-listener access log policy, not
/// from the config flag that enables this feature, so a deployment can have the
/// feature on with no OTLP sink attached. That case still records the counter.
#[derive(Clone, Debug)]
pub struct CapabilityObserver {
	logger: Option<Arc<OtelAccessLogger>>,
	metrics: Arc<Metrics>,
	trace: Option<(Strng, Strng)>,
}

impl CapabilityObserver {
	pub fn new(
		logger: Option<Arc<OtelAccessLogger>>,
		metrics: Arc<Metrics>,
		trace: Option<(Strng, Strng)>,
	) -> Self {
		Self {
			logger,
			metrics,
			trace,
		}
	}

	/// Build an observer from a `RequestLog`, or `None` when capability
	/// observations are disabled. This is the single construction point for every
	/// decision site, so returning `None` here disables the feature end to end.
	pub fn from_log(log: &RequestLog) -> Option<Self> {
		if !log.cel.capability_observations {
			return None;
		}
		let trace = log
			.outgoing_span
			.as_ref()
			.map(|s| (Strng::from(s.trace_id()), Strng::from(s.span_id())))
			.or_else(|| {
				log
					.incoming_span
					.as_ref()
					.map(|s| (Strng::from(s.trace_id()), Strng::from(s.span_id())))
			});
		Some(Self::new(
			log.otel_logger.clone(),
			log.metrics.clone(),
			trace,
		))
	}

	/// Whether a log record will actually be built. Callers use this to skip work
	/// that only the record consumes -- notably the non-short-circuiting
	/// re-evaluation that produces [`PolicyRef`]s.
	pub fn emits_records(&self) -> bool {
		self.logger.is_some()
	}

	/// Record the bounded metric, and emit the log record when there is a sink.
	pub fn observe(&self, obs: &CapabilityObservation) {
		record_observation(&self.metrics, obs);
		if let Some(logger) = &self.logger {
			emit(obs, logger, self.trace.as_ref());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn resource() -> Resource {
		Resource::new("mcp.tool", "ServerOne", "increment")
	}

	#[test]
	fn capability_id_is_deterministic() {
		let r = resource();
		let a = capability_id("tools/call", &r);
		let b = capability_id("tools/call", &r);
		assert_eq!(a, b);
		assert_eq!(a.len(), 64);
		assert!(
			a.chars()
				.all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
		);
	}

	#[test]
	fn capability_id_distinguishes_action() {
		let r = resource();
		assert_ne!(
			capability_id("tools/call", &r),
			capability_id("tools/list", &r)
		);
	}

	#[test]
	fn capability_id_lowercases_action_and_type() {
		let upper = capability_id(
			"TOOLS/CALL",
			&Resource::new("MCP.Tool", "ServerOne", "increment"),
		);
		let lower = capability_id("tools/call", &resource());
		assert_eq!(upper, lower);
	}

	#[test]
	fn capability_id_preserves_target_and_id_case() {
		let a = capability_id(
			"tools/call",
			&Resource::new("mcp.tool", "ServerOne", "increment"),
		);
		let b = capability_id(
			"tools/call",
			&Resource::new("mcp.tool", "serverone", "INCREMENT"),
		);
		assert_ne!(a, b);
	}

	#[test]
	fn capability_id_handles_empty_target() {
		let a = capability_id("tools/call", &Resource::new("mcp.tool", "", "increment"));
		let b = capability_id("tools/call", &Resource::new("mcp.tool", "", "increment"));
		assert_eq!(a, b);
		assert_ne!(
			a,
			capability_id("tools/call", &Resource::new("mcp.tool", "x", "increment"))
		);
	}

	#[test]
	fn capability_id_separators_cannot_be_forged() {
		// A model name comes from the request body and an MCP tool name from the
		// upstream server, so a value carrying the field separator must not be able
		// to shift a boundary and impersonate another capability.
		let shifted_left = capability_id("tools/call", &Resource::new("mcp.tool", "a|b", "c"));
		let shifted_right = capability_id("tools/call", &Resource::new("mcp.tool", "a", "b|c"));
		assert_ne!(shifted_left, shifted_right);

		// The same for a separator smuggled across the type/target boundary.
		assert_ne!(
			capability_id("tools/call", &Resource::new("mcp.tool|x", "y", "z")),
			capability_id("tools/call", &Resource::new("mcp.tool", "x|y", "z"))
		);

		// And for the length prefix itself: a value that looks like one must not
		// let a shorter value absorb it.
		assert_ne!(
			capability_id("tools/call", &Resource::new("mcp.tool", "", "1:a")),
			capability_id("tools/call", &Resource::new("mcp.tool", "1:a", ""))
		);
	}

	#[test]
	fn observation_ids_are_unique() {
		let r = resource();
		let a = CapabilityObservation::new(
			"tools/call",
			r.clone(),
			Outcome::Allow,
			AuthorizationBasis::CelPolicy,
			"mcp authorization",
		);
		let b = CapabilityObservation::new(
			"tools/call",
			r,
			Outcome::Allow,
			AuthorizationBasis::CelPolicy,
			"mcp authorization",
		);
		assert_ne!(a.observation_id(), b.observation_id());
	}

	#[test]
	fn authorization_basis_spellings_are_stable() {
		// The `Display` spelling is what reaches the log record, so it is part of the
		// record's contract rather than an implementation detail.
		assert_eq!(AuthorizationBasis::CelPolicy.to_string(), "cel_policy");
		assert_eq!(AuthorizationBasis::Default.to_string(), "default");
		assert_eq!(AuthorizationBasis::Guardrail.to_string(), "guardrail");
		assert_eq!(AuthorizationBasis::ApiKey.to_string(), "api_key");
	}

	fn request_log(capability_observations: bool) -> RequestLog {
		use frozen_collections::FzHashSet;
		use prometheus_client::registry::Registry;

		use crate::telemetry::log::{CelLogging, Config, LoggingFields};
		use crate::transport::stream::TCPConnectionInfo;

		let cel = CelLogging::new(
			Config {
				capability_observations,
				filter: None,
				fields: LoggingFields::default(),
				standard_attributes: Default::default(),
				session: Default::default(),
				level: "info".to_string(),
				format: crate::LoggingFormat::Text,
				database: None,
			},
			Default::default(),
		);
		let mut prom = Registry::default();
		let metrics = Arc::new(Metrics::new(
			&mut prom,
			FzHashSet::default(),
			Default::default(),
		));
		let start = agent_core::Timestamp::now();
		RequestLog::new(
			cel,
			metrics,
			crate::llm::catalog::ModelCatalog::empty(),
			start,
			TCPConnectionInfo {
				peer_addr: "127.0.0.1:12345".parse().unwrap(),
				local_addr: "127.0.0.1:8080".parse().unwrap(),
				start: start.as_instant(),
				raw_peer_addr: None,
			},
		)
	}

	#[test]
	fn observer_is_absent_when_the_feature_is_disabled() {
		// No OTLP logger either, but the flag alone must be enough to opt out.
		assert!(CapabilityObserver::from_log(&request_log(false)).is_none());
	}

	#[test]
	fn observer_counts_without_an_otlp_logger() {
		// The OTLP access logger is a per-listener policy, so it may well be absent
		// when the feature is on. The bounded counter must still be recorded; only
		// the log record needs somewhere to go.
		let log = request_log(true);
		assert!(log.otel_logger.is_none());
		let observer = CapabilityObserver::from_log(&log).expect("observer without an OTLP sink");
		assert!(
			!observer.emits_records(),
			"no sink means no log record is built"
		);
	}

	#[test]
	fn record_observation_uses_bounded_labels_only() {
		use frozen_collections::FzHashSet;
		use prometheus_client::registry::Registry;

		let mut prom = Registry::default();
		let metrics = Metrics::new(&mut prom, FzHashSet::default(), Default::default());
		let obs = CapabilityObservation::new(
			"tools/call",
			resource(),
			Outcome::Deny,
			AuthorizationBasis::CelPolicy,
			"mcp authorization",
		)
		.with_principal(Some(Principal::new("jwt", "alice")));
		record_observation(&metrics, &obs);

		let mut encoded = String::new();
		prometheus_client::encoding::text::encode(&mut encoded, &prom).unwrap();
		let line = encoded
			.lines()
			.find(|l| l.starts_with("capability_observations_total{"))
			.unwrap_or_else(|| panic!("no capability counter in:\n{encoded}"));

		// Label values follow the repo's CamelCase convention (see `GuardrailAction`);
		// the log record spells the same outcome lowercase.
		assert!(line.contains(r#"outcome="Deny""#), "{line}");
		assert!(line.contains(r#"action="tools/call""#), "{line}");
		assert!(line.contains(r#"resource_type="mcp.tool""#), "{line}");
		assert!(line.contains(r#"resource_target="ServerOne""#), "{line}");
		// Request-derived values must never become labels.
		assert!(!line.contains("increment"), "resource_id leaked: {line}");
		assert!(!line.contains("alice"), "principal leaked: {line}");
		assert!(
			!line.contains(obs.capability_id().as_str()),
			"capability_id leaked: {line}"
		);
	}

	#[test]
	fn principal_from_extensions_excludes_secrets() {
		let mut extensions = ::http::Extensions::new();
		extensions.insert(crate::http::jwt::Claims {
			inner: serde_json::Map::from_iter([(
				"sub".to_string(),
				serde_json::Value::String("alice".to_string()),
			)]),
			jwt: Default::default(),
		});
		let principal = principal_from_extensions(&extensions).expect("jwt principal");
		assert_eq!(principal.type_, "jwt");
		assert_eq!(principal.id, "alice");
	}

	#[test]
	fn principal_falls_back_to_api_key_name() {
		let mut extensions = ::http::Extensions::new();
		extensions.insert(crate::http::apikey::Claims {
			key: crate::http::apikey::APIKey::new("secret-value"),
			metadata: serde_json::json!({ "name": "my-key" }),
		});
		let principal = principal_from_extensions(&extensions).expect("api_key principal");
		assert_eq!(principal.type_, "api_key");
		assert_eq!(principal.id, "my-key");
	}
}
