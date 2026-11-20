use std::sync::Arc;

use ::cel::Value;
use ::cel::objects::{KeyRef, MapValue};
use agent_core::strng::Strng;
use serde::Serialize;
use vector_map::VecMap;

use crate::cel::ContextBuilder;
use crate::http::authorization::{AuthorizationDecision, DecisionBasis, RuleSet, RuleSets};
use crate::telemetry::capability::{
	CapabilityObservation, CapabilityObserver, Outcome, PolicyRef, Resource,
	principal_from_extensions,
};
use crate::*;

#[apply(schema!)]
pub struct McpAuthorization(
	/// CEL authorization rules for MCP tools, prompts, and resources.
	RuleSet,
);

impl McpAuthorization {
	pub fn new(rule_set: RuleSet) -> Self {
		Self(rule_set)
	}

	pub fn into_inner(self) -> RuleSet {
		self.0
	}
}

/// Cheap clone via Arc; this API treats the request as read-only after construction.
#[derive(Clone)]
pub struct CelExecWrapper(Arc<crate::mcp::upstream::IncomingRequestContext>);

impl From<crate::mcp::upstream::IncomingRequestContext> for CelExecWrapper {
	fn from(ctx: crate::mcp::upstream::IncomingRequestContext) -> Self {
		Self(Arc::new(ctx))
	}
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuthorizationSet(RuleSets);

impl McpAuthorizationSet {
	pub fn new(rs: RuleSets) -> Self {
		Self(rs)
	}

	/// Combine rule sets so both apply; see [`RuleSets::merge`].
	pub fn merge(self, other: Self) -> Self {
		Self(self.0.merge(other.0))
	}

	pub fn validate(&self, res: &ResourceType, method_name: &Strng, cel: &CelExecWrapper) -> bool {
		self.evaluate(res, method_name, cel, false).allowed
	}

	fn evaluate(
		&self,
		res: &ResourceType,
		method_name: &Strng,
		cel: &CelExecWrapper,
		with_rules: bool,
	) -> AuthorizationDecision {
		if !self.0.has_rules() {
			return AuthorizationDecision {
				allowed: true,
				rules: Vec::new(),
				basis: DecisionBasis::Default,
			};
		}
		tracing::debug!("Checking RBAC for resource: {:?}", res);
		let mut mcp = crate::mcp::MCPInfo::from(res);
		mcp.method_name = Some(method_name.clone());
		let mut exec = cel.0.executor();
		exec.mcp = Some(crate::mcp::MCPView::new(&mcp));
		self.0.evaluate_with_rules(&exec, with_rules)
	}

	/// Like [`Self::validate`], but also emits a capability observation when an
	/// OTLP logger is available via the request extensions (threaded there by
	/// `mcp::router` using `CapabilityObserver`).
	pub fn validate_observed(
		&self,
		res: &ResourceType,
		method_name: &Strng,
		cel: &CelExecWrapper,
	) -> bool {
		let Some(observer) = cel.0.extensions().get::<CapabilityObserver>() else {
			return self.evaluate(res, method_name, cel, false).allowed;
		};
		// The rule list is only read back by the log record, and a listing evaluates
		// this once per advertised tool, prompt and resource, so skip the
		// non-short-circuiting pass when nothing will carry it.
		let decision = self.evaluate(res, method_name, cel, observer.emits_records());

		let (resource_type, target, id) = match res {
			ResourceType::Tool(r) => ("mcp.tool", r.target(), r.name()),
			ResourceType::Prompt(r) => ("mcp.prompt", r.target(), r.name()),
			ResourceType::Resource(r) => ("mcp.resource", r.target(), r.name()),
			ResourceType::Task(r) => ("mcp.task", r.target(), r.name()),
		};
		let resource = Resource::new(resource_type, target, id);
		let outcome = if decision.allowed {
			Outcome::Allow
		} else {
			Outcome::Deny
		};
		let policy_refs = decision.rules.iter().map(PolicyRef::from).collect();
		let principal = principal_from_extensions(cel.0.extensions());
		let obs = CapabilityObservation::new(
			method_name.clone(),
			resource,
			outcome,
			decision.basis.into(),
			strng::literal!("mcp authorization"),
		)
		.with_policy_refs(policy_refs)
		.with_principal(principal);
		observer.observe(&obs);
		decision.allowed
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.0.register(cel);
	}
}

#[apply(schema!)]
#[derive(Eq, PartialEq)]
pub enum ResourceType {
	/// The tool being accessed
	Tool(ResourceId),
	/// The prompt being accessed
	Prompt(ResourceId),
	/// The resource being accessed
	Resource(ResourceId),
	/// The task being accessed (SEP-2663); `name` is the task ID.
	Task(ResourceId),
}

impl cel::DynamicType for ResourceType {
	fn materialize(&self) -> Value<'_> {
		let (n, t) = match self {
			ResourceType::Tool(t) => ("tool", t),
			ResourceType::Prompt(t) => ("prompt", t),
			ResourceType::Resource(t) => ("resource", t),
			ResourceType::Task(t) => ("task", t),
		};
		Value::Map(MapValue::Borrow(VecMap::from_iter([(
			KeyRef::String(n.into()),
			t.materialize(),
		)])))
	}

	fn field(&self, field: &str) -> Option<Value<'_>> {
		match (self, field) {
			(ResourceType::Tool(t), "tool") => Some(t.materialize()),
			(ResourceType::Prompt(t), "prompt") => Some(t.materialize()),
			(ResourceType::Resource(t), "resource") => Some(t.materialize()),
			(ResourceType::Task(t), "task") => Some(t.materialize()),
			_ => None,
		}
	}
}

#[apply(schema!)]
#[derive(Eq, PartialEq, ::cel::DynamicType)]
pub struct ResourceId {
	#[serde(default)]
	/// The target of the resource
	target: String,
	#[serde(rename = "name", default)]
	/// The name of the resource
	id: String,
}

impl ResourceId {
	pub fn new(target: String, id: String) -> Self {
		Self { target, id }
	}

	pub fn target(&self) -> &str {
		&self.target
	}

	pub fn name(&self) -> &str {
		&self.id
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use serde_json::json;

	use super::*;
	use crate::http::authorization::PolicySet;
	use crate::mcp::guardrails::methods::{TOOLS_CALL, TOOLS_LIST};

	fn cel_context(req: ::http::Request<bytes::Bytes>) -> CelExecWrapper {
		let (parts, body) = req.into_parts();
		let mut ctx = crate::mcp::upstream::IncomingRequestContext::new(&parts);
		*ctx.request.body_mut() = Some(body);
		ctx.into()
	}

	fn tool_resource(target: &str, name: &str) -> ResourceType {
		ResourceType::Tool(ResourceId::new(target.to_string(), name.to_string()))
	}

	fn req_with_claims(claims: serde_json::Value) -> ::http::Request<bytes::Bytes> {
		let mut req = ::http::Request::builder()
			.method(::http::Method::POST)
			.uri("http://example.com/mcp")
			.body(bytes::Bytes::new())
			.unwrap();
		let serde_json::Value::Object(claims) = claims else {
			panic!("claims must be a JSON object");
		};
		req.extensions_mut().insert(crate::http::jwt::Claims {
			inner: claims,
			jwt: Default::default(),
		});
		req
	}

	fn req_without_claims() -> ::http::Request<bytes::Bytes> {
		::http::Request::builder()
			.method(::http::Method::POST)
			.uri("http://example.com/mcp")
			.body(bytes::Bytes::new())
			.unwrap()
	}

	fn authorization_set(expr: &str) -> McpAuthorizationSet {
		let policies = PolicySet::new(
			vec![Arc::new(cel::Expression::new_strict(expr).unwrap())],
			vec![],
			vec![],
		);
		McpAuthorizationSet::new(RuleSets::from(vec![RuleSet::new(policies)]))
	}

	#[test]
	fn test_mcp_authorization_empty_rules_short_circuits() {
		let res = tool_resource("server", "increment");

		let no_rule_sets = McpAuthorizationSet::new(RuleSets::from(vec![]));
		assert!(no_rule_sets.validate(&res, &TOOLS_CALL, &cel_context(req_without_claims())));

		let empty_rule_set = McpAuthorizationSet::new(RuleSets::from(vec![RuleSet::new(
			PolicySet::new(vec![], vec![], vec![]),
		)]));
		assert!(empty_rule_set.validate(&res, &TOOLS_CALL, &cel_context(req_without_claims())));
	}

	#[test]
	fn test_backend_policies_merge_composes_mcp_authorization() {
		let with_authz = |authz: McpAuthorizationSet| crate::store::BackendPolicies {
			mcp_authorization: Some(authz),
			..Default::default()
		};
		let deny_all = || {
			McpAuthorizationSet::new(RuleSets::from(vec![RuleSet::new(PolicySet::new(
				vec![],
				vec![Arc::new(cel::Expression::new_strict("true").unwrap())],
				vec![],
			))]))
		};
		let res = tool_resource("server", "increment");
		let cel = cel_context(req_without_claims());

		// Higher-precedence allow does not erase a base deny
		let merged = with_authz(deny_all())
			.merge(with_authz(authorization_set("true")))
			.mcp_authorization
			.unwrap();
		assert!(!merged.validate(&res, &TOOLS_CALL, &cel));

		// A policy on only one side passes through
		for merged in [
			with_authz(deny_all()).merge(Default::default()),
			crate::store::BackendPolicies::default().merge(with_authz(deny_all())),
		] {
			assert!(
				!merged
					.mcp_authorization
					.unwrap()
					.validate(&res, &TOOLS_CALL, &cel)
			);
		}
	}

	#[test]
	fn test_mcp_authorization_jwt_claim_match() {
		let authz = authorization_set(r#"mcp.tool.name == "increment" && jwt.sub == "1234567890""#);
		let req = req_with_claims(json!({ "sub": "1234567890" }));
		let res = tool_resource("server", "increment");

		assert!(authz.validate(&res, &TOOLS_CALL, &cel_context(req)));
	}

	#[test]
	fn test_mcp_authorization_jwt_nested_claim_mismatch() {
		let authz = authorization_set(r#"mcp.tool.name == "increment" && jwt.user.role == "admin""#);
		let req = req_with_claims(json!({ "user": { "role": "viewer" } }));
		let res = tool_resource("server", "increment");

		assert!(!authz.validate(&res, &TOOLS_CALL, &cel_context(req)));
	}

	#[test]
	fn test_mcp_authorization_jwt_claim_required_but_missing() {
		let authz = authorization_set(r#"mcp.tool.name == "increment" && jwt.sub == "1234567890""#);
		let req = req_without_claims();
		let res = tool_resource("server", "increment");

		assert!(!authz.validate(&res, &TOOLS_CALL, &cel_context(req)));
	}

	#[test]
	fn test_mcp_authorization_method_name_distinguishes_list_from_call() {
		let authz = authorization_set(r#"mcp.methodName == "tools/list""#);
		let req = req_without_claims();
		let res = tool_resource("server", "increment");
		let cel = cel_context(req);

		assert!(authz.validate(&res, &TOOLS_LIST, &cel));
		assert!(!authz.validate(&res, &TOOLS_CALL, &cel));
	}

	/// Builds an observer over a fresh, unprefixed local registry so the
	/// counter series can be scraped without pulling in the full proxy metrics
	/// stack. Mirrors the pattern in `telemetry::capability::tests` and
	/// `llm::policy::tests`.
	fn observer_over_registry() -> (
		prometheus_client::registry::Registry,
		crate::telemetry::capability::CapabilityObserver,
	) {
		let mut prom = prometheus_client::registry::Registry::default();
		let metrics = Arc::new(crate::telemetry::metrics::Metrics::new(
			&mut prom,
			frozen_collections::FzHashSet::default(),
			Default::default(),
		));
		let observer = crate::telemetry::capability::CapabilityObserver::new(None, metrics, None);
		(prom, observer)
	}

	fn scrape_capability_line(prom: &prometheus_client::registry::Registry) -> String {
		let mut encoded = String::new();
		prometheus_client::encoding::text::encode(&mut encoded, prom).unwrap();
		encoded
			.lines()
			.find(|l| l.starts_with("capability_observations_total{"))
			.unwrap_or_else(|| panic!("no capability counter in:\n{encoded}"))
			.to_string()
	}

	#[test]
	fn test_validate_observed_denied_tool_is_counted_and_still_denied() {
		// The allow rule keys on a claim the request never carries, so the
		// decision is deny; per `CapabilityObserver` docs, observing must never
		// change that outcome.
		let authz = authorization_set(r#"mcp.tool.name == "increment" && jwt.sub == "1234567890""#);
		let res = tool_resource("ServerOne", "increment");

		let (prom, observer) = observer_over_registry();
		let mut req = req_without_claims();
		req.extensions_mut().insert(observer);
		let cel = cel_context(req);

		let allowed = authz.validate_observed(&res, &TOOLS_CALL, &cel);
		assert!(!allowed, "observing must not change the deny decision");

		let line = scrape_capability_line(&prom);
		assert!(line.contains(r#"outcome="Deny""#), "{line}");
		assert!(line.contains(r#"action="tools/call""#), "{line}");
		assert!(line.contains(r#"resource_type="mcp.tool""#), "{line}");
		assert!(line.contains(r#"resource_target="ServerOne""#), "{line}");
		// resource_id and principal are log-only, never metric labels.
		assert!(!line.contains("increment"), "resource id leaked: {line}");
		assert!(!line.contains("1234567890"), "principal leaked: {line}");
	}

	#[test]
	fn test_validate_observed_allowed_tool_is_counted_as_allow() {
		let authz = authorization_set(r#"mcp.tool.name == "increment""#);
		let res = tool_resource("ServerOne", "increment");

		let (prom, observer) = observer_over_registry();
		let mut req = req_without_claims();
		req.extensions_mut().insert(observer);
		let cel = cel_context(req);

		let allowed = authz.validate_observed(&res, &TOOLS_CALL, &cel);
		assert!(allowed, "observing must not change the allow decision");

		let line = scrape_capability_line(&prom);
		assert!(line.contains(r#"outcome="Allow""#), "{line}");
		assert!(line.contains(r#"action="tools/call""#), "{line}");
		assert!(line.contains(r#"resource_type="mcp.tool""#), "{line}");
		assert!(line.contains(r#"resource_target="ServerOne""#), "{line}");
		assert!(!line.contains("increment"), "resource id leaked: {line}");
	}
}
