use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cel::{ContextBuilder, Executor};
use crate::proxy::ProxyError;
use crate::proxy::dtrace::{
	self, AuthorizationResult as TraceAuthorizationResult, AuthorizationRuleMode,
	AuthorizationRuleResult,
};
use crate::telemetry::capability::{
	CapabilityObservation, CapabilityObserver, Outcome, PolicyRef, Resource,
	principal_from_extensions,
};
use crate::telemetry::log::RequestLog;
use crate::*;

#[derive(Clone, Debug, Serialize)]
pub struct HTTPAuthorizationSet(RuleSets);

/// Lowercase HTTP method as a capability action. The standard methods are a
/// closed set, so only an extension method has to allocate.
fn method_action(method: &::http::Method) -> Strng {
	match *method {
		::http::Method::GET => strng::literal!("get"),
		::http::Method::POST => strng::literal!("post"),
		::http::Method::PUT => strng::literal!("put"),
		::http::Method::DELETE => strng::literal!("delete"),
		::http::Method::PATCH => strng::literal!("patch"),
		::http::Method::HEAD => strng::literal!("head"),
		::http::Method::OPTIONS => strng::literal!("options"),
		::http::Method::CONNECT => strng::literal!("connect"),
		::http::Method::TRACE => strng::literal!("trace"),
		_ => strng::new(method.as_str().to_ascii_lowercase()),
	}
}

impl HTTPAuthorizationSet {
	pub fn new(rs: RuleSets) -> Self {
		Self(rs)
	}
	pub fn merge(self, other: Self) -> Self {
		Self(self.0.merge(other.0))
	}
	pub fn expressions(&self) -> impl Iterator<Item = &cel::Expression> {
		self.0.expressions()
	}
	/// Evaluate this policy set against `req`. `with_rules` asks for the diagnostic
	/// rule list, which costs a second, non-short-circuiting pass.
	pub fn evaluate(&self, req: &http::Request, with_rules: bool) -> AuthorizationDecision {
		tracing::debug!(info=?http::DebugExtensions(req), "Checking HTTP request");
		let exec = cel::Executor::new_request(req);
		self.0.evaluate_with_rules(&exec, with_rules)
	}

	fn observe_decision(
		&self,
		observer: &CapabilityObserver,
		log: &RequestLog,
		req: &http::Request,
		decision: &AuthorizationDecision,
	) {
		let policy_refs = decision.rules.iter().map(PolicyRef::from).collect();

		// Both authorization phases run request-side, where `LLMContext` is not yet
		// populated (it is attached to the response), so the capability is always
		// described in HTTP terms here. LLM capabilities are observed by the
		// guardrail path in `llm::policy`.
		//
		// The action is the bare HTTP method so it stays safe as a metric label; the
		// path is carried as the resource id, which is log-only.
		let action = method_action(req.method());
		// The listener, not the route: the route is not selected yet at gateway scope,
		// so keying on it gave the same request two ids depending on which
		// authorization point decided. A route name is also config that can be renamed
		// or split without the capability changing, which the id must survive.
		// Qualified: a listener name is local to its gateway, and unnamed listeners
		// default to `listener{index}`, so the bare name collides across gateways.
		let target = log
			.listener_name
			.as_ref()
			.map(|l| strng::format!("{}/{}", l.as_gateway_name(), l.listener_name))
			.unwrap_or_default();
		let resource = Resource::new("http.path", target, req.uri().path());

		let outcome = if decision.allowed {
			Outcome::Allow
		} else {
			Outcome::Deny
		};
		let principal = principal_from_extensions(req.extensions());
		let obs = CapabilityObservation::new(
			action,
			resource,
			outcome,
			decision.basis.into(),
			log.policy_phase.unwrap_or("http authorization"),
		)
		.with_policy_refs(policy_refs)
		.with_principal(principal);
		observer.observe(&obs);
	}
}

impl crate::store::RequestPolicyTrait for HTTPAuthorizationSet {
	async fn apply(
		&self,
		_client: &crate::proxy::httpproxy::PolicyClient,
		log: &mut crate::telemetry::log::RequestLog,
		req: &mut http::Request,
	) -> Result<http::PolicyResponse, ProxyError> {
		tracing::debug!(info=?http::DebugExtensions(req), "Checking HTTP request");
		let exec = cel::Executor::new_request(req);
		// The observer is the single gate: the diagnostic re-evaluation is only
		// worth its cost when a capability log record will actually carry it.
		let observer = CapabilityObserver::from_log(log);
		let decision = self
			.0
			.evaluate_with_rules(&exec, observer.as_ref().is_some_and(|o| o.emits_records()));
		if let Some(observer) = &observer {
			self.observe_decision(observer, log, req, &decision);
		}
		if !decision.allowed {
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(http::PolicyResponse::default())
	}

	fn expressions(&self) -> impl Iterator<Item = &cel::Expression> {
		self.0.expressions()
	}
}

impl crate::store::BackendPolicyTrait for HTTPAuthorizationSet {
	async fn apply(
		&self,
		_client: &crate::proxy::httpproxy::PolicyClient,
		log: &mut Option<&mut crate::telemetry::log::RequestLog>,
		req: &mut http::Request,
	) -> Result<http::PolicyResponse, ProxyError> {
		tracing::debug!(info=?http::DebugExtensions(req), "Checking HTTP request");
		let exec = cel::Executor::new_request(req);
		let observer = log.as_deref().and_then(CapabilityObserver::from_log);
		let decision = self
			.0
			.evaluate_with_rules(&exec, observer.as_ref().is_some_and(|o| o.emits_records()));
		if let (Some(observer), Some(log)) = (&observer, log.as_deref()) {
			self.observe_decision(observer, log, req, &decision);
		}
		if !decision.allowed {
			return Err(ProxyError::AuthorizationFailed);
		}
		Ok(http::PolicyResponse::default())
	}

	fn expressions(&self) -> impl Iterator<Item = &cel::Expression> {
		self.0.expressions()
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkAuthorizationSet(RuleSets);

impl NetworkAuthorizationSet {
	pub fn new(rs: RuleSets) -> Self {
		Self(rs)
	}

	pub fn apply(&self, exec: &Executor<'_>) -> Result<(), ProxyError> {
		let allowed = self.0.validate(exec);
		if !allowed {
			Err(ProxyError::AuthorizationFailed)
		} else {
			Ok(())
		}
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.0.register(cel);
	}

	pub fn merge_rule_set(&mut self, rule_set: RuleSet) {
		self.0.0.push(Arc::new(rule_set));
	}
}

#[apply(schema!)]
pub struct RuleSet {
	/// CEL authorization rules to evaluate for a request.
	#[serde(serialize_with = "se_policies", deserialize_with = "de_policies")]
	#[cfg_attr(feature = "schema", schemars(with = "Vec<RuleSerde>"))]
	pub rules: PolicySet,
}

#[derive(Clone, Debug, Default)]
pub struct PolicySet {
	allow: Vec<Arc<cel::Expression>>,
	deny: Vec<Arc<cel::Expression>>,
	require: Vec<Arc<cel::Expression>>,
}

#[derive(Clone, Debug)]
pub enum Policy {
	Allow(Arc<cel::Expression>),
	Deny(Arc<cel::Expression>),
	Require(Arc<cel::Expression>),
}

#[apply(schema!)]
#[serde(untagged)]
enum RuleSerde {
	Object {
		#[serde(flatten)]
		rule: RuleTypeSerde,
	},
	PlainString(String),
}

#[apply(schema!)]
enum RuleTypeSerde {
	/// Allow the request when this CEL expression is true.
	Allow(String),
	/// Deny the request when this CEL expression is true. This mode is not
	/// recommended because expression failures fail to deny; prefer `Allow` or
	/// `Require`. If used, design expressions defensively against evaluation errors.
	Deny(String),
	/// Require this CEL expression to be true.
	Require(String),
}

impl PolicySet {
	pub fn new(
		allow: Vec<Arc<cel::Expression>>,
		deny: Vec<Arc<cel::Expression>>,
		require: Vec<Arc<cel::Expression>>,
	) -> Self {
		Self {
			allow,
			deny,
			require,
		}
	}
}

pub fn se_policies<S: Serializer>(t: &PolicySet, serializer: S) -> Result<S::Ok, S::Error> {
	let len = usize::from(!t.allow.is_empty())
		+ usize::from(!t.deny.is_empty())
		+ usize::from(!t.require.is_empty());
	let mut m = serializer.serialize_map(Some(len))?;
	if !t.allow.is_empty() {
		m.serialize_entry("allow", &t.allow)?;
	}
	if !t.deny.is_empty() {
		m.serialize_entry("deny", &t.deny)?;
	}
	if !t.require.is_empty() {
		m.serialize_entry("require", &t.require)?;
	}
	m.end()
}

pub fn de_policies<'de: 'a, 'a, D>(deserializer: D) -> Result<PolicySet, D::Error>
where
	D: Deserializer<'de>,
{
	let raw = Vec::<RuleSerde>::deserialize(deserializer)?;
	let mut res = PolicySet {
		allow: vec![],
		deny: vec![],
		require: vec![],
	};
	for r in raw {
		match r {
			RuleSerde::Object {
				rule: RuleTypeSerde::Allow(allow),
			}
			| RuleSerde::PlainString(allow) => res.allow.push(
				cel::Expression::new_strict(&allow)
					.map(Arc::new)
					.map_err(|e| serde::de::Error::custom(e.to_string()))?,
			),
			RuleSerde::Object {
				rule: RuleTypeSerde::Deny(deny),
			} => res.deny.push(
				cel::Expression::new_strict(deny)
					.map(Arc::new)
					.map_err(|e| serde::de::Error::custom(e.to_string()))?,
			),
			RuleSerde::Object {
				rule: RuleTypeSerde::Require(require),
			} => res.require.push(
				cel::Expression::new_strict(require)
					.map(Arc::new)
					.map_err(|e| serde::de::Error::custom(e.to_string()))?,
			),
		};
	}
	Ok(res)
}

#[apply(schema!)]
pub struct RuleSets(Vec<Arc<RuleSet>>);

impl From<Vec<RuleSet>> for RuleSets {
	fn from(value: Vec<RuleSet>) -> Self {
		Self(value.into_iter().map(Arc::new).collect())
	}
}

impl RuleSets {
	pub fn from_arcs(value: Vec<Arc<RuleSet>>) -> Self {
		Self(value)
	}

	/// Combine two sets so both apply: a deny in either denies, all requires must
	/// hold, and allow rules are OR'd across both.
	pub fn merge(mut self, other: Self) -> Self {
		self.0.extend(other.0);
		self
	}
}

impl RuleSets {
	pub fn register(&self, ctx: &mut ContextBuilder) {
		for expr in self.expressions() {
			ctx.register_expression(expr);
		}
	}
	fn expressions(&self) -> impl Iterator<Item = &cel::Expression> {
		self.0.iter().flat_map(|rule_set| {
			rule_set
				.rules
				.allow
				.iter()
				.chain(rule_set.rules.deny.iter())
				.chain(rule_set.rules.require.iter())
				.map(|rule| rule.as_ref())
		})
	}
	pub(crate) fn has_rules(&self) -> bool {
		self.0.iter().any(|r| r.has_rules())
	}
	pub fn validate(&self, exec: &Executor) -> bool {
		self.evaluate_with_rules(exec, false).allowed
	}
	pub fn evaluate_with_rules(&self, exec: &Executor, with_rules: bool) -> AuthorizationDecision {
		let rule_sets = &self.0;
		let has_rules = self.has_rules();
		// If there are no rule sets, everyone has access
		#[allow(clippy::if_same_then_else)] // This is intentional to make things explicit.
		let allowed = if !has_rules {
			true
		// If there are any DENY, deny
		} else if rule_sets.iter().any(|r| r.denies(exec)) {
			false
		// All REQUIRE policies must match when present.
		} else if rule_sets.iter().any(|r| !r.all_requires_match(exec)) {
			false
		// If there are any ALLOW, allow
		} else if rule_sets.iter().any(|r| r.allows(exec)) {
			true
		} else {
			// If only deny rules exist (no allow rules), default to allow (denylist semantics).
			// If allow rules exist but none matched, default to deny (allowlist semantics).
			!rule_sets.iter().any(|r| r.has_allow_rules())
		};

		// Re-evaluate the rules for diagnostics. Note we do not short-circuit here.
		// Only pay the double-evaluation cost when an observation needs `rules`
		// or a dtrace watcher is active; otherwise preserve the original
		// short-circuit behavior.
		let mut rules = Vec::new();

		if with_rules || dtrace::is_active() {
			for rule_set in rule_sets {
				for rule in &rule_set.rules.allow {
					rules.push(AuthorizationRuleResult {
						name: rule.original_expression.clone(),
						matched: exec.eval_bool(rule.as_ref()),
						mode: AuthorizationRuleMode::Allow,
					});
				}
				for rule in &rule_set.rules.deny {
					rules.push(AuthorizationRuleResult {
						name: rule.original_expression.clone(),
						matched: exec.eval_bool(rule.as_ref()),
						mode: AuthorizationRuleMode::Deny,
					});
				}
				for rule in &rule_set.rules.require {
					rules.push(AuthorizationRuleResult {
						name: rule.original_expression.clone(),
						matched: exec.eval_bool(rule.as_ref()),
						mode: AuthorizationRuleMode::Require,
					});
				}
			}
		}

		dtrace::trace(|trace| {
			trace.authorization_result(
				rules.clone(),
				if allowed {
					TraceAuthorizationResult::Allow
				} else {
					TraceAuthorizationResult::Deny
				},
			)
		});

		AuthorizationDecision {
			allowed,
			basis: if has_rules {
				DecisionBasis::CelPolicy
			} else {
				DecisionBasis::Default
			},
			rules,
		}
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

/// The result of evaluating an authorization policy set for a request.
#[derive(Debug)]
pub struct AuthorizationDecision {
	pub allowed: bool,
	pub rules: Vec<dtrace::AuthorizationRuleResult>,
	pub basis: DecisionBasis,
}

/// Why an authorization decision came out the way it did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecisionBasis {
	/// A CEL policy set produced the decision.
	CelPolicy,
	/// No policies were configured, so the default outcome applied.
	Default,
}

impl RuleSet {
	pub fn new(rules: PolicySet) -> Self {
		Self { rules }
	}

	pub fn has_rules(&self) -> bool {
		!self.rules.allow.is_empty() || !self.rules.deny.is_empty() || !self.rules.require.is_empty()
	}

	pub fn has_allow_rules(&self) -> bool {
		!self.rules.allow.is_empty()
	}
	pub fn denies(&self, exec: &cel::Executor) -> bool {
		if self.rules.deny.is_empty() {
			false
		} else {
			self
				.rules
				.deny
				.iter()
				.any(|rule| exec.eval_bool(rule.as_ref()))
		}
	}

	pub fn allows(&self, exec: &cel::Executor) -> bool {
		if self.rules.allow.is_empty() {
			false
		} else {
			self
				.rules
				.allow
				.iter()
				.any(|rule| exec.eval_bool(rule.as_ref()))
		}
	}

	pub fn all_requires_match(&self, exec: &cel::Executor) -> bool {
		self
			.rules
			.require
			.iter()
			.all(|rule| exec.eval_bool(rule.as_ref()))
	}
}

#[cfg(any(test, feature = "internal_benches"))]
#[path = "authorization_tests.rs"]
mod tests;

// A separate module from `authorization_tests.rs` (which is mounted as `tests`).
#[cfg(test)]
mod evaluate_with_rules_tests {
	use super::*;

	fn expr(e: &str) -> Arc<cel::Expression> {
		Arc::new(cel::Expression::new_strict(e).unwrap())
	}

	const ALLOW_GET: &str = r#"request.method == "GET""#;
	const DENY_POST: &str = r#"request.method == "POST""#;

	fn rule_sets() -> RuleSets {
		RuleSets::from(vec![RuleSet::new(PolicySet::new(
			vec![expr(ALLOW_GET)],
			vec![expr(DENY_POST)],
			vec![],
		))])
	}

	fn request() -> http::Request {
		::http::Request::builder()
			.method(::http::Method::GET)
			.uri("http://example.com/things")
			.body(http::Body::empty())
			.unwrap()
	}

	#[test]
	fn rules_are_not_evaluated_when_nothing_consumes_them() {
		let req = request();
		let exec = cel::Executor::new_request(&req);
		let decision = rule_sets().evaluate_with_rules(&exec, false);
		assert!(decision.allowed);
		// An empty vector is the observable proof that the non-short-circuiting
		// second pass was skipped.
		assert!(decision.rules.is_empty());
	}

	#[test]
	fn rules_report_every_policy_when_requested() {
		let req = request();
		let exec = cel::Executor::new_request(&req);
		let decision = rule_sets().evaluate_with_rules(&exec, true);
		assert!(decision.allowed);
		assert_eq!(decision.rules.len(), 2);

		assert_eq!(decision.rules[0].name, ALLOW_GET);
		assert!(matches!(
			decision.rules[0].mode,
			AuthorizationRuleMode::Allow
		));
		assert!(decision.rules[0].matched);

		assert_eq!(decision.rules[1].name, DENY_POST);
		assert!(matches!(
			decision.rules[1].mode,
			AuthorizationRuleMode::Deny
		));
		assert!(!decision.rules[1].matched);
	}
}
