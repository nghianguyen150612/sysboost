#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Safe configuration-layer merging.
//!
//! Parsing a concrete TOML format is intentionally deferred. This crate
//! freezes the trust hierarchy and exposes typed layers so a future parser
//! cannot accidentally widen administrator restrictions.

use sysboost_core::{ErrorCode, Policy, PolicyMode, PolicyRequest, RiskClass, SysboostError};

/// Trust level of a configuration layer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConfigSource {
    /// Compiled safe defaults.
    Defaults,
    /// Root-owned administrator policy.
    System,
    /// User selection beneath system restrictions.
    User,
    /// Explicit invocation selection.
    Invocation,
}

/// A typed policy layer before it is merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigLayer {
    /// Trust source.
    pub source: ConfigSource,
    /// Parsed policy.
    pub policy: Policy,
}

impl ConfigLayer {
    /// Construct a layer.
    pub fn new(source: ConfigSource, policy: Policy) -> Self {
        Self { source, policy }
    }
}

/// Ordered configuration hierarchy with restrictive merging semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigHierarchy {
    defaults: ConfigLayer,
    system: Option<ConfigLayer>,
    user: Option<ConfigLayer>,
    invocation: Option<ConfigLayer>,
}

impl ConfigHierarchy {
    /// Start with compiled safe defaults.
    pub fn new(defaults: Policy) -> Self {
        Self {
            defaults: ConfigLayer::new(ConfigSource::Defaults, defaults),
            system: None,
            user: None,
            invocation: None,
        }
    }

    /// Set the system layer.
    pub fn with_system(mut self, policy: Policy) -> Self {
        self.system = Some(ConfigLayer::new(ConfigSource::System, policy));
        self
    }

    /// Set the user layer.
    pub fn with_user(mut self, policy: Policy) -> Self {
        self.user = Some(ConfigLayer::new(ConfigSource::User, policy));
        self
    }

    /// Set invocation narrowing.
    pub fn with_invocation(mut self, policy: Policy) -> Self {
        self.invocation = Some(ConfigLayer::new(ConfigSource::Invocation, policy));
        self
    }

    /// Compute an effective policy without allowing a lower-trust layer to
    /// widen risk, experimental access, or a higher-trust request allowlist.
    pub fn effective(&self) -> Result<Policy, SysboostError> {
        let layers = [
            Some(&self.defaults),
            self.system.as_ref(),
            self.user.as_ref(),
            self.invocation.as_ref(),
        ];
        let max_risk = layers
            .iter()
            .flatten()
            .map(|layer| layer.policy.max_risk)
            .min()
            .unwrap_or(RiskClass::Low);
        let allow_experimental = layers
            .iter()
            .flatten()
            .all(|layer| layer.policy.allow_experimental);
        let required_default = layers
            .iter()
            .flatten()
            .any(|layer| layer.policy.required_default);
        let session_timeout_ms = layers
            .iter()
            .flatten()
            .map(|layer| layer.policy.session_timeout_ms)
            .filter(|value| *value > 0)
            .min()
            .ok_or_else(|| {
                SysboostError::new(
                    ErrorCode::ConfigError,
                    "configuration hierarchy has no positive session timeout",
                )
            })?;

        let mode = if self
            .system
            .as_ref()
            .is_some_and(|layer| layer.policy.mode == PolicyMode::Report)
            || self
                .user
                .as_ref()
                .is_some_and(|layer| layer.policy.mode == PolicyMode::Report)
            || self
                .invocation
                .as_ref()
                .is_some_and(|layer| layer.policy.mode == PolicyMode::Report)
        {
            PolicyMode::Report
        } else {
            layers
                .iter()
                .flatten()
                .find(|layer| layer.source != ConfigSource::Defaults)
                .map(|layer| layer.policy.mode)
                .unwrap_or(self.defaults.policy.mode)
        };

        let selected = self
            .invocation
            .as_ref()
            .or(self.user.as_ref())
            .or(self.system.as_ref())
            .map(|layer| layer.policy.requests.clone())
            .unwrap_or_default();
        let allowlists = [self.system.as_ref(), self.user.as_ref()];
        let mut requests = Vec::new();
        for request in selected {
            if allowlists.iter().flatten().all(|layer| {
                layer.policy.requests.is_empty()
                    || contains_request(&layer.policy.requests, &request)
            }) {
                requests.push(request);
            } else if request.required {
                return Err(SysboostError::new(
                    ErrorCode::AuthorizationError,
                    "required request is outside a higher-trust configuration allowlist",
                ));
            }
        }

        Ok(Policy {
            mode,
            max_risk,
            allow_experimental,
            required_default,
            requests,
            session_timeout_ms,
        })
    }
}

fn contains_request(requests: &[PolicyRequest], requested: &PolicyRequest) -> bool {
    requests.iter().any(|candidate| {
        candidate.capability == requested.capability
            && candidate.target == requested.target
            && candidate.operation == requested.operation
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_trust_cannot_widen_risk_or_experimental_access() {
        let defaults = Policy::safe_defaults();
        let system = Policy {
            mode: PolicyMode::Report,
            max_risk: RiskClass::Medium,
            allow_experimental: false,
            ..Policy::safe_defaults()
        };
        let user = Policy {
            mode: PolicyMode::Boost,
            max_risk: RiskClass::Critical,
            allow_experimental: true,
            ..Policy::safe_defaults()
        };
        let effective = ConfigHierarchy::new(defaults)
            .with_system(system)
            .with_user(user)
            .effective()
            .expect("valid hierarchy");
        assert_eq!(effective.max_risk, RiskClass::Medium);
        assert!(!effective.allow_experimental);
        assert_eq!(effective.mode, PolicyMode::Report);
    }
}
