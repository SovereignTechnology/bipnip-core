//! Rules an order sets for who may take it (bipnip drafts "Liquidity leases" and "Liquidity
//! rings"): the least a taker's node must show in the public Lightning graph.
//!
//! A lease offer's rules apply to its buyer; a ring's rules apply to every member. Whoever checks
//! them (the instance, at a take; a seller's or a member's own agent, again, on its own node)
//! reads the taker's node from its own graph. A node the graph does not know meets only empty
//! rules.
//!
//! On the wire the rules are a JSON object with only the rules that are set, and an optional
//! `rules` tag on the order event, one `key=value` value per rule set, in this order:
//! `min_channels`, `min_capacity_sat`. No rule set: no field, no tag, so a message without rules
//! is byte-identical to one from before rules existed.
//!
//! Everything here is pure.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The most public channels a rule may ask a node to have.
pub const MAX_MIN_CHANNELS: u32 = 10_000;
/// The most total capacity, in satoshi, a rule may ask a node to have (all the bitcoin there is).
pub const MAX_MIN_CAPACITY_SAT: u64 = 21_000_000 * 100_000_000;

/// Why rules were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesError(pub &'static str);

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid rules: {}", self.0)
    }
}

impl std::error::Error for RulesError {}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// The least a taker's node must show in the public graph. Zero means no such rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Fewest public channels.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_channels: u32,
    /// Least total capacity of its public channels, in satoshi.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_capacity_sat: u64,
}

/// A canonical decimal greater than zero.
fn positive<T: std::str::FromStr + Default + PartialEq>(
    s: &str,
    what: &'static str,
) -> Result<T, RulesError> {
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|c| c.is_ascii_digit())
        && !s.starts_with('0');
    if !canonical {
        return Err(RulesError(what));
    }
    s.parse().map_err(|_| RulesError(what))
}

impl Rules {
    /// True when no rule is set: anyone may take the order.
    pub fn is_none(&self) -> bool {
        *self == Rules::default()
    }

    /// Checks each rule's range.
    pub fn validate(&self) -> Result<(), RulesError> {
        if self.min_channels > MAX_MIN_CHANNELS {
            return Err(RulesError("min_channels"));
        }
        if self.min_capacity_sat > MAX_MIN_CAPACITY_SAT {
            return Err(RulesError("min_capacity_sat"));
        }
        Ok(())
    }

    /// Whether a node the graph shows with `graph` = (public channels, their total capacity in
    /// satoshi) meets the rules. `None`: the graph does not know the node, which meets only
    /// empty rules.
    pub fn met_by(&self, graph: Option<(u32, u64)>) -> bool {
        match graph {
            None => self.is_none(),
            Some((channels, capacity_sat)) => {
                channels >= self.min_channels && capacity_sat >= self.min_capacity_sat
            }
        }
    }

    /// The values of the order event's `rules` tag (without the tag's name); empty when no rule
    /// is set, and then no tag is written.
    pub fn tag_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if self.min_channels > 0 {
            values.push(format!("min_channels={}", self.min_channels));
        }
        if self.min_capacity_sat > 0 {
            values.push(format!("min_capacity_sat={}", self.min_capacity_sat));
        }
        values
    }

    /// Reads a `rules` tag's values. Strict: at least one rule, known names only, each once, in
    /// the order [`Rules::tag_values`] writes them, values canonical and greater than zero, and
    /// within range.
    pub fn from_tag_values(values: &[String]) -> Result<Self, RulesError> {
        if values.is_empty() {
            return Err(RulesError("an empty rules tag"));
        }
        let mut rules = Rules::default();
        let mut last = 0;
        for value in values {
            let (name, number) = value
                .split_once('=')
                .ok_or(RulesError("a rule is not name=value"))?;
            let place = match name {
                "min_channels" => {
                    rules.min_channels = positive(number, "min_channels")?;
                    1
                }
                "min_capacity_sat" => {
                    rules.min_capacity_sat = positive(number, "min_capacity_sat")?;
                    2
                }
                _ => return Err(RulesError("an unknown rule")),
            };
            if place <= last {
                return Err(RulesError("rules out of order or repeated"));
            }
            last = place;
        }
        rules.validate()?;
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn empty_rules_are_met_by_anyone_and_write_nothing() {
        let none = Rules::default();
        assert!(none.is_none());
        assert!(none.met_by(None));
        assert!(none.met_by(Some((0, 0))));
        assert!(none.tag_values().is_empty());
        assert_eq!(serde_json::to_string(&none).unwrap(), "{}");
        assert_eq!(serde_json::from_str::<Rules>("{}").unwrap(), none);
    }

    #[test]
    fn rules_are_met_only_by_a_node_the_graph_shows_with_enough() {
        let rules = Rules {
            min_channels: 3,
            min_capacity_sat: 5_000_000,
        };
        assert!(!rules.met_by(None));
        assert!(!rules.met_by(Some((2, 9_000_000))));
        assert!(!rules.met_by(Some((5, 4_999_999))));
        assert!(rules.met_by(Some((3, 5_000_000))));
        let channels_only = Rules {
            min_channels: 1,
            ..Rules::default()
        };
        assert!(channels_only.met_by(Some((1, 0))));
        assert!(!channels_only.met_by(Some((0, 0))));
    }

    #[test]
    fn the_tag_round_trips_and_only_its_canonical_form_reads() {
        let rules = Rules {
            min_channels: 3,
            min_capacity_sat: 5_000_000,
        };
        let values = rules.tag_values();
        assert_eq!(
            values,
            strings(&["min_channels=3", "min_capacity_sat=5000000"])
        );
        assert_eq!(Rules::from_tag_values(&values), Ok(rules));
        let one = strings(&["min_capacity_sat=1"]);
        assert_eq!(
            Rules::from_tag_values(&one),
            Ok(Rules {
                min_capacity_sat: 1,
                ..Rules::default()
            })
        );
        for bad in [
            vec![],
            vec!["min_channels"],
            vec!["min_channels=0"],
            vec!["min_channels=03"],
            vec!["min_channels=+3"],
            vec!["min_channels=3", "min_channels=3"],
            vec!["min_capacity_sat=5", "min_channels=3"],
            vec!["max_channels=3"],
            vec!["clearnet=1"],
            vec!["min_channels=10001"],
            vec!["min_capacity_sat=2100000000000001"],
            vec!["min_channels=99999999999999999999"],
        ] {
            assert!(
                Rules::from_tag_values(&strings(&bad)).is_err(),
                "{bad:?} was read"
            );
        }
    }

    #[test]
    fn json_keeps_only_the_rules_set_and_refuses_unknown_fields() {
        let rules = Rules {
            min_channels: 2,
            ..Rules::default()
        };
        let json = serde_json::to_string(&rules).unwrap();
        assert_eq!(json, r#"{"min_channels":2}"#);
        assert_eq!(serde_json::from_str::<Rules>(&json).unwrap(), rules);
        assert!(serde_json::from_str::<Rules>(r#"{"clearnet":true}"#).is_err());
    }
}
