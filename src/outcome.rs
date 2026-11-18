//! Liquidity outcomes (bipnip draft "Liquidity outcomes", kind 8735): how a lease or a ring edge
//! ended, signed by a party that saw it end, or by the instance that coordinated it.
//!
//! The event is regular, not addressable, so an author cannot replace what it said. Its `content`
//! is the author's node binding (kind 31735) as JSON, so a reader checks the author against one
//! of the two nodes without a second lookup ([`Outcome::author_node`]). An instance's outcome has
//! an empty `content`; a reader trusts it only from an instance it chose.
//!
//! What a reader makes of outcomes (which count, which are confirmed) is the reader's; the draft
//! states the rules. This module only writes and reads the event, strictly.
//!
//! Everything here is pure, apart from the clock a caller passes.

use std::fmt;
use std::str::FromStr;

use nostr_sdk::prelude::{Event, EventBuilder, Kind, Tag};
use secp256k1::PublicKey;

use crate::lease_message::check_binding;
use crate::node_binding::Network;

/// The kind of a liquidity outcome event.
pub const KIND_LIQUIDITY_OUTCOME: u16 = 8735;

/// Why an outcome was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeError(pub &'static str);

impl fmt::Display for OutcomeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid liquidity outcome: {}", self.0)
    }
}

impl std::error::Error for OutcomeError {}

fn refuse<T>(what: &'static str) -> Result<T, OutcomeError> {
    Err(OutcomeError(what))
}

/// What kind of deal the outcome is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Deal {
    /// A lease; the subject is the lease id.
    Lease,
    /// One edge of a ring; the subject is the ring id.
    Ring,
}

impl Deal {
    /// As written in the `k` tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            Deal::Lease => "lease",
            Deal::Ring => "ring",
        }
    }
}

/// A node's part in the deal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A lease's seller.
    Seller,
    /// A lease's buyer.
    Buyer,
    /// The ring member that owed the channel.
    Opener,
    /// The ring member the channel was owed to.
    Receiver,
}

impl Role {
    /// As written in an `n` or `closer` tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Seller => "seller",
            Role::Buyer => "buyer",
            Role::Opener => "opener",
            Role::Receiver => "receiver",
        }
    }

    fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "seller" => Role::Seller,
            "buyer" => Role::Buyer,
            "opener" => Role::Opener,
            "receiver" => Role::Receiver,
            _ => return None,
        })
    }

    /// The two roles of a deal, in the order the `n` tags are written.
    fn of(deal: Deal) -> [Role; 2] {
        match deal {
            Deal::Lease => [Role::Seller, Role::Buyer],
            Deal::Ring => [Role::Opener, Role::Receiver],
        }
    }
}

/// How the deal ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeResult {
    /// A lease's channel stood until the lease had run its length.
    Kept,
    /// A lease's channel closed before the lease had run its length.
    ClosedEarly,
    /// A lease ran its length and the buyer never paid the completion share it was billed.
    Unpaid,
    /// A lease buyer's bond was taken (an instance's outcome only).
    Slashed,
    /// A ring edge's channel was there by the end of the window.
    Opened,
    /// It was not.
    Missing,
}

impl OutcomeResult {
    /// As written in the `result` tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            OutcomeResult::Kept => "kept",
            OutcomeResult::ClosedEarly => "closed-early",
            OutcomeResult::Unpaid => "unpaid",
            OutcomeResult::Slashed => "slashed",
            OutcomeResult::Opened => "opened",
            OutcomeResult::Missing => "missing",
        }
    }

    fn parse(s: &str) -> Option<OutcomeResult> {
        Some(match s {
            "kept" => OutcomeResult::Kept,
            "closed-early" => OutcomeResult::ClosedEarly,
            "unpaid" => OutcomeResult::Unpaid,
            "slashed" => OutcomeResult::Slashed,
            "opened" => OutcomeResult::Opened,
            "missing" => OutcomeResult::Missing,
            _ => return None,
        })
    }

    /// True when the result may describe a deal of this kind.
    pub fn fits(&self, deal: Deal) -> bool {
        match deal {
            Deal::Lease => matches!(
                self,
                OutcomeResult::Kept
                    | OutcomeResult::ClosedEarly
                    | OutcomeResult::Unpaid
                    | OutcomeResult::Slashed
            ),
            Deal::Ring => matches!(self, OutcomeResult::Opened | OutcomeResult::Missing),
        }
    }
}

/// Who closed a channel that closed early, as the author's node saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClosedBy {
    /// The node with this role in the deal.
    Party(Role),
    /// The author's node cannot say.
    Unknown,
}

/// One outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What kind of deal.
    pub deal: Deal,
    /// The lease id or the ring id, 64 lower-case hex.
    pub subject: String,
    /// The network the nodes are on.
    pub network: Network,
    /// The two nodes, in the order [`Role::of`] gives: seller and buyer, or opener and receiver.
    pub nodes: [PublicKey; 2],
    /// How it ended.
    pub result: OutcomeResult,
    /// For [`OutcomeResult::ClosedEarly`] only: who closed.
    pub closer: Option<ClosedBy>,
    /// The block that confirmed the funding transaction, as the author's node saw it.
    pub funding_height: Option<u32>,
    /// The block that confirmed the close, as the author's node saw it.
    pub close_height: Option<u32>,
    /// The funding outpoint `txid:vout`, for an announced channel only.
    pub outpoint: Option<String>,
    /// The instance that coordinated the deal, 64 lower-case hex.
    pub instance: Option<String>,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_outpoint(s: &str) -> bool {
    match s.split_once(':') {
        Some((txid, vout)) => {
            is_lower_hex(txid, 64)
                && !vout.is_empty()
                && vout.len() <= 10
                && vout.bytes().all(|c| c.is_ascii_digit())
                && (vout.len() == 1 || !vout.starts_with('0'))
                && vout.parse::<u32>().is_ok()
        }
        None => false,
    }
}

/// A canonical decimal block height.
fn height(s: &str) -> Result<u32, OutcomeError> {
    let canonical = !s.is_empty()
        && s.len() <= 10
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if !canonical {
        return refuse("height");
    }
    s.parse().map_err(|_| OutcomeError("height"))
}

/// Every tag named `name`.
fn tags<'a>(event: &'a Event, name: &'static str) -> Vec<&'a [String]> {
    event
        .tags
        .iter()
        .map(|t| t.as_slice())
        .filter(|s| s.first().map(String::as_str) == Some(name))
        .collect()
}

/// The values of the one tag named `name`, which must have between `least` and `most` of them.
/// `None` when there is no such tag.
fn optional<'a>(
    event: &'a Event,
    name: &'static str,
    least: usize,
    most: usize,
) -> Result<Option<&'a [String]>, OutcomeError> {
    match tags(event, name).as_slice() {
        [] => Ok(None),
        [tag] if (least..=most).contains(&(tag.len() - 1)) => Ok(Some(&tag[1..])),
        _ => refuse(name),
    }
}

fn required<'a>(event: &'a Event, name: &'static str) -> Result<&'a str, OutcomeError> {
    match optional(event, name, 1, 1)? {
        Some(values) => Ok(&values[0]),
        None => refuse(name),
    }
}

impl Outcome {
    /// The node with `role`, if the deal has that role.
    pub fn node(&self, role: Role) -> Option<PublicKey> {
        let roles = Role::of(self.deal);
        roles
            .iter()
            .position(|r| *r == role)
            .map(|place| self.nodes[place])
    }

    /// Checks that the parts fit together: the subject's form, two different nodes, a result
    /// for this kind of deal, a closer exactly when it closed early, heights in order, and the
    /// outpoint's and the instance's forms.
    pub fn validate(&self) -> Result<(), OutcomeError> {
        if !is_lower_hex(&self.subject, 64) {
            return refuse("x");
        }
        if self.nodes[0] == self.nodes[1] {
            return refuse("the two nodes are one");
        }
        if !self.result.fits(self.deal) {
            return refuse("result");
        }
        match (self.result, self.closer) {
            (OutcomeResult::ClosedEarly, Some(ClosedBy::Unknown)) => {}
            (OutcomeResult::ClosedEarly, Some(ClosedBy::Party(role)))
                if Role::of(self.deal).contains(&role) => {}
            (OutcomeResult::ClosedEarly, _) => return refuse("closer"),
            (_, Some(_)) => return refuse("closer"),
            (_, None) => {}
        }
        match (self.funding_height, self.close_height) {
            (None, Some(_)) => return refuse("height"),
            (Some(funding), Some(close)) if close < funding => return refuse("height"),
            _ => {}
        }
        if self.outpoint.as_deref().is_some_and(|o| !valid_outpoint(o)) {
            return refuse("outpoint");
        }
        if self
            .instance
            .as_deref()
            .is_some_and(|i| !is_lower_hex(i, 64))
        {
            return refuse("instance");
        }
        Ok(())
    }

    /// The unsigned event, with `binding` (the author's node binding event as JSON, or empty for
    /// an instance) as its content. The caller signs it with the author's liquidity identity and
    /// dates it at the end of its run, so the same outcome sent twice is the same event.
    pub fn to_event_builder(&self, binding: &str) -> Result<EventBuilder, OutcomeError> {
        self.validate()?;
        let one = |name: &str, value: String| Tag::custom(name, vec![value]);
        let mut tags = vec![
            one("k", self.deal.as_str().to_string()),
            one("x", self.subject.clone()),
            one("network", self.network.as_str().to_string()),
        ];
        for (node, role) in self.nodes.iter().zip(Role::of(self.deal)) {
            tags.push(Tag::custom(
                "n",
                vec![node.to_string(), role.as_str().to_string()],
            ));
        }
        tags.push(one("result", self.result.as_str().to_string()));
        if let Some(closer) = self.closer {
            let named = match closer {
                ClosedBy::Party(role) => role.as_str(),
                ClosedBy::Unknown => "unknown",
            };
            tags.push(one("closer", named.to_string()));
        }
        if let Some(funding) = self.funding_height {
            let mut values = vec![funding.to_string()];
            values.extend(self.close_height.map(|h| h.to_string()));
            tags.push(Tag::custom("height", values));
        }
        if let Some(outpoint) = &self.outpoint {
            tags.push(one("outpoint", outpoint.clone()));
        }
        if let Some(instance) = &self.instance {
            tags.push(one("instance", instance.clone()));
        }
        Ok(EventBuilder::new(Kind::Custom(KIND_LIQUIDITY_OUTCOME), binding).tags(tags))
    }

    /// Reads and checks an outcome event: its own id and signature, the kind, each tag at most
    /// once with canonical values (`n` exactly twice, in role order), and
    /// [`Outcome::validate`]. Tags it does not know are passed over. Who wrote it is a separate
    /// check ([`Outcome::author_node`]).
    pub fn from_event(event: &Event) -> Result<Self, OutcomeError> {
        event
            .verify()
            .map_err(|_| OutcomeError("event signature"))?;
        if event.kind != Kind::Custom(KIND_LIQUIDITY_OUTCOME) {
            return refuse("kind");
        }
        let deal = match required(event, "k")? {
            "lease" => Deal::Lease,
            "ring" => Deal::Ring,
            _ => return refuse("k"),
        };
        let subject = required(event, "x")?.to_string();
        let network =
            Network::from_str(required(event, "network")?).map_err(|_| OutcomeError("network"))?;
        let named = tags(event, "n");
        let roles = Role::of(deal);
        if named.len() != 2 {
            return refuse("n");
        }
        let mut nodes = Vec::with_capacity(2);
        for (tag, role) in named.iter().zip(roles) {
            if tag.len() != 3 || Role::parse(&tag[2]) != Some(role) || !is_lower_hex(&tag[1], 66) {
                return refuse("n");
            }
            nodes.push(PublicKey::from_str(&tag[1]).map_err(|_| OutcomeError("n"))?);
        }
        let result =
            OutcomeResult::parse(required(event, "result")?).ok_or(OutcomeError("result"))?;
        let closer = match optional(event, "closer", 1, 1)? {
            None => None,
            Some(values) if values[0] == "unknown" => Some(ClosedBy::Unknown),
            Some(values) => Some(ClosedBy::Party(
                Role::parse(&values[0]).ok_or(OutcomeError("closer"))?,
            )),
        };
        let (funding_height, close_height) = match optional(event, "height", 1, 2)? {
            None => (None, None),
            Some(values) => (
                Some(height(&values[0])?),
                values.get(1).map(|h| height(h)).transpose()?,
            ),
        };
        let outpoint = optional(event, "outpoint", 1, 1)?.map(|values| values[0].clone());
        let instance = optional(event, "instance", 1, 1)?.map(|values| values[0].clone());
        let outcome = Outcome {
            deal,
            subject,
            network,
            nodes: [nodes[0], nodes[1]],
            result,
            closer,
            funding_height,
            close_height,
            outpoint,
            instance,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// The role of the node `event`'s author is bound to, by the binding in the event's content:
    /// a binding of the author's key to one of the outcome's two nodes, on its network, not dated
    /// in the future at `now`. Refused when the content binds the author to neither.
    pub fn author_node(&self, event: &Event, now: u64) -> Result<Role, OutcomeError> {
        let author = event.pubkey.to_hex();
        for (node, role) in self.nodes.iter().zip(Role::of(self.deal)) {
            if check_binding(&event.content, node, self.network, &author, now).is_ok() {
                return Ok(role);
            }
        }
        refuse("the author is bound to neither node")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_binding::{
        sign_ln_message, Action as BindingAction, SignedStatement, Statement,
    };
    use nostr_sdk::prelude::{FinalizeEvent, Keys};
    use secp256k1::{Secp256k1, SecretKey};

    const NOW: u64 = 1_794_800_000;

    fn secret(n: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = n;
        SecretKey::from_slice(&b).expect("key")
    }

    fn node(n: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret(n))
    }

    fn binding(nostr: &Keys, node_n: u8) -> String {
        let statement = Statement::new(
            BindingAction::Bind,
            Network::Regtest,
            &nostr.public_key().to_hex(),
            node(node_n),
            NOW - 60,
        )
        .expect("statement");
        let node_signature = sign_ln_message(statement.text().as_bytes(), &secret(node_n));
        SignedStatement {
            statement,
            node_signature,
        }
        .to_event_builder()
        .finalize(nostr)
        .expect("signs")
        .as_json()
    }

    fn closed_early() -> Outcome {
        Outcome {
            deal: Deal::Lease,
            subject: "ab".repeat(32),
            network: Network::Regtest,
            nodes: [node(1), node(2)],
            result: OutcomeResult::ClosedEarly,
            closer: Some(ClosedBy::Party(Role::Seller)),
            funding_height: Some(200),
            close_height: Some(250),
            outpoint: Some(format!("{}:1", "cd".repeat(32))),
            instance: Some("ef".repeat(32)),
        }
    }

    fn signed(outcome: &Outcome, author: &Keys, content: &str) -> Event {
        outcome
            .to_event_builder(content)
            .expect("valid")
            .finalize(author)
            .expect("signs")
    }

    /// The outcome's event with its tags bent by `bend`, signed again.
    fn bent(outcome: &Outcome, bend: impl Fn(&mut Vec<Vec<String>>)) -> Event {
        let event = signed(outcome, &Keys::generate(), "");
        let mut all: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        bend(&mut all);
        let tags: Vec<Tag> = all
            .into_iter()
            .map(|t| Tag::parse(t).expect("tag"))
            .collect();
        EventBuilder::new(Kind::Custom(KIND_LIQUIDITY_OUTCOME), "")
            .tags(tags)
            .finalize(&Keys::generate())
            .expect("signs")
    }

    #[test]
    fn an_outcome_round_trips_and_names_its_authors_node() {
        let buyer = Keys::generate();
        let outcome = closed_early();
        let event = signed(&outcome, &buyer, &binding(&buyer, 2));
        assert_eq!(event.kind, Kind::Custom(KIND_LIQUIDITY_OUTCOME));
        assert_eq!(Outcome::from_event(&event), Ok(outcome.clone()));
        assert_eq!(outcome.author_node(&event, NOW), Ok(Role::Buyer));
        assert_eq!(outcome.node(Role::Seller), Some(node(1)));

        // Signed by a key the binding does not name, or with a binding of a third node.
        let impostor = signed(&outcome, &Keys::generate(), &binding(&buyer, 2));
        assert!(outcome.author_node(&impostor, NOW).is_err());
        let stranger = Keys::generate();
        let elsewhere = signed(&outcome, &stranger, &binding(&stranger, 3));
        assert!(outcome.author_node(&elsewhere, NOW).is_err());
        let empty = signed(&outcome, &stranger, "");
        assert!(outcome.author_node(&empty, NOW).is_err());
    }

    #[test]
    fn a_ring_edge_has_an_opener_and_a_receiver_and_ring_results_only() {
        let edge = Outcome {
            deal: Deal::Ring,
            result: OutcomeResult::Missing,
            closer: None,
            ..closed_early()
        };
        let read = Outcome::from_event(&signed(&edge, &Keys::generate(), "")).expect("read");
        assert_eq!(read.node(Role::Opener), Some(node(1)));
        assert_eq!(read.node(Role::Seller), None);
        for wrong in [
            Outcome {
                result: OutcomeResult::Kept,
                ..edge.clone()
            },
            Outcome {
                deal: Deal::Lease,
                ..edge.clone()
            },
        ] {
            assert!(wrong.validate().is_err(), "{wrong:?}");
        }
    }

    #[test]
    fn parts_that_do_not_fit_are_refused() {
        let good = closed_early();
        let wrong = [
            Outcome {
                subject: "AB".repeat(32),
                ..good.clone()
            },
            Outcome {
                nodes: [node(1), node(1)],
                ..good.clone()
            },
            Outcome {
                closer: None,
                ..good.clone()
            },
            Outcome {
                result: OutcomeResult::Kept,
                ..good.clone()
            },
            Outcome {
                closer: Some(ClosedBy::Party(Role::Opener)),
                ..good.clone()
            },
            Outcome {
                funding_height: None,
                ..good.clone()
            },
            Outcome {
                close_height: Some(100),
                ..good.clone()
            },
            Outcome {
                outpoint: Some("cd:1".into()),
                ..good.clone()
            },
            Outcome {
                instance: Some("zz".into()),
                ..good.clone()
            },
        ];
        for outcome in wrong {
            assert!(outcome.validate().is_err(), "{outcome:?}");
            assert!(outcome.to_event_builder("").is_err());
        }
    }

    #[test]
    fn events_are_read_strictly() {
        let good = closed_early();
        assert!(Outcome::from_event(&bent(&good, |_| {})).is_ok());
        // An unknown tag is passed over.
        assert!(
            Outcome::from_event(&bent(&good, |t| t.push(vec!["client".into(), "x".into()])))
                .is_ok()
        );
        type Bend = Box<dyn Fn(&mut Vec<Vec<String>>)>;
        let cases: Vec<Bend> = vec![
            Box::new(|t| t.retain(|t| t[0] != "k")),
            Box::new(|t| t.push(vec!["k".into(), "lease".into()])),
            Box::new(|t| t.retain(|t| t[0] != "result")),
            Box::new(|t| {
                for tag in t.iter_mut().filter(|t| t[0] == "result") {
                    tag[1] = "great".into();
                }
            }),
            // The roles out of order, a third node, a missing one.
            Box::new(|t| t.retain(|t| !(t[0] == "n" && t[2] == "buyer"))),
            Box::new(|t| t.push(vec!["n".into(), node(3).to_string(), "buyer".into()])),
            Box::new(|t| {
                for tag in t.iter_mut().filter(|t| t[0] == "n") {
                    tag[2] = if tag[2] == "seller" {
                        "buyer"
                    } else {
                        "seller"
                    }
                    .into();
                }
            }),
            Box::new(|t| {
                for tag in t.iter_mut().filter(|t| t[0] == "height") {
                    tag[1] = "0200".into();
                }
            }),
            Box::new(|t| t.push(vec!["closer".into(), "buyer".into()])),
        ];
        for (n, bend) in cases.iter().enumerate() {
            assert!(Outcome::from_event(&bent(&good, bend)).is_err(), "case {n}");
        }
        // Another kind.
        let event = signed(&good, &Keys::generate(), "");
        let other = EventBuilder::new(Kind::Custom(38735), "")
            .tags(event.tags.iter().cloned())
            .finalize(&Keys::generate())
            .expect("signs");
        assert!(Outcome::from_event(&other).is_err());
    }
}
