//! The public ring order (bipnip draft "Liquidity rings"): the addressable event an instance
//! publishes for a creator's ring, so node runners on any relay can find it and take a slot.
//!
//! Kind [`KIND_LEASE_ORDER`] (the liquidity order kind, shared with lease orders), `d` = the order
//! id, `k` = `ring`, signed by the instance. It carries the terms and how many slots are taken.
//! It names no member: who is in a ring is shown to its members only, in the roster.
//!
//! A parsed order is the instance's word, nothing more. A member checks the roster it is later
//! sent against the terms it saw here ([`crate::ring_message::RingOffer::check_ring`] does the
//! same for the creator).

use std::str::FromStr;

use nostr_sdk::prelude::{Event, EventBuilder, Kind, Tag};
use uuid::Uuid;

use crate::lease_order::{rules_tag, KIND_LEASE_ORDER};
use crate::node_binding::Network;
use crate::ring::{RingTerms, MAX_RING_SIZE, MIN_RING_SIZE};
use crate::ring_message::{RingMessageError, RingOffer};
use crate::rules::Rules;

/// The `k` tag of a ring order.
pub const RING_ORDER_K: &str = "ring";

/// Where a ring order stands, as the instance publishes it in the `s` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RingOrderStatus {
    /// Slots are open.
    Pending,
    /// Full; the members are committing or opening.
    InProgress,
    /// Every channel was confirmed.
    Success,
    /// The window ended with some channels missing.
    Partial,
    /// Withdrawn by the creator before it was full.
    Canceled,
    /// The slots were not filled in time.
    Expired,
}

impl RingOrderStatus {
    /// The tag value.
    pub fn as_str(self) -> &'static str {
        match self {
            RingOrderStatus::Pending => "pending",
            RingOrderStatus::InProgress => "in-progress",
            RingOrderStatus::Success => "success",
            RingOrderStatus::Partial => "partial",
            RingOrderStatus::Canceled => "canceled",
            RingOrderStatus::Expired => "expired",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => RingOrderStatus::Pending,
            "in-progress" => RingOrderStatus::InProgress,
            "success" => RingOrderStatus::Success,
            "partial" => RingOrderStatus::Partial,
            "canceled" => RingOrderStatus::Canceled,
            "expired" => RingOrderStatus::Expired,
            _ => return None,
        })
    }
}

/// A ring order: a creator's ring under an instance's order id, with its status and how many
/// slots are taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingOrder {
    /// The order id the instance gave the ring.
    pub id: Uuid,
    /// Where the order stands.
    pub status: RingOrderStatus,
    /// The network every member's node must be on.
    pub network: Network,
    /// Capacity of every channel, in satoshi.
    pub capacity_sat: u64,
    /// How many members the ring has.
    pub slots: u8,
    /// How many slots are taken, the creator's included.
    pub taken: u8,
    /// Whether the channels are announced.
    pub announce: bool,
    /// Seconds members have to open once the roster is fixed.
    pub open_window_secs: u64,
    /// What each member locks at the instance until the ring ends, in satoshi; 0 for none.
    pub bond_sat: u64,
    /// Unix seconds after which open slots can no longer be taken.
    pub expires_at: u64,
    /// What every member's node must show in the public graph ([`Rules`]); the optional `rules`
    /// tag.
    pub rules: Rules,
}

fn field(what: &'static str) -> RingMessageError {
    RingMessageError::Field(what)
}

/// A canonical decimal: digits only, no leading zero, in range for `T`.
fn num<T: FromStr>(s: &str, what: &'static str) -> Result<T, RingMessageError> {
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if !canonical {
        return Err(field(what));
    }
    s.parse().map_err(|_| field(what))
}

/// The values of the one tag named `name`, which must have exactly `count` of them.
fn tag_values<'a>(
    event: &'a Event,
    name: &'static str,
    count: usize,
) -> Result<&'a [String], RingMessageError> {
    let mut found = event
        .tags
        .iter()
        .map(|t| t.as_slice())
        .filter(|s| s.first().map(String::as_str) == Some(name));
    let tag = found.next().ok_or(field(name))?;
    if found.next().is_some() || tag.len() != count + 1 {
        return Err(field(name));
    }
    Ok(&tag[1..])
}

impl RingOrder {
    /// The order an instance publishes for `offer` with `taken` slots filled. The offer must be
    /// valid.
    pub fn from_offer(
        id: Uuid,
        status: RingOrderStatus,
        taken: u8,
        offer: &RingOffer,
    ) -> Result<Self, RingMessageError> {
        offer.validate()?;
        let order = RingOrder {
            id,
            status,
            network: offer.network,
            capacity_sat: offer.capacity_sat,
            slots: offer.slots,
            taken,
            announce: offer.announce,
            open_window_secs: offer.open_window_secs,
            bond_sat: offer.bond_sat,
            expires_at: offer.expires_at,
            rules: offer.rules,
        };
        order.validate()?;
        Ok(order)
    }

    /// The terms every channel of this ring has.
    pub fn terms(&self) -> RingTerms {
        RingTerms {
            network: self.network,
            capacity_sat: self.capacity_sat,
            announce: self.announce,
            open_window_secs: self.open_window_secs,
            bond_sat: self.bond_sat,
            rules: self.rules,
        }
    }

    /// Checks the terms, the number of slots, that no more are taken than there are, that at
    /// least the creator's is, and that there is an expiry.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        self.terms().validate()?;
        if !(MIN_RING_SIZE..=MAX_RING_SIZE).contains(&usize::from(self.slots)) {
            return Err(field("slots"));
        }
        if self.taken == 0 || self.taken > self.slots {
            return Err(field("slots"));
        }
        if self.expires_at == 0 {
            return Err(field("expires_at"));
        }
        Ok(())
    }

    /// True when a slot can be taken at `now`.
    pub fn is_open(&self, now: u64) -> bool {
        self.status == RingOrderStatus::Pending && self.taken < self.slots && now < self.expires_at
    }

    /// The unsigned order event, for the instance to sign.
    pub fn to_event_builder(&self) -> EventBuilder {
        let one = |name: &str, value: String| Tag::custom(name, vec![value]);
        let rules = (!self.rules.is_none()).then(|| Tag::custom("rules", self.rules.tag_values()));
        EventBuilder::new(Kind::Custom(KIND_LEASE_ORDER), "").tags(
            [
                Tag::identifier(self.id.to_string()),
                one("k", RING_ORDER_K.to_string()),
                one("s", self.status.as_str().to_string()),
                one("network", self.network.as_str().to_string()),
                Tag::custom(
                    "slots",
                    vec![self.slots.to_string(), self.taken.to_string()],
                ),
                one("capacity", self.capacity_sat.to_string()),
                one("announce", self.announce.to_string()),
                one("window", self.open_window_secs.to_string()),
                one("bond", self.bond_sat.to_string()),
                one("expiration", self.expires_at.to_string()),
            ]
            .into_iter()
            .chain(rules),
        )
    }

    /// Reads and checks an order event: its own id and signature, the kind, `k` = `ring`,
    /// exactly one of each tag with canonical values, and [`RingOrder::validate`]. The caller
    /// decides whether it trusts the instance that signed it (`event.pubkey`).
    pub fn from_event(event: &Event) -> Result<Self, RingMessageError> {
        event.verify().map_err(|_| field("event signature"))?;
        if event.kind != Kind::Custom(KIND_LEASE_ORDER) {
            return Err(field("kind"));
        }
        if tag_values(event, "k", 1)?[0] != RING_ORDER_K {
            return Err(field("k"));
        }
        let d = &tag_values(event, "d", 1)?[0];
        let id = Uuid::parse_str(d).map_err(|_| field("d"))?;
        if id.to_string() != *d {
            return Err(field("d"));
        }
        let status = RingOrderStatus::parse(&tag_values(event, "s", 1)?[0]).ok_or(field("s"))?;
        let network = Network::from_str(&tag_values(event, "network", 1)?[0])
            .map_err(|_| field("network"))?;
        let slots = tag_values(event, "slots", 2)?;
        let announce = match tag_values(event, "announce", 1)?[0].as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(field("announce")),
        };
        let order = RingOrder {
            id,
            status,
            network,
            capacity_sat: num(&tag_values(event, "capacity", 1)?[0], "capacity")?,
            slots: num(&slots[0], "slots")?,
            taken: num(&slots[1], "slots")?,
            announce,
            open_window_secs: num(&tag_values(event, "window", 1)?[0], "window")?,
            bond_sat: num(&tag_values(event, "bond", 1)?[0], "bond")?,
            expires_at: num(&tag_values(event, "expiration", 1)?[0], "expiration")?,
            rules: rules_tag(event).map_err(|_| field("rules"))?,
        };
        order.validate()?;
        Ok(order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease_order::LeaseOrder;
    use crate::ring_message::RingSeat;
    use nostr_sdk::prelude::{FinalizeEvent, Keys};

    fn node() -> secp256k1::PublicKey {
        let mut b = [0u8; 32];
        b[31] = 1;
        secp256k1::PublicKey::from_secret_key(
            &secp256k1::Secp256k1::signing_only(),
            &secp256k1::SecretKey::from_slice(&b).expect("key"),
        )
    }

    fn offer() -> RingOffer {
        RingOffer {
            network: Network::Regtest,
            capacity_sat: 2_000_000,
            slots: 4,
            announce: true,
            open_window_secs: 48 * 3_600,
            bond_sat: 0,
            expires_at: 1_794_886_400,
            seat: RingSeat {
                node: node().to_string(),
                binding: "{}".into(),
                node_address: None,
            },
            rules: Rules::default(),
        }
    }

    fn order() -> RingOrder {
        let id = Uuid::parse_str("308e1272-d5f4-47e6-bd97-3504baea9c23").expect("uuid");
        RingOrder::from_offer(id, RingOrderStatus::Pending, 1, &offer()).expect("order")
    }

    /// The order's tags as plain strings, for tests to bend.
    fn tags(order: &RingOrder) -> Vec<Vec<String>> {
        let event = order
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        event.tags.iter().map(|t| t.as_slice().to_vec()).collect()
    }

    fn signed(kind: u16, tags: Vec<Vec<String>>) -> Event {
        let tags: Vec<Tag> = tags
            .into_iter()
            .map(|t| Tag::parse(t).expect("tag"))
            .collect();
        EventBuilder::new(Kind::Custom(kind), "")
            .tags(tags)
            .finalize(&Keys::generate())
            .expect("signs")
    }

    /// The good order with one tag's values replaced.
    fn with_tag(name: &str, values: &[&str]) -> Event {
        let mut all = tags(&order());
        let tag = all
            .iter_mut()
            .find(|t| t[0] == name)
            .expect("the order has this tag");
        tag.truncate(1);
        tag.extend(values.iter().map(|v| v.to_string()));
        signed(KIND_LEASE_ORDER, all)
    }

    #[test]
    fn an_order_round_trips_through_its_event() {
        let instance = Keys::generate();
        for status in [
            RingOrderStatus::Pending,
            RingOrderStatus::InProgress,
            RingOrderStatus::Success,
            RingOrderStatus::Partial,
            RingOrderStatus::Canceled,
            RingOrderStatus::Expired,
        ] {
            for taken in 1..=4 {
                let order = RingOrder {
                    status,
                    taken,
                    ..order()
                };
                let event = order.to_event_builder().finalize(&instance).expect("signs");
                assert_eq!(event.pubkey, instance.public_key());
                assert_eq!(RingOrder::from_event(&event), Ok(order));
            }
        }
        let private = RingOrder {
            announce: false,
            ..order()
        };
        let event = private
            .to_event_builder()
            .finalize(&instance)
            .expect("signs");
        assert_eq!(RingOrder::from_event(&event), Ok(private));
    }

    #[test]
    fn the_event_names_no_member() {
        let event = order()
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        let json = event.as_json();
        assert!(!json.contains(&offer().seat.node));
        assert_eq!(order().terms(), offer().terms());
    }

    #[test]
    fn slots_can_be_taken_only_while_pending_unfilled_and_unexpired() {
        let open = order();
        assert!(open.is_open(1_794_800_000));
        assert!(!open.is_open(open.expires_at));
        let full = RingOrder {
            taken: 4,
            ..order()
        };
        assert!(!full.is_open(1_794_800_000));
        let running = RingOrder {
            status: RingOrderStatus::InProgress,
            ..order()
        };
        assert!(!running.is_open(1_794_800_000));
    }

    #[test]
    fn the_bond_is_published_with_the_order() {
        let mut bonded = offer();
        bonded.bond_sat = 50_000;
        let order =
            RingOrder::from_offer(order().id, RingOrderStatus::Pending, 1, &bonded).expect("order");
        assert_eq!(order.bond_sat, 50_000);
        assert_eq!(order.terms(), bonded.terms());
        let event = order
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        assert_eq!(RingOrder::from_event(&event), Ok(order));
        // A bond on a ring of unannounced channels is not an order an instance may publish.
        bonded.announce = false;
        assert!(RingOrder::from_offer(order_id(), RingOrderStatus::Pending, 1, &bonded).is_err());
        // An order without the tag is from another version, and is refused.
        let mut missing = tags(&self::order());
        missing.retain(|t| t[0] != "bond");
        assert!(RingOrder::from_event(&signed(KIND_LEASE_ORDER, missing)).is_err());
    }

    fn order_id() -> Uuid {
        order().id
    }

    #[test]
    fn orders_out_of_range_are_refused() {
        let id = order().id;
        let pending = RingOrderStatus::Pending;
        assert_eq!(
            RingOrder::from_offer(id, pending, 0, &offer()),
            Err(field("slots"))
        );
        assert_eq!(
            RingOrder::from_offer(id, pending, 5, &offer()),
            Err(field("slots"))
        );
        let mut tiny = offer();
        tiny.capacity_sat = 1;
        assert!(RingOrder::from_offer(id, pending, 1, &tiny).is_err());
        let mut one = offer();
        one.slots = 1;
        assert!(RingOrder::from_offer(id, pending, 1, &one).is_err());
    }

    #[test]
    fn events_that_are_not_a_canonical_ring_order_are_refused() {
        for (name, values) in [
            ("k", vec!["lease"]),
            ("d", vec!["not-a-uuid"]),
            ("d", vec!["308E1272-D5F4-47E6-BD97-3504BAEA9C23"]),
            ("s", vec!["open"]),
            ("network", vec!["mainnet"]),
            ("slots", vec!["4"]),
            ("slots", vec!["4", "5"]),
            ("slots", vec!["4", "0"]),
            ("slots", vec!["6", "1"]),
            ("slots", vec!["04", "1"]),
            ("capacity", vec!["1"]),
            ("capacity", vec!["2000000", "5000000"]),
            ("announce", vec!["yes"]),
            ("bond", vec!["050000"]),
            ("bond", vec!["-1"]),
            ("bond", vec![]),
            ("window", vec!["59"]),
            ("window", vec!["+172800"]),
            ("expiration", vec!["0"]),
            ("expiration", vec![]),
        ] {
            let event = with_tag(name, &values);
            assert!(
                RingOrder::from_event(&event).is_err(),
                "{name} = {values:?}"
            );
        }

        // Another kind, a missing tag, a tag twice.
        assert!(RingOrder::from_event(&signed(38_383, tags(&order()))).is_err());
        let mut missing = tags(&order());
        missing.retain(|t| t[0] != "window");
        assert!(RingOrder::from_event(&signed(KIND_LEASE_ORDER, missing)).is_err());
        let mut twice = tags(&order());
        twice.push(vec!["capacity".into(), "3000000".into()]);
        assert!(RingOrder::from_event(&signed(KIND_LEASE_ORDER, twice)).is_err());

        // An event whose content was changed after signing.
        let good = order()
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        let mut value: serde_json::Value = serde_json::from_str(&good.as_json()).expect("json");
        value["content"] = serde_json::json!("changed");
        let forged = Event::from_json(value.to_string()).expect("parses");
        assert!(RingOrder::from_event(&forged).is_err());
        assert!(RingOrder::from_event(&good).is_ok());
    }

    #[test]
    fn a_ring_order_is_not_a_lease_order_and_the_other_way_round() {
        let ring = order()
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        assert!(LeaseOrder::from_event(&ring).is_err());
    }

    #[test]
    fn a_ring_orders_rules_are_its_terms_rules() {
        assert!(!tags(&order()).iter().any(|t| t[0] == "rules"));
        let mut strict = offer();
        strict.rules.min_capacity_sat = 1_000_000;
        let order =
            RingOrder::from_offer(order_id(), RingOrderStatus::Pending, 1, &strict).expect("order");
        assert_eq!(order.terms().rules, strict.rules);
        let read = RingOrder::from_event(&signed(KIND_LEASE_ORDER, tags(&order))).expect("read");
        assert_eq!(read.rules, strict.rules);
        assert_eq!(read.terms(), strict.terms());
    }
}
