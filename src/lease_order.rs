//! The public lease order (bipnip draft "Liquidity leases"): the addressable event an instance
//! publishes for a seller's offer, so buyers on any relay can find it.
//!
//! Kind [`KIND_LEASE_ORDER`], `d` = the order id, signed by the instance. The tags carry what a
//! buyer needs to price a lease and write the contract; the seller's binding is not repeated here
//! (it is its own event, kind 31735, found by the `node` tag).
//!
//! A parsed order is the instance's word, nothing more: the buyer's agent still checks the
//! seller's binding, and the seller and the instance still check the buyer's contract against
//! the offer they hold.

use std::str::FromStr;

use nostr_sdk::prelude::{Event, EventBuilder, Kind, Tag};
use secp256k1::PublicKey;
use uuid::Uuid;

use crate::lease::{LeaseTerms, MAX_CAPACITY_SAT, MIN_CAPACITY_SAT};
use crate::lease_message::{LeaseMessageError, LeaseOffer};
use crate::node_binding::Network;

/// Kind of the liquidity order event (addressable; `d` = order id; tag `k` says which sort).
pub const KIND_LEASE_ORDER: u16 = 38735;
/// The `k` tag of a lease order.
pub const LEASE_ORDER_K: &str = "lease";

/// Where a lease order stands, as the instance publishes it in the `s` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseOrderStatus {
    /// Open: a buyer can take it.
    Pending,
    /// Taken; the lease is being set up.
    InProgress,
    /// The lease is active.
    Success,
    /// Withdrawn by the seller or canceled by either party before the lease was active.
    Canceled,
    /// Nobody took it in time.
    Expired,
}

impl LeaseOrderStatus {
    /// The tag value.
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseOrderStatus::Pending => "pending",
            LeaseOrderStatus::InProgress => "in-progress",
            LeaseOrderStatus::Success => "success",
            LeaseOrderStatus::Canceled => "canceled",
            LeaseOrderStatus::Expired => "expired",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => LeaseOrderStatus::Pending,
            "in-progress" => LeaseOrderStatus::InProgress,
            "success" => LeaseOrderStatus::Success,
            "canceled" => LeaseOrderStatus::Canceled,
            "expired" => LeaseOrderStatus::Expired,
            _ => return None,
        })
    }
}

/// A lease order: a seller's offer under an instance's order id and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseOrder {
    /// The order id the instance gave the offer.
    pub id: Uuid,
    /// Where the order stands.
    pub status: LeaseOrderStatus,
    /// The network the seller's node is on.
    pub network: Network,
    /// The seller's node key.
    pub seller_node: PublicKey,
    /// Smallest channel the seller opens, in satoshi.
    pub min_capacity_sat: u64,
    /// Largest channel the seller opens, in satoshi.
    pub max_capacity_sat: u64,
    /// As [`LeaseTerms::duration_blocks`].
    pub duration_blocks: u32,
    /// As [`LeaseTerms::fee_base_sat`].
    pub fee_base_sat: u64,
    /// As [`LeaseTerms::fee_ppm`].
    pub fee_ppm: u32,
    /// As [`LeaseTerms::upfront_percent`].
    pub upfront_percent: u8,
    /// As [`LeaseTerms::min_confirmations`].
    pub min_confirmations: u32,
    /// As [`LeaseTerms::announce`].
    pub announce: bool,
    /// Unix seconds after which the order can no longer be taken.
    pub expires_at: u64,
    /// The bond the buyer locks at the instance while the lease is set up, in satoshi; 0 for none.
    pub bond_sat: u64,
}

fn field(what: &'static str) -> LeaseMessageError {
    LeaseMessageError::Field(what)
}

/// A canonical decimal: digits only, no leading zero, in range for `T`.
fn num<T: FromStr>(s: &str, what: &'static str) -> Result<T, LeaseMessageError> {
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
) -> Result<&'a [String], LeaseMessageError> {
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

impl LeaseOrder {
    /// The order an instance publishes for `offer`. The offer must be valid.
    pub fn from_offer(
        id: Uuid,
        status: LeaseOrderStatus,
        offer: &LeaseOffer,
    ) -> Result<Self, LeaseMessageError> {
        offer.validate()?;
        Ok(LeaseOrder {
            id,
            status,
            network: offer.network,
            seller_node: offer.seller_node_key()?,
            min_capacity_sat: offer.min_capacity_sat,
            max_capacity_sat: offer.max_capacity_sat,
            duration_blocks: offer.duration_blocks,
            fee_base_sat: offer.fee_base_sat,
            fee_ppm: offer.fee_ppm,
            upfront_percent: offer.upfront_percent,
            min_confirmations: offer.min_confirmations,
            announce: offer.announce,
            expires_at: offer.expires_at,
            bond_sat: offer.bond_sat,
        })
    }

    fn terms_unchecked(&self, capacity_sat: u64) -> LeaseTerms {
        LeaseTerms {
            capacity_sat,
            duration_blocks: self.duration_blocks,
            fee_base_sat: self.fee_base_sat,
            fee_ppm: self.fee_ppm,
            upfront_percent: self.upfront_percent,
            min_confirmations: self.min_confirmations,
            announce: self.announce,
        }
    }

    /// Checks the capacity range, the terms at both ends of it, and that there is an expiry: the
    /// same rules an offer passes.
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        if self.min_capacity_sat > self.max_capacity_sat
            || self.min_capacity_sat < MIN_CAPACITY_SAT
            || self.max_capacity_sat > MAX_CAPACITY_SAT
        {
            return Err(field("capacity range"));
        }
        self.terms_unchecked(self.min_capacity_sat).validate()?;
        self.terms_unchecked(self.max_capacity_sat).validate()?;
        if self.expires_at == 0 {
            return Err(field("expires_at"));
        }
        let bond_ok = crate::bond::bond_amount_ok(self.bond_sat)
            && (self.bond_sat == 0 || (self.announce && self.bond_sat <= self.min_capacity_sat));
        if !bond_ok {
            return Err(field("bond"));
        }
        Ok(())
    }

    /// The terms of a lease of `capacity_sat` under this order; refused outside the range. A
    /// buyer writes its contract from these.
    pub fn terms_for(&self, capacity_sat: u64) -> Result<LeaseTerms, LeaseMessageError> {
        if !(self.min_capacity_sat..=self.max_capacity_sat).contains(&capacity_sat) {
            return Err(field("capacity outside the offer"));
        }
        let terms = self.terms_unchecked(capacity_sat);
        terms.validate()?;
        Ok(terms)
    }

    /// True when the order can be taken at `now`.
    pub fn is_open(&self, now: u64) -> bool {
        self.status == LeaseOrderStatus::Pending && now < self.expires_at
    }

    /// The unsigned order event, for the instance to sign.
    pub fn to_event_builder(&self) -> EventBuilder {
        let one = |name: &str, value: String| Tag::custom(name, vec![value]);
        let two = |name: &str, a: String, b: String| Tag::custom(name, vec![a, b]);
        EventBuilder::new(Kind::Custom(KIND_LEASE_ORDER), "").tags([
            Tag::identifier(self.id.to_string()),
            one("k", LEASE_ORDER_K.to_string()),
            one("s", self.status.as_str().to_string()),
            one("node", self.seller_node.to_string()),
            one("network", self.network.as_str().to_string()),
            two(
                "capacity",
                self.min_capacity_sat.to_string(),
                self.max_capacity_sat.to_string(),
            ),
            one("duration", self.duration_blocks.to_string()),
            two(
                "fee",
                self.fee_base_sat.to_string(),
                self.fee_ppm.to_string(),
            ),
            one("split", self.upfront_percent.to_string()),
            one("confs", self.min_confirmations.to_string()),
            one("announce", self.announce.to_string()),
            one("bond", self.bond_sat.to_string()),
            one("expiration", self.expires_at.to_string()),
        ])
    }

    /// Reads and checks an order event: its own id and signature, the kind, `k` = `lease`,
    /// exactly one of each tag with canonical values, and [`LeaseOrder::validate`]. The caller
    /// decides whether it trusts the instance that signed it (`event.pubkey`).
    pub fn from_event(event: &Event) -> Result<Self, LeaseMessageError> {
        event.verify().map_err(|_| field("event signature"))?;
        if event.kind != Kind::Custom(KIND_LEASE_ORDER) {
            return Err(field("kind"));
        }
        if tag_values(event, "k", 1)?[0] != LEASE_ORDER_K {
            return Err(field("k"));
        }
        let d = &tag_values(event, "d", 1)?[0];
        let id = Uuid::parse_str(d).map_err(|_| field("d"))?;
        if id.to_string() != *d {
            return Err(field("d"));
        }
        let status = LeaseOrderStatus::parse(&tag_values(event, "s", 1)?[0]).ok_or(field("s"))?;
        let node = &tag_values(event, "node", 1)?[0];
        let lower_hex =
            node.len() == 66 && node.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        if !lower_hex {
            return Err(field("node"));
        }
        let seller_node = PublicKey::from_str(node).map_err(|_| field("node"))?;
        let network = Network::from_str(&tag_values(event, "network", 1)?[0])
            .map_err(|_| field("network"))?;
        let capacity = tag_values(event, "capacity", 2)?;
        let fee = tag_values(event, "fee", 2)?;
        let announce = match tag_values(event, "announce", 1)?[0].as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(field("announce")),
        };
        let order = LeaseOrder {
            id,
            status,
            network,
            seller_node,
            min_capacity_sat: num(&capacity[0], "capacity")?,
            max_capacity_sat: num(&capacity[1], "capacity")?,
            duration_blocks: num(&tag_values(event, "duration", 1)?[0], "duration")?,
            fee_base_sat: num(&fee[0], "fee")?,
            fee_ppm: num(&fee[1], "fee")?,
            upfront_percent: num(&tag_values(event, "split", 1)?[0], "split")?,
            min_confirmations: num(&tag_values(event, "confs", 1)?[0], "confs")?,
            announce,
            expires_at: num(&tag_values(event, "expiration", 1)?[0], "expiration")?,
            bond_sat: num(&tag_values(event, "bond", 1)?[0], "bond")?,
        };
        order.validate()?;
        Ok(order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{FinalizeEvent, Keys};
    use secp256k1::{Secp256k1, SecretKey};

    fn node(n: u8) -> PublicKey {
        let mut b = [0u8; 32];
        b[31] = n;
        PublicKey::from_secret_key(
            &Secp256k1::signing_only(),
            &SecretKey::from_slice(&b).expect("key"),
        )
    }

    fn offer() -> LeaseOffer {
        LeaseOffer {
            network: Network::Regtest,
            seller_node: node(1).to_string(),
            binding: "{}".into(),
            min_capacity_sat: 1_000_000,
            max_capacity_sat: 5_000_000,
            duration_blocks: 4_320,
            fee_base_sat: 1_000,
            fee_ppm: 2_500,
            upfront_percent: 50,
            min_confirmations: 3,
            announce: true,
            expires_at: 1_794_886_400,
            bond_sat: 0,
        }
    }

    fn order() -> LeaseOrder {
        let id = Uuid::parse_str("308e1272-d5f4-47e6-bd97-3504baea9c23").expect("uuid");
        LeaseOrder::from_offer(id, LeaseOrderStatus::Pending, &offer()).expect("order")
    }

    /// The order's tags as plain strings, for tests to bend.
    fn tags(order: &LeaseOrder) -> Vec<Vec<String>> {
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
            LeaseOrderStatus::Pending,
            LeaseOrderStatus::InProgress,
            LeaseOrderStatus::Success,
            LeaseOrderStatus::Canceled,
            LeaseOrderStatus::Expired,
        ] {
            let order = LeaseOrder { status, ..order() };
            let event = order.to_event_builder().finalize(&instance).expect("signs");
            assert_eq!(event.pubkey, instance.public_key());
            assert_eq!(LeaseOrder::from_event(&event), Ok(order));
        }
        let private = LeaseOrder {
            announce: false,
            ..order()
        };
        let event = private
            .to_event_builder()
            .finalize(&instance)
            .expect("signs");
        assert_eq!(LeaseOrder::from_event(&event), Ok(private));
    }

    #[test]
    fn the_tags_are_the_drafts() {
        let expected: Vec<Vec<String>> = [
            vec!["d", "308e1272-d5f4-47e6-bd97-3504baea9c23"],
            vec!["k", "lease"],
            vec!["s", "pending"],
            vec![
                "node",
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ],
            vec!["network", "regtest"],
            vec!["capacity", "1000000", "5000000"],
            vec!["duration", "4320"],
            vec!["fee", "1000", "2500"],
            vec!["split", "50"],
            vec!["confs", "3"],
            vec!["announce", "true"],
            vec!["bond", "0"],
            vec!["expiration", "1794886400"],
        ]
        .into_iter()
        .map(|t| t.into_iter().map(String::from).collect())
        .collect();
        assert_eq!(tags(&order()), expected);
    }

    #[test]
    fn a_buyer_prices_a_lease_from_the_order_exactly_as_the_offer_does() {
        let (order, offer) = (order(), offer());
        for capacity in [1_000_000, 2_000_000, 5_000_000] {
            assert_eq!(order.terms_for(capacity), offer.terms_for(capacity));
        }
        assert!(order.terms_for(999_999).is_err());
        assert!(order.terms_for(5_000_001).is_err());
        assert!(order.is_open(order.expires_at - 1));
        assert!(!order.is_open(order.expires_at));
        let taken = LeaseOrder {
            status: LeaseOrderStatus::InProgress,
            ..order
        };
        assert!(!taken.is_open(0));
    }

    #[test]
    fn an_invalid_offer_makes_no_order() {
        let mut bad = offer();
        bad.upfront_percent = 0;
        let id = Uuid::new_v4();
        assert!(LeaseOrder::from_offer(id, LeaseOrderStatus::Pending, &bad).is_err());
    }

    #[test]
    fn the_bond_is_published_with_the_order() {
        let mut bonded = offer();
        bonded.bond_sat = 50_000;
        let order =
            LeaseOrder::from_offer(order().id, LeaseOrderStatus::Pending, &bonded).expect("order");
        assert_eq!(order.bond_sat, 50_000);
        let event = order
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        assert_eq!(LeaseOrder::from_event(&event), Ok(order.clone()));
        // A bond on an unannounced channel is refused, in an offer and in an event.
        let private = LeaseOrder {
            announce: false,
            ..order
        };
        assert!(private.validate().is_err());
        let event = private
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        assert!(LeaseOrder::from_event(&event).is_err());
        // An order without the tag is from another version, and is refused.
        let mut missing = tags(&self::order());
        missing.retain(|t| t[0] != "bond");
        assert!(LeaseOrder::from_event(&signed(KIND_LEASE_ORDER, missing)).is_err());
    }

    #[test]
    fn events_that_are_not_well_formed_lease_orders_are_refused() {
        let good = tags(&order());
        assert!(LeaseOrder::from_event(&signed(KIND_LEASE_ORDER, good.clone())).is_ok());
        assert_eq!(
            LeaseOrder::from_event(&signed(38383, good.clone())),
            Err(field("kind"))
        );
        assert_eq!(
            LeaseOrder::from_event(&with_tag("k", &["ring"])),
            Err(field("k"))
        );

        // (tag, replacement values, the field the refusal names)
        let cases: [(&str, &[&str], &str); 22] = [
            ("d", &["not-a-uuid"], "d"),
            ("d", &["308E1272-D5F4-47E6-BD97-3504BAEA9C23"], "d"),
            ("s", &["open"], "s"),
            ("s", &["Pending"], "s"),
            ("node", &["02"], "node"),
            (
                "node",
                &["0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"],
                "node",
            ),
            ("network", &["mainnet"], "network"),
            ("capacity", &["1000000"], "capacity"),
            ("capacity", &["1000000", "5000000", "1"], "capacity"),
            ("capacity", &["01000000", "5000000"], "capacity"),
            ("capacity", &["5000000", "1000000"], "capacity range"),
            ("capacity", &["1", "5000000"], "capacity range"),
            ("duration", &["4320 "], "duration"),
            ("duration", &["-1"], "duration"),
            ("fee", &["1000"], "fee"),
            ("fee", &["1000", "2.5"], "fee"),
            ("fee", &["1000", "4294967296"], "fee"),
            ("split", &["256"], "split"),
            ("confs", &["0x3"], "confs"),
            ("announce", &["yes"], "announce"),
            ("announce", &["True"], "announce"),
            ("expiration", &["0"], "expires_at"),
        ];
        for (name, values, names) in cases {
            assert_eq!(
                LeaseOrder::from_event(&with_tag(name, values)),
                Err(field(names)),
                "{name} = {values:?}"
            );
        }
        // Out-of-range terms are refused by the same rules an offer passes.
        let out_of_range: [(&str, &[&str]); 5] = [
            ("split", &["0"]),
            ("split", &["101"]),
            ("duration", &["0"]),
            ("confs", &["0"]),
            ("fee", &["0", "0"]),
        ];
        for (name, values) in out_of_range {
            assert!(
                matches!(
                    LeaseOrder::from_event(&with_tag(name, values)),
                    Err(LeaseMessageError::Lease(_))
                ),
                "{name} = {values:?}"
            );
        }

        // A missing tag and a repeated tag.
        for name in [
            "d",
            "k",
            "s",
            "node",
            "network",
            "capacity",
            "duration",
            "fee",
            "split",
            "confs",
            "announce",
            "expiration",
        ] {
            let missing: Vec<_> = good.iter().filter(|t| t[0] != name).cloned().collect();
            assert!(
                LeaseOrder::from_event(&signed(KIND_LEASE_ORDER, missing)).is_err(),
                "missing {name}"
            );
            let mut twice = good.clone();
            let again = good.iter().find(|t| t[0] == name).expect("tag").clone();
            twice.push(again);
            assert!(
                LeaseOrder::from_event(&signed(KIND_LEASE_ORDER, twice)).is_err(),
                "repeated {name}"
            );
        }
    }

    #[test]
    fn a_tampered_event_fails_its_signature() {
        let event = order()
            .to_event_builder()
            .finalize(&Keys::generate())
            .expect("signs");
        let json = event.as_json().replacen("\"2500\"", "\"1\"", 1);
        let tampered = Event::from_json(json).expect("still parses");
        assert_eq!(
            LeaseOrder::from_event(&tampered),
            Err(field("event signature"))
        );
    }
}
