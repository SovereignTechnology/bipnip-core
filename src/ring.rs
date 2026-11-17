//! Liquidity rings (bipnip draft "Liquidity rings"): what a ring's members agree on, and the
//! roster they all refer to.
//!
//! N node runners (2 to 5) each open one channel of the same capacity to the next member and
//! receive one from the previous member; the last opens to the first. No money changes hands.
//!
//! The roster's canonical text fixes the terms and the order of the members. Its SHA-256 is the
//! ring id, which every member signs before anyone opens, so no member can be shown a different
//! ring than the others.
//!
//! Everything here is pure: no node, no relay, no clock.

use std::fmt;

use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::lease::{MAX_CAPACITY_SAT, MIN_CAPACITY_SAT};
use crate::node_binding::Network;

/// Fewest members a ring may have: two nodes opening a channel to each other.
pub const MIN_RING_SIZE: usize = 2;
/// Most members a ring may have.
pub const MAX_RING_SIZE: usize = 5;
/// Shortest time members may be given to open their channel: an hour.
pub const MIN_OPEN_WINDOW_SECS: u64 = 3_600;
/// Longest time members may be given to open their channel: two weeks.
pub const MAX_OPEN_WINDOW_SECS: u64 = 14 * 24 * 3_600;
/// Shortest window on regtest: a minute, so a test can run a window to its end.
pub const MIN_OPEN_WINDOW_SECS_REGTEST: u64 = 60;
/// Longest window a ring with bonds may have: 48 hours. A bond is a payment held at the
/// instance's node for the whole window, and a held payment ties up liquidity on every node in
/// its path.
pub const MAX_BONDED_WINDOW_SECS: u64 = 48 * 3_600;

/// Why ring terms or a roster were rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingError {
    /// A term is outside its allowed range; the name says which.
    Term(&'static str),
    /// The roster is not in canonical form or its members do not make a ring; the name says how.
    Roster(&'static str),
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RingError::Term(why) => write!(f, "invalid ring term: {why}"),
            RingError::Roster(why) => write!(f, "invalid ring roster: {why}"),
        }
    }
}

impl std::error::Error for RingError {}

/// What every channel of a ring looks like, and how long members have to open theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingTerms {
    /// The network every member's node is on.
    pub network: Network,
    /// Capacity of every channel, in satoshi.
    pub capacity_sat: u64,
    /// Whether the channels are announced.
    pub announce: bool,
    /// Seconds members have to open their channel, counted from the roster's `created_at`.
    pub open_window_secs: u64,
    /// What each member locks at the instance until the ring ends, in satoshi; 0 for none. A
    /// member whose channel is missing when the window ends loses it to the member it failed.
    pub bond_sat: u64,
}

impl RingTerms {
    /// Checks every term's range.
    pub fn validate(&self) -> Result<(), RingError> {
        if !(MIN_CAPACITY_SAT..=MAX_CAPACITY_SAT).contains(&self.capacity_sat) {
            return Err(RingError::Term("capacity_sat"));
        }
        let shortest = match self.network {
            Network::Regtest => MIN_OPEN_WINDOW_SECS_REGTEST,
            _ => MIN_OPEN_WINDOW_SECS,
        };
        if !(shortest..=MAX_OPEN_WINDOW_SECS).contains(&self.open_window_secs) {
            return Err(RingError::Term("open_window_secs"));
        }
        if self.bond_sat > 0 {
            // A bond is taken only on what the instance's own node can see, so the channels
            // must be announced; and it is held for the whole window, so the window is short.
            if !self.announce {
                return Err(RingError::Term("a bond needs announced channels"));
            }
            if self.open_window_secs > MAX_BONDED_WINDOW_SECS {
                return Err(RingError::Term("a bond needs a window of 48 hours or less"));
            }
            if self.bond_sat > self.capacity_sat || !crate::bond::bond_amount_ok(self.bond_sat) {
                return Err(RingError::Term("bond_sat"));
            }
        }
        Ok(())
    }
}

/// A ring: its terms and its members in opening order. Member `i` opens a channel to member
/// `i + 1`, and the last member to the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring {
    /// The terms.
    pub terms: RingTerms,
    /// The members' node keys, in opening order.
    pub members: Vec<PublicKey>,
    /// Unix seconds when the instance fixed the roster; the open window starts here.
    pub created_at: u64,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_num(s: &str, what: &'static str) -> Result<u64, RingError> {
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if !canonical {
        return Err(RingError::Roster(what));
    }
    s.parse().map_err(|_| RingError::Roster(what))
}

impl Ring {
    /// Checks the terms, the number of members, and that no node is in the ring twice.
    pub fn validate(&self) -> Result<(), RingError> {
        self.terms.validate()?;
        if !(MIN_RING_SIZE..=MAX_RING_SIZE).contains(&self.members.len()) {
            return Err(RingError::Roster("number of members"));
        }
        for (i, member) in self.members.iter().enumerate() {
            if self.members[..i].contains(member) {
                return Err(RingError::Roster("a node is in the ring twice"));
            }
        }
        Ok(())
    }

    /// The canonical text (ASCII, no spaces; members separated by commas, in opening order):
    ///
    /// ```text
    /// bipnip-ring:v1:<network>:<capacity_sat>:<announce 0|1>:<open_window_secs>:<bond_sat>:
    /// <created_at>:<node 1>,<node 2>,…,<node N>
    /// ```
    pub fn text(&self) -> String {
        let members: Vec<String> = self.members.iter().map(ToString::to_string).collect();
        format!(
            "bipnip-ring:v1:{}:{}:{}:{}:{}:{}:{}",
            self.terms.network.as_str(),
            self.terms.capacity_sat,
            u8::from(self.terms.announce),
            self.terms.open_window_secs,
            self.terms.bond_sat,
            self.created_at,
            members.join(",")
        )
    }

    /// The ring id: SHA-256 of the canonical text, lower-case hex.
    pub fn id(&self) -> String {
        Sha256::digest(self.text().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Parses canonical text. Anything not byte-identical to [`Ring::text`]'s output for the
    /// parsed values, or failing [`Ring::validate`], is rejected.
    pub fn parse(text: &str) -> Result<Self, RingError> {
        let f: Vec<&str> = text.split(':').collect();
        if f.len() != 9 || f[0] != "bipnip-ring" || f[1] != "v1" {
            return Err(RingError::Roster("header"));
        }
        let network = f[2]
            .parse::<Network>()
            .map_err(|_| RingError::Roster("network"))?;
        let announce = match f[4] {
            "0" => false,
            "1" => true,
            _ => return Err(RingError::Roster("announce")),
        };
        let mut members = Vec::new();
        for node in f[8].split(',') {
            if !is_lower_hex(node, 66) {
                return Err(RingError::Roster("member"));
            }
            members.push(node.parse().map_err(|_| RingError::Roster("member"))?);
        }
        let ring = Ring {
            terms: RingTerms {
                network,
                capacity_sat: parse_num(f[3], "capacity_sat")?,
                announce,
                open_window_secs: parse_num(f[5], "open_window_secs")?,
                bond_sat: parse_num(f[6], "bond_sat")?,
            },
            members,
            created_at: parse_num(f[7], "created_at")?,
        };
        ring.validate()?;
        if ring.text() != text {
            return Err(RingError::Roster("not canonical"));
        }
        Ok(ring)
    }

    /// Where `node` sits in the opening order, from 0.
    pub fn position(&self, node: &PublicKey) -> Option<usize> {
        self.members.iter().position(|member| member == node)
    }

    /// The node `node` opens its channel to: the next member, or the first for the last.
    pub fn opens_to(&self, node: &PublicKey) -> Option<PublicKey> {
        let i = self.position(node)?;
        Some(self.members[(i + 1) % self.members.len()])
    }

    /// The node that opens a channel to `node`: the previous member, or the last for the first.
    pub fn receives_from(&self, node: &PublicKey) -> Option<PublicKey> {
        let i = self.position(node)?;
        let n = self.members.len();
        Some(self.members[(i + n - 1) % n])
    }

    /// Unix seconds when the open window ends.
    pub fn window_ends_at(&self) -> u64 {
        self.created_at.saturating_add(self.terms.open_window_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn node(n: u8) -> PublicKey {
        let mut b = [0u8; 32];
        b[31] = n;
        let sk = SecretKey::from_slice(&b).unwrap();
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &sk)
    }

    fn ring(size: u8) -> Ring {
        Ring {
            terms: RingTerms {
                network: Network::Regtest,
                capacity_sat: 2_000_000,
                announce: true,
                open_window_secs: 48 * 3_600,
                bond_sat: 0,
            },
            members: (1..=size).map(node).collect(),
            created_at: 1_794_800_000,
        }
    }

    #[test]
    fn the_text_is_stable_and_the_id_is_its_hash() {
        let r = ring(3);
        let expected = format!(
            "bipnip-ring:v1:regtest:2000000:1:172800:0:1794800000:{},{},{}",
            node(1),
            node(2),
            node(3)
        );
        assert_eq!(r.text(), expected);
        let digest: String = Sha256::digest(expected.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(r.id(), digest);
        assert_eq!(r.id().len(), 64);
        assert_eq!(r.window_ends_at(), 1_794_800_000 + 172_800);
    }

    #[test]
    fn every_valid_ring_parses_back_to_itself() {
        for size in 2..=5 {
            let r = ring(size);
            assert_eq!(Ring::parse(&r.text()), Ok(r.clone()), "size {size}");
            let mut private = r.clone();
            private.terms.announce = false;
            private.terms.network = Network::Signet;
            assert_eq!(Ring::parse(&private.text()), Ok(private));
        }
    }

    #[test]
    fn each_member_opens_to_the_next_and_the_last_to_the_first() {
        let r = ring(4);
        assert_eq!(r.opens_to(&node(1)), Some(node(2)));
        assert_eq!(r.opens_to(&node(3)), Some(node(4)));
        assert_eq!(r.opens_to(&node(4)), Some(node(1)));
        assert_eq!(r.receives_from(&node(1)), Some(node(4)));
        assert_eq!(r.receives_from(&node(2)), Some(node(1)));
        assert_eq!(r.position(&node(3)), Some(2));
        assert_eq!(r.opens_to(&node(9)), None);
        assert_eq!(r.receives_from(&node(9)), None);
        // Every member opens exactly one channel and receives exactly one.
        for member in &r.members {
            let to = r.opens_to(member).unwrap();
            assert_ne!(&to, member);
            assert_eq!(r.receives_from(&to), Some(*member));
        }
        // Two members open to each other.
        let pair = ring(2);
        assert_eq!(pair.opens_to(&node(1)), Some(node(2)));
        assert_eq!(pair.opens_to(&node(2)), Some(node(1)));
        assert_eq!(pair.receives_from(&node(1)), Some(node(2)));
    }

    #[test]
    fn the_order_of_the_members_is_part_of_the_id() {
        let r = ring(3);
        let mut swapped = r.clone();
        swapped.members.swap(0, 1);
        assert_ne!(r.id(), swapped.id());
        let mut later = r.clone();
        later.created_at += 1;
        assert_ne!(r.id(), later.id());
    }

    #[test]
    fn rings_out_of_range_are_refused() {
        let good = ring(3);
        assert!(good.validate().is_ok());
        let with = |change: &dyn Fn(&mut Ring)| {
            let mut r = good.clone();
            change(&mut r);
            r.validate()
        };
        assert_eq!(
            with(&|r| r.members.truncate(1)),
            Err(RingError::Roster("number of members"))
        );
        assert_eq!(
            with(&|r| r.members = (1..=6).map(node).collect()),
            Err(RingError::Roster("number of members"))
        );
        assert_eq!(
            with(&|r| r.members[2] = node(1)),
            Err(RingError::Roster("a node is in the ring twice"))
        );
        assert_eq!(
            with(&|r| r.terms.capacity_sat = MIN_CAPACITY_SAT - 1),
            Err(RingError::Term("capacity_sat"))
        );
        assert_eq!(
            with(&|r| r.terms.capacity_sat = MAX_CAPACITY_SAT + 1),
            Err(RingError::Term("capacity_sat"))
        );
        assert_eq!(
            with(&|r| r.terms.open_window_secs = MIN_OPEN_WINDOW_SECS_REGTEST - 1),
            Err(RingError::Term("open_window_secs"))
        );
        assert_eq!(
            with(&|r| r.terms.open_window_secs = MAX_OPEN_WINDOW_SECS + 1),
            Err(RingError::Term("open_window_secs"))
        );
    }

    #[test]
    fn a_bond_needs_announced_channels_and_a_short_window() {
        let mut bonded = ring(3);
        bonded.terms.bond_sat = 50_000;
        assert!(bonded.validate().is_ok());
        // The bond is part of the text every member signs.
        assert!(bonded.text().contains(":172800:50000:1794800000:"));
        assert_ne!(bonded.id(), ring(3).id());
        assert_eq!(Ring::parse(&bonded.text()), Ok(bonded.clone()));

        let with = |change: &dyn Fn(&mut Ring)| {
            let mut r = bonded.clone();
            change(&mut r);
            r.validate()
        };
        assert_eq!(
            with(&|r| r.terms.announce = false),
            Err(RingError::Term("a bond needs announced channels"))
        );
        assert_eq!(
            with(&|r| r.terms.open_window_secs = MAX_BONDED_WINDOW_SECS + 1),
            Err(RingError::Term("a bond needs a window of 48 hours or less"))
        );
        assert_eq!(
            with(&|r| r.terms.bond_sat = r.terms.capacity_sat + 1),
            Err(RingError::Term("bond_sat"))
        );
        assert_eq!(
            with(&|r| r.terms.bond_sat = crate::bond::MIN_BOND_SAT - 1),
            Err(RingError::Term("bond_sat"))
        );
        // Without a bond neither rule applies.
        let mut free = ring(3);
        free.terms.announce = false;
        free.terms.open_window_secs = MAX_OPEN_WINDOW_SECS;
        assert!(free.validate().is_ok());
    }

    #[test]
    fn only_regtest_allows_a_window_under_an_hour() {
        let mut quick = ring(3);
        quick.terms.open_window_secs = MIN_OPEN_WINDOW_SECS_REGTEST;
        assert!(quick.validate().is_ok());
        quick.terms.open_window_secs = MIN_OPEN_WINDOW_SECS_REGTEST - 1;
        assert!(quick.validate().is_err());
        for network in [Network::Bitcoin, Network::Signet, Network::Testnet4] {
            let mut real = ring(3);
            real.terms.network = network;
            real.terms.open_window_secs = MIN_OPEN_WINDOW_SECS - 1;
            assert_eq!(
                real.validate(),
                Err(RingError::Term("open_window_secs")),
                "{network:?}"
            );
            real.terms.open_window_secs = MIN_OPEN_WINDOW_SECS;
            assert!(real.validate().is_ok());
        }
    }

    #[test]
    fn text_that_is_not_canonical_is_refused() {
        let text = ring(3).text();
        let bad = [
            text.replace("bipnip-ring", "bipnip-rings"),
            text.replace(":v1:", ":v2:"),
            text.replace(":regtest:", ":mainnet:"),
            text.replace(":2000000:", ":02000000:"),
            text.replace(":2000000:", ":2000000 :"),
            text.replace(":1:172800:", ":2:172800:"),
            text.replace(":1:172800:", ":true:172800:"),
            text.replace(":172800:", ":+172800:"),
            text.replace(":172800:0:", ":172800:00:"),
            text.replace(":172800:0:", ":172800:"),
            text.replace(&node(2).to_string(), &node(2).to_string().to_uppercase()),
            text.replace(&format!(",{}", node(3)), ""),
            text.replace(&format!(",{}", node(3)), &format!(",{}", node(1))),
            format!("{text},"),
            format!("{text}:"),
            format!(" {text}"),
            text.replace(',', ", "),
            String::new(),
        ];
        for candidate in bad {
            // Dropping a member of three leaves a valid ring of two; that one is a different
            // ring, not a malformed one.
            let dropped_to_two =
                candidate.matches(',').count() == 1 && candidate.len() < text.len();
            if dropped_to_two {
                assert_ne!(Ring::parse(&candidate).map(|r| r.id()), Ok(ring(3).id()));
                continue;
            }
            assert!(Ring::parse(&candidate).is_err(), "{candidate}");
        }
    }
}
