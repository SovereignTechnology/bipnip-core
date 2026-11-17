//! What travels between a ring's members and the instance (bipnip draft "Liquidity rings"): the
//! payloads of the ring [`Action`]s, with the checks every receiver runs before acting on one.
//!
//! | action | direction | payload |
//! |---|---|---|
//! | `ring-offer` | creator → instance; echoed back with the order id | [`RingPayload::Offer`] |
//! | `take-ring-slot` | member → instance | [`RingPayload::Take`] |
//! | `ring-roster` | instance → every member, once the slots are full | [`RingPayload::Roster`] |
//! | `ring-commit` | member → instance | [`RingPayload::Commit`] |
//! | `ring-open` | instance → every member, once all have committed | [`RingPayload::Open`] |
//! | `ring-edge-opened` | opener → instance → the member it opened to | [`RingPayload::Edge`] |
//! | `ring-edge-verified` | receiver → instance → the opener | [`RingPayload::Edge`] |
//! | `ring-closed` | instance → every member, at the end | [`RingPayload::Closed`] |
//! | `ring-bond-invoice` | instance → each member of a ring with bonds, after the commits | [`RingPayload::Invoice`] |
//! | `ring-bond-claim` | a member that is owed a bond → instance | [`RingPayload::Invoice`] |
//!
//! What a member does not take on the instance's word:
//!
//! - **Who is in the ring.** The roster carries every member's node binding; a member checks each
//!   one ([`RingRoster::check`]), so the instance cannot seat a node its operator does not
//!   control or a Nostr key the node does not vouch for.
//! - **That everyone saw the same ring.** Each member signs the ring id with its liquidity
//!   identity ([`RingCommit`]); a member opens only after it holds a valid commit from every
//!   member ([`RingOpen::check`]).
//! - **That a channel exists.** `ring-edge-opened` only says where to look; the receiving
//!   member's own node is the judge.
//!
//! A ring may ask for a bond ([`crate::ring::RingTerms::bond_sat`]): each member locks that
//! much at the instance's node before anyone opens. All bonds go back when every channel is
//! there. A member whose channel is missing when the window ends loses its bond to the member it
//! should have opened to. The instance decides that on what its own node's graph shows, which is
//! why a bond needs announced channels; a member's word cannot take another member's bond.
//!
//! Everything here is pure: no node, no relay, no clock (callers pass `now`).

use std::fmt;

use nostr_sdk::prelude::{Event, Keys, PublicKey as NostrKey};
use secp256k1::{schnorr, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lease_message::{
    check_binding, valid_invoice_shape, valid_node_address, LeaseMessageError, MAX_BINDING_JSON_LEN,
};
use crate::message::{Action, Message, Payload};
use crate::node_binding::Network;
use crate::ring::{Ring, RingError, RingTerms, MAX_RING_SIZE, MIN_RING_SIZE};

/// Why a ring message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingMessageError {
    /// A field is malformed or out of range; the name says which.
    Field(&'static str),
    /// The terms or the roster are invalid.
    Ring(RingError),
    /// A member's binding is invalid, or is not a binding of that node to that Nostr key.
    Binding(LeaseMessageError),
    /// Well-formed, but it does not match the ring or the offer at hand; the reason says how.
    Mismatch(&'static str),
    /// A commit is missing, repeated, or its signature does not verify.
    Commit(&'static str),
}

impl fmt::Display for RingMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RingMessageError::Field(what) => write!(f, "invalid ring message: {what}"),
            RingMessageError::Ring(e) => write!(f, "{e}"),
            RingMessageError::Binding(e) => write!(f, "{e}"),
            RingMessageError::Mismatch(what) => write!(f, "not this ring: {what}"),
            RingMessageError::Commit(what) => write!(f, "invalid ring commit: {what}"),
        }
    }
}

impl std::error::Error for RingMessageError {}

impl From<RingError> for RingMessageError {
    fn from(e: RingError) -> Self {
        RingMessageError::Ring(e)
    }
}

fn field(what: &'static str) -> RingMessageError {
    RingMessageError::Field(what)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex64(s: &str) -> Option<[u8; 64]> {
    if !is_lower_hex(s, 128) {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A member's place in a ring: its node, the binding that shows who runs it, and where the
/// member that opens to it can reach the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingSeat {
    /// The member's node key, 66 lower-case hex.
    pub node: String,
    /// The node's binding event (kind 31735), as JSON.
    pub binding: String,
    /// `host:port` of the node, if it accepts connections.
    pub node_address: Option<String>,
}

impl RingSeat {
    /// The node key.
    pub fn node_key(&self) -> Result<PublicKey, RingMessageError> {
        if !is_lower_hex(&self.node, 66) {
            return Err(field("node"));
        }
        self.node.parse().map_err(|_| field("node"))
    }

    /// Checks the fields' form. The binding is checked separately: it needs a clock.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        self.node_key()?;
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_JSON_LEN {
            return Err(field("binding"));
        }
        if let Some(address) = &self.node_address {
            if !valid_node_address(address) {
                return Err(field("node_address"));
            }
        }
        Ok(())
    }

    /// For the instance: the binding is of this seat's node, on `network`, to the Nostr key that
    /// sent the message.
    pub fn check_binding(
        &self,
        network: Network,
        sender_nostr_pubkey: &str,
        now: u64,
    ) -> Result<(), RingMessageError> {
        check_binding(
            &self.binding,
            &self.node_key()?,
            network,
            sender_nostr_pubkey,
            now,
        )
        .map(|_| ())
        .map_err(RingMessageError::Binding)
    }

    /// For the other members: the Nostr key this seat's node vouches for. That is the key that
    /// signed the binding event; the binding is checked to be of this node, on `network`, to it.
    pub fn bound_key(&self, network: Network, now: u64) -> Result<NostrKey, RingMessageError> {
        self.validate()?;
        let key = Event::from_json(&self.binding)
            .map_err(|_| field("binding"))?
            .pubkey;
        self.check_binding(network, &key.to_hex(), now)?;
        Ok(key)
    }
}

/// A ring a creator proposes. The creator takes the first slot itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingOffer {
    /// The network every member's node must be on.
    pub network: Network,
    /// Capacity of every channel, in satoshi.
    pub capacity_sat: u64,
    /// How many members the ring has, the creator included.
    pub slots: u8,
    /// Whether the channels are announced.
    pub announce: bool,
    /// Seconds members have to open once the roster is fixed.
    pub open_window_secs: u64,
    /// What each member locks at the instance until the ring ends, in satoshi; 0 for none.
    pub bond_sat: u64,
    /// Unix seconds after which the open slots can no longer be taken.
    pub expires_at: u64,
    /// The creator's own seat.
    pub seat: RingSeat,
}

impl RingOffer {
    /// The terms every channel of this ring has.
    pub fn terms(&self) -> RingTerms {
        RingTerms {
            network: self.network,
            capacity_sat: self.capacity_sat,
            announce: self.announce,
            open_window_secs: self.open_window_secs,
            bond_sat: self.bond_sat,
        }
    }

    /// Checks the terms, the number of slots, the expiry and the creator's seat. The binding is
    /// checked separately ([`RingOffer::check_binding`]).
    pub fn validate(&self) -> Result<(), RingMessageError> {
        self.terms().validate()?;
        if !(MIN_RING_SIZE..=MAX_RING_SIZE).contains(&usize::from(self.slots)) {
            return Err(field("slots"));
        }
        if self.expires_at == 0 {
            return Err(field("expires_at"));
        }
        self.seat.validate()
    }

    /// For the instance: the creator's binding is of its seat's node to the key that sent the
    /// offer.
    pub fn check_binding(
        &self,
        sender_nostr_pubkey: &str,
        now: u64,
    ) -> Result<(), RingMessageError> {
        self.seat
            .check_binding(self.network, sender_nostr_pubkey, now)
    }

    /// True when the open slots can no longer be taken at `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// For a member: `ring` is this offer, filled. Its terms are the offer's, it has as many
    /// members as the offer has slots, and the creator's node is one of them. An instance cannot
    /// change the capacity, the announce flag, the window or the size between offer and roster.
    pub fn check_ring(&self, ring: &Ring) -> Result<(), RingMessageError> {
        if ring.terms != self.terms() {
            return Err(RingMessageError::Mismatch("the terms are not the offer's"));
        }
        if ring.members.len() != usize::from(self.slots) {
            return Err(RingMessageError::Mismatch(
                "the ring is not the size offered",
            ));
        }
        if ring.position(&self.seat.node_key()?).is_none() {
            return Err(RingMessageError::Mismatch("the creator is not in the ring"));
        }
        Ok(())
    }
}

/// The filled ring: its canonical text and every member's seat, in opening order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingRoster {
    /// The canonical text ([`Ring::text`]).
    pub ring: String,
    /// The members' seats, in the order of the text.
    pub seats: Vec<RingSeat>,
}

impl RingRoster {
    /// For the instance: the roster of `seats`, in that order, under `terms`, fixed at
    /// `created_at`.
    pub fn from_seats(
        terms: RingTerms,
        seats: Vec<RingSeat>,
        created_at: u64,
    ) -> Result<Self, RingMessageError> {
        let mut members = Vec::with_capacity(seats.len());
        for seat in &seats {
            seat.validate()?;
            members.push(seat.node_key()?);
        }
        let ring = Ring {
            terms,
            members,
            created_at,
        };
        ring.validate()?;
        Ok(RingRoster {
            ring: ring.text(),
            seats,
        })
    }

    /// Parses the ring and checks that the seats are its members' seats, one each, in order.
    /// Bindings are checked by [`RingRoster::check`].
    pub fn validate(&self) -> Result<Ring, RingMessageError> {
        let ring = Ring::parse(&self.ring)?;
        if self.seats.len() != ring.members.len() {
            return Err(RingMessageError::Mismatch(
                "the seats are not the ring's members",
            ));
        }
        for (seat, member) in self.seats.iter().zip(&ring.members) {
            seat.validate()?;
            if seat.node_key()? != *member {
                return Err(RingMessageError::Mismatch(
                    "the seats are not the ring's members",
                ));
            }
        }
        Ok(ring)
    }

    /// For a member: everything [`RingRoster::validate`] checks, plus every member's binding.
    /// Returns the ring and the Nostr key each member's node vouches for, in opening order. The
    /// commits are checked against these keys.
    pub fn check(&self, now: u64) -> Result<(Ring, Vec<NostrKey>), RingMessageError> {
        let ring = self.validate()?;
        let mut keys = Vec::with_capacity(self.seats.len());
        for seat in &self.seats {
            let key = seat.bound_key(ring.terms.network, now)?;
            if keys.contains(&key) {
                return Err(RingMessageError::Mismatch("one Nostr key holds two seats"));
            }
            keys.push(key);
        }
        Ok((ring, keys))
    }
}

/// What a member signs to commit to a ring: the ring id, under a prefix that makes the signature
/// useless for anything else.
pub fn commit_text(ring_id: &str) -> String {
    format!("bipnip-ring-commit:v1:{ring_id}")
}

fn commit_digest(ring_id: &str) -> [u8; 32] {
    Sha256::digest(commit_text(ring_id).as_bytes()).into()
}

fn commit_verifies(ring_id: &str, key: &NostrKey, signature: &str) -> bool {
    let Some(bytes) = unhex64(signature) else {
        return false;
    };
    let Ok(xonly) = key.xonly() else {
        return false;
    };
    let signature = schnorr::Signature::from_byte_array(bytes);
    xonly
        .verify(
            &Secp256k1::verification_only(),
            &commit_digest(ring_id),
            &signature,
        )
        .is_ok()
}

/// A member's commitment to a ring, sent to the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingCommit {
    /// The ring id.
    pub ring_id: String,
    /// Schnorr signature of [`commit_text`]'s SHA-256 by the member's liquidity identity, 128
    /// lower-case hex.
    pub signature: String,
}

impl RingCommit {
    /// Commits `keys` to `ring`.
    pub fn sign(ring: &Ring, keys: &Keys) -> Self {
        let ring_id = ring.id();
        let signature = Message::sign(commit_text(&ring_id), keys);
        RingCommit {
            signature: hex(signature.as_bytes()),
            ring_id,
        }
    }

    /// Checks the fields' form.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        if !is_lower_hex(&self.ring_id, 64) {
            return Err(field("ring_id"));
        }
        if !is_lower_hex(&self.signature, 128) {
            return Err(field("signature"));
        }
        Ok(())
    }

    /// Checks that this is `key`'s commit to `ring`.
    pub fn verify(&self, ring: &Ring, key: &NostrKey) -> Result<(), RingMessageError> {
        self.validate()?;
        if self.ring_id != ring.id() {
            return Err(RingMessageError::Mismatch("another ring id"));
        }
        if !commit_verifies(&self.ring_id, key, &self.signature) {
            return Err(RingMessageError::Commit("the signature does not verify"));
        }
        Ok(())
    }
}

/// One member's commit, as the instance passes it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingCommitment {
    /// The Nostr key that committed, 64 lower-case hex.
    pub nostr_pubkey: String,
    /// Its signature, as in [`RingCommit::signature`].
    pub signature: String,
}

/// Every member has committed: the open window runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingOpen {
    /// The ring id.
    pub ring_id: String,
    /// Every member's commit.
    pub commits: Vec<RingCommitment>,
}

impl RingOpen {
    /// Checks the fields' form and that there are not more commits than a ring has members.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        if !is_lower_hex(&self.ring_id, 64) {
            return Err(field("ring_id"));
        }
        if self.commits.is_empty() || self.commits.len() > MAX_RING_SIZE {
            return Err(field("commits"));
        }
        for commit in &self.commits {
            if !is_lower_hex(&commit.nostr_pubkey, 64) {
                return Err(field("nostr_pubkey"));
            }
            if !is_lower_hex(&commit.signature, 128) {
                return Err(field("signature"));
            }
        }
        Ok(())
    }

    /// For a member, before it opens: there is exactly one commit per member of `ring`, each by
    /// the Nostr key that member's node vouches for (`bound_keys`, from [`RingRoster::check`]),
    /// each a valid signature of this ring's id.
    pub fn check(&self, ring: &Ring, bound_keys: &[NostrKey]) -> Result<(), RingMessageError> {
        self.validate()?;
        if self.ring_id != ring.id() {
            return Err(RingMessageError::Mismatch("another ring id"));
        }
        if bound_keys.len() != ring.members.len() || self.commits.len() != bound_keys.len() {
            return Err(RingMessageError::Commit("not one commit per member"));
        }
        for key in bound_keys {
            let hex = key.to_hex();
            let mut of_member = self.commits.iter().filter(|c| c.nostr_pubkey == hex);
            let Some(commit) = of_member.next() else {
                return Err(RingMessageError::Commit("a member has not committed"));
            };
            if of_member.next().is_some() {
                return Err(RingMessageError::Commit("a member committed twice"));
            }
            if !commit_verifies(&self.ring_id, key, &commit.signature) {
                return Err(RingMessageError::Commit("a signature does not verify"));
            }
        }
        Ok(())
    }
}

/// One channel of the ring: reported by the member that opened it (`ring-edge-opened`), then
/// confirmed by the member it was opened to (`ring-edge-verified`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingEdge {
    /// The ring id.
    pub ring_id: String,
    /// The funding transaction id, 64 lower-case hex.
    pub funding_txid: String,
    /// The funding output's index.
    pub output_index: u32,
}

impl RingEdge {
    /// Checks the fields' form.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        if !is_lower_hex(&self.ring_id, 64) {
            return Err(field("ring_id"));
        }
        if !is_lower_hex(&self.funding_txid, 64) {
            return Err(field("funding_txid"));
        }
        Ok(())
    }

    /// The funding outpoint as nodes print it: `<txid>:<index>`.
    pub fn channel_point(&self) -> String {
        format!("{}:{}", self.funding_txid, self.output_index)
    }
}

/// A BOLT 11 invoice tied to a ring: the instance's hold invoice for a member's bond
/// (`ring-bond-invoice`), or a member's invoice for a bond it is owed (`ring-bond-claim`). The
/// receiver checks the invoice itself before paying; nothing here vouches for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingInvoice {
    /// The ring id.
    pub ring_id: String,
    /// The BOLT 11 invoice.
    pub invoice: String,
}

impl RingInvoice {
    /// Checks the id's form and the invoice's shape.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        if !is_lower_hex(&self.ring_id, 64) {
            return Err(field("ring_id"));
        }
        if !valid_invoice_shape(&self.invoice) {
            return Err(field("invoice"));
        }
        Ok(())
    }
}

/// How the ring ended: which members' channels were confirmed, and whose bond was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingClosed {
    /// The ring id.
    pub ring_id: String,
    /// Positions (from 0, in opening order) of the members whose channel was confirmed, in
    /// ascending order.
    pub verified: Vec<u8>,
    /// Positions of the members whose bond was taken because their channel was missing, in
    /// ascending order. Empty for a ring without bonds. Each of these bonds is owed to the next
    /// member.
    pub slashed: Vec<u8>,
}

impl RingClosed {
    /// Checks the fields' form: positions ascending, none repeated, none beyond the largest
    /// ring.
    pub fn validate(&self) -> Result<(), RingMessageError> {
        if !is_lower_hex(&self.ring_id, 64) {
            return Err(field("ring_id"));
        }
        let well_formed = |positions: &[u8]| {
            positions.windows(2).all(|pair| pair[0] < pair[1])
                && positions
                    .iter()
                    .all(|position| usize::from(*position) < MAX_RING_SIZE)
        };
        if !well_formed(&self.verified) {
            return Err(field("verified"));
        }
        // A member whose channel was confirmed keeps its bond.
        let both = self.slashed.iter().any(|p| self.verified.contains(p));
        if !well_formed(&self.slashed) || both {
            return Err(field("slashed"));
        }
        Ok(())
    }

    /// Checks that this is about `ring` and names only positions it has.
    pub fn check(&self, ring: &Ring) -> Result<(), RingMessageError> {
        self.validate()?;
        if self.ring_id != ring.id() {
            return Err(RingMessageError::Mismatch("another ring id"));
        }
        if self
            .verified
            .iter()
            .chain(&self.slashed)
            .any(|position| usize::from(*position) >= ring.members.len())
        {
            return Err(RingMessageError::Mismatch(
                "a position the ring does not have",
            ));
        }
        if !self.slashed.is_empty() && ring.terms.bond_sat == 0 {
            return Err(RingMessageError::Mismatch(
                "a bond taken in a ring without bonds",
            ));
        }
        Ok(())
    }

    /// True when the member at `position` is owed a bond: the member before it, which should
    /// have opened a channel to it, lost its own.
    pub fn owed_a_bond(&self, ring: &Ring, position: usize) -> bool {
        let n = ring.members.len();
        if n == 0 || position >= n {
            return false;
        }
        let before = (position + n - 1) % n;
        self.slashed
            .iter()
            .any(|slashed| usize::from(*slashed) == before)
    }

    /// True when every member's channel was confirmed.
    pub fn is_complete(&self, ring: &Ring) -> bool {
        self.verified.len() == ring.members.len()
    }
}

/// The payload of a ring action; see the table in the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RingPayload {
    /// With [`Action::RingOffer`].
    Offer(RingOffer),
    /// With [`Action::TakeRingSlot`].
    Take(RingSeat),
    /// With [`Action::RingRoster`].
    Roster(RingRoster),
    /// With [`Action::RingCommit`].
    Commit(RingCommit),
    /// With [`Action::RingOpen`].
    Open(RingOpen),
    /// With [`Action::RingEdgeOpened`] and [`Action::RingEdgeVerified`].
    Edge(RingEdge),
    /// With [`Action::RingClosed`].
    Closed(RingClosed),
    /// With [`Action::RingBondInvoice`] and [`Action::RingBondClaim`].
    Invoice(RingInvoice),
}

impl RingPayload {
    /// Runs the carried type's own `validate` (form and ranges; no binding, no clock).
    pub fn validate(&self) -> Result<(), RingMessageError> {
        match self {
            RingPayload::Offer(offer) => offer.validate(),
            RingPayload::Take(seat) => seat.validate(),
            RingPayload::Roster(roster) => roster.validate().map(|_| ()),
            RingPayload::Commit(commit) => commit.validate(),
            RingPayload::Open(open) => open.validate(),
            RingPayload::Edge(edge) => edge.validate(),
            RingPayload::Closed(closed) => closed.validate(),
            RingPayload::Invoice(invoice) => invoice.validate(),
        }
    }
}

/// True for the actions this module owns.
pub fn is_ring_action(action: &Action) -> bool {
    matches!(
        action,
        Action::RingOffer
            | Action::TakeRingSlot
            | Action::RingRoster
            | Action::RingCommit
            | Action::RingOpen
            | Action::RingEdgeOpened
            | Action::RingEdgeVerified
            | Action::RingClosed
            | Action::RingBondInvoice
            | Action::RingBondClaim
    )
}

/// The shape rule [`crate::message::MessageKind::verify`] applies to ring actions: which payload
/// each carries, and that every one but a creator's first `ring-offer` names an order. Returns
/// `false` for any other action.
pub fn shape_ok(action: &Action, has_id: bool, payload: Option<&Payload>) -> bool {
    let Some(Payload::Ring(ring)) = payload else {
        return false;
    };
    match action {
        Action::RingOffer => matches!(ring, RingPayload::Offer(_)),
        Action::TakeRingSlot => has_id && matches!(ring, RingPayload::Take(_)),
        Action::RingRoster => has_id && matches!(ring, RingPayload::Roster(_)),
        Action::RingCommit => has_id && matches!(ring, RingPayload::Commit(_)),
        Action::RingOpen => has_id && matches!(ring, RingPayload::Open(_)),
        Action::RingEdgeOpened | Action::RingEdgeVerified => {
            has_id && matches!(ring, RingPayload::Edge(_))
        }
        Action::RingClosed => has_id && matches!(ring, RingPayload::Closed(_)),
        Action::RingBondInvoice | Action::RingBondClaim => {
            has_id && matches!(ring, RingPayload::Invoice(_))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_binding::{
        sign_ln_message, Action as BindingAction, SignedStatement, Statement,
    };
    use nostr_sdk::prelude::FinalizeEvent;
    use secp256k1::SecretKey;
    use uuid::Uuid;

    const NOW: u64 = 1_794_800_000;

    /// A member: a node key and the liquidity identity it is bound to.
    struct Member {
        node: SecretKey,
        keys: Keys,
    }

    impl Member {
        fn new(n: u8) -> Self {
            let mut b = [0u8; 32];
            b[31] = n;
            Member {
                node: SecretKey::from_slice(&b).unwrap(),
                keys: Keys::generate(),
            }
        }

        fn node_key(&self) -> PublicKey {
            PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.node)
        }

        /// This node's binding of `keys` on `network`.
        fn binding(&self, keys: &Keys, network: Network) -> String {
            let statement = Statement::new(
                BindingAction::Bind,
                network,
                &keys.public_key().to_hex(),
                self.node_key(),
                NOW - 60,
            )
            .unwrap();
            let node_signature = sign_ln_message(statement.text().as_bytes(), &self.node);
            SignedStatement {
                statement,
                node_signature,
            }
            .to_event_builder()
            .finalize(keys)
            .unwrap()
            .as_json()
        }

        fn seat(&self) -> RingSeat {
            RingSeat {
                node: self.node_key().to_string(),
                binding: self.binding(&self.keys, Network::Regtest),
                node_address: Some("203.0.113.7:9735".into()),
            }
        }
    }

    fn members(n: u8) -> Vec<Member> {
        (1..=n).map(Member::new).collect()
    }

    fn offer(creator: &Member, slots: u8) -> RingOffer {
        RingOffer {
            network: Network::Regtest,
            capacity_sat: 2_000_000,
            slots,
            announce: true,
            open_window_secs: 48 * 3_600,
            bond_sat: 0,
            expires_at: NOW + 86_400,
            seat: creator.seat(),
        }
    }

    fn roster(of: &[Member], offer: &RingOffer) -> RingRoster {
        let seats = of.iter().map(Member::seat).collect();
        RingRoster::from_seats(offer.terms(), seats, NOW).unwrap()
    }

    fn open(of: &[Member], ring: &Ring) -> RingOpen {
        RingOpen {
            ring_id: ring.id(),
            commits: of
                .iter()
                .map(|m| RingCommitment {
                    nostr_pubkey: m.keys.public_key().to_hex(),
                    signature: RingCommit::sign(ring, &m.keys).signature,
                })
                .collect(),
        }
    }

    #[test]
    fn a_ring_goes_from_offer_to_roster_to_commits_with_every_check_passing() {
        let ms = members(4);
        let offer = offer(&ms[0], 4);
        offer.validate().unwrap();
        offer
            .check_binding(&ms[0].keys.public_key().to_hex(), NOW)
            .unwrap();
        assert!(!offer.is_expired(NOW));
        assert!(offer.is_expired(NOW + 86_400));

        let roster = roster(&ms, &offer);
        let (ring, keys) = roster.check(NOW).unwrap();
        assert_eq!(ring.members.len(), 4);
        assert_eq!(ring.created_at, NOW);
        assert_eq!(
            keys,
            ms.iter().map(|m| m.keys.public_key()).collect::<Vec<_>>()
        );
        offer.check_ring(&ring).unwrap();
        assert_eq!(ring.opens_to(&ms[3].node_key()), Some(ms[0].node_key()));

        for (member, key) in ms.iter().zip(&keys) {
            let commit = RingCommit::sign(&ring, &member.keys);
            commit.verify(&ring, key).unwrap();
        }
        open(&ms, &ring).check(&ring, &keys).unwrap();
    }

    #[test]
    fn an_offer_out_of_range_or_with_someone_elses_binding_is_refused() {
        let ms = members(2);
        let good = offer(&ms[0], 3);
        let with = |change: &dyn Fn(&mut RingOffer)| {
            let mut o = good.clone();
            change(&mut o);
            o.validate()
        };
        assert_eq!(with(&|o| o.slots = 1), Err(field("slots")));
        assert_eq!(with(&|o| o.slots = 6), Err(field("slots")));
        assert_eq!(with(&|o| o.expires_at = 0), Err(field("expires_at")));
        assert!(matches!(
            with(&|o| o.capacity_sat = 1),
            Err(RingMessageError::Ring(RingError::Term("capacity_sat")))
        ));
        assert!(matches!(
            with(&|o| o.open_window_secs = 59),
            Err(RingMessageError::Ring(RingError::Term("open_window_secs")))
        ));
        assert_eq!(with(&|o| o.seat.node = "02ab".into()), Err(field("node")));
        assert_eq!(
            with(&|o| o.seat.node_address = Some("no port".into())),
            Err(field("node_address"))
        );
        assert_eq!(
            with(&|o| o.seat.binding = String::new()),
            Err(field("binding"))
        );

        // The binding must be of the seat's node to the sender.
        let sender = ms[0].keys.public_key().to_hex();
        good.check_binding(&sender, NOW).unwrap();
        let stranger = ms[1].keys.public_key().to_hex();
        assert!(matches!(
            good.check_binding(&stranger, NOW),
            Err(RingMessageError::Binding(_))
        ));
        let mut other_node = good.clone();
        other_node.seat.node = ms[1].node_key().to_string();
        assert!(matches!(
            other_node.check_binding(&sender, NOW),
            Err(RingMessageError::Binding(_))
        ));
        let mut other_network = good.clone();
        other_network.network = Network::Signet;
        assert!(matches!(
            other_network.check_binding(&sender, NOW),
            Err(RingMessageError::Binding(_))
        ));
    }

    #[test]
    fn a_roster_the_instance_tampered_with_is_refused() {
        let ms = members(3);
        let offer = offer(&ms[0], 3);
        let good = roster(&ms, &offer);
        good.check(NOW).unwrap();

        // Seats in another order than the text, a seat missing, a seat for a node not in it.
        let mut reordered = good.clone();
        reordered.seats.swap(0, 1);
        let mut short = good.clone();
        short.seats.pop();
        let mut foreign = good.clone();
        foreign.seats[2] = Member::new(9).seat();
        for bad in [reordered, short, foreign] {
            assert_eq!(
                bad.validate(),
                Err(RingMessageError::Mismatch(
                    "the seats are not the ring's members"
                ))
            );
        }

        // A seat whose binding is to a key its node never vouched for: the instance cannot seat
        // itself on someone's node.
        let impostor = Keys::generate();
        let mut seized = good.clone();
        seized.seats[1].binding = ms[2].binding(&impostor, Network::Regtest);
        assert!(matches!(
            seized.check(NOW),
            Err(RingMessageError::Binding(_))
        ));
        // A binding for another network.
        let mut elsewhere = good.clone();
        elsewhere.seats[1].binding = ms[1].binding(&ms[1].keys, Network::Signet);
        assert!(matches!(
            elsewhere.check(NOW),
            Err(RingMessageError::Binding(_))
        ));
        // One operator behind two nodes of the same ring.
        let twin = Member {
            node: Member::new(8).node,
            keys: ms[0].keys.clone(),
        };
        let seats = vec![ms[0].seat(), twin.seat(), ms[2].seat()];
        let doubled = RingRoster::from_seats(offer.terms(), seats, NOW).unwrap();
        assert_eq!(
            doubled.check(NOW),
            Err(RingMessageError::Mismatch("one Nostr key holds two seats"))
        );

        // A roster that is not the offer: other terms, another size, the creator left out.
        let (ring, _) = good.check(NOW).unwrap();
        let mut bigger = offer.clone();
        bigger.capacity_sat += 1;
        assert!(bigger.check_ring(&ring).is_err());
        let mut private = offer.clone();
        private.announce = false;
        assert!(private.check_ring(&ring).is_err());
        let mut four = offer.clone();
        four.slots = 4;
        assert!(four.check_ring(&ring).is_err());
        let others = roster(&members(5)[2..5], &offer);
        let (without_creator, _) = others.check(NOW).unwrap();
        assert_eq!(
            offer.check_ring(&without_creator),
            Err(RingMessageError::Mismatch("the creator is not in the ring"))
        );
        // The same node twice cannot be built into a roster at all.
        let twice = vec![ms[0].seat(), ms[1].seat(), ms[0].seat()];
        assert!(RingRoster::from_seats(offer.terms(), twice, NOW).is_err());
    }

    #[test]
    fn a_commit_is_one_members_signature_of_one_ring() {
        let ms = members(3);
        let offer = offer(&ms[0], 3);
        let (ring, keys) = roster(&ms, &offer).check(NOW).unwrap();
        let commit = RingCommit::sign(&ring, &ms[0].keys);
        commit.validate().unwrap();
        commit.verify(&ring, &keys[0]).unwrap();

        // Not another member's, and not for another ring.
        assert_eq!(
            commit.verify(&ring, &keys[1]),
            Err(RingMessageError::Commit("the signature does not verify"))
        );
        let mut later = ring.clone();
        later.created_at += 1;
        assert_eq!(
            commit.verify(&later, &keys[0]),
            Err(RingMessageError::Mismatch("another ring id"))
        );
        // A signature moved under another ring's id does not verify either.
        let moved = RingCommit {
            ring_id: later.id(),
            signature: commit.signature.clone(),
        };
        assert_eq!(
            moved.verify(&later, &keys[0]),
            Err(RingMessageError::Commit("the signature does not verify"))
        );
        // The signature is of the prefixed text, not of the bare id: it is no use elsewhere.
        assert!(commit_text(&ring.id()).starts_with("bipnip-ring-commit:v1:"));
        let bare = RingCommit {
            ring_id: ring.id(),
            signature: hex(Message::sign(ring.id(), &ms[0].keys).as_bytes()),
        };
        assert!(bare.verify(&ring, &keys[0]).is_err());

        let upper = commit.signature.to_uppercase();
        for bad in ["", "zz", &commit.signature[..126], upper.as_str()] {
            let malformed = RingCommit {
                ring_id: ring.id(),
                signature: bad.to_string(),
            };
            assert_eq!(malformed.validate(), Err(field("signature")), "{bad}");
        }
    }

    #[test]
    fn nobody_opens_until_every_member_has_committed() {
        let ms = members(3);
        let offer = offer(&ms[0], 3);
        let (ring, keys) = roster(&ms, &offer).check(NOW).unwrap();
        let good = open(&ms, &ring);
        good.check(&ring, &keys).unwrap();
        // The order of the commits does not matter.
        let mut shuffled = good.clone();
        shuffled.commits.reverse();
        shuffled.check(&ring, &keys).unwrap();

        let mut missing = good.clone();
        missing.commits.pop();
        assert_eq!(
            missing.check(&ring, &keys),
            Err(RingMessageError::Commit("not one commit per member"))
        );
        // One member's commit twice in place of another's.
        let mut repeated = good.clone();
        repeated.commits[2] = repeated.commits[0].clone();
        assert!(matches!(
            repeated.check(&ring, &keys),
            Err(RingMessageError::Commit(_))
        ));
        // A stranger's commit in place of a member's.
        let stranger = Keys::generate();
        let mut swapped = good.clone();
        swapped.commits[1] = RingCommitment {
            nostr_pubkey: stranger.public_key().to_hex(),
            signature: RingCommit::sign(&ring, &stranger).signature,
        };
        assert_eq!(
            swapped.check(&ring, &keys),
            Err(RingMessageError::Commit("a member has not committed"))
        );
        // A member's name on someone else's signature.
        let mut forged = good.clone();
        forged.commits[1].signature = good.commits[0].signature.clone();
        assert_eq!(
            forged.check(&ring, &keys),
            Err(RingMessageError::Commit("a signature does not verify"))
        );
        // Commits to another ring.
        let mut later = ring.clone();
        later.created_at += 1;
        assert_eq!(
            open(&ms, &later).check(&ring, &keys),
            Err(RingMessageError::Mismatch("another ring id"))
        );
        // Checked against too few keys.
        assert!(good.check(&ring, &keys[..2]).is_err());
    }

    #[test]
    fn edges_and_the_closing_report_are_checked() {
        let ms = members(3);
        let offer = offer(&ms[0], 3);
        let (ring, _) = roster(&ms, &offer).check(NOW).unwrap();
        let edge = RingEdge {
            ring_id: ring.id(),
            funding_txid: "cd".repeat(32),
            output_index: 1,
        };
        edge.validate().unwrap();
        assert_eq!(edge.channel_point(), format!("{}:1", "cd".repeat(32)));
        let mut bad = edge.clone();
        bad.funding_txid = "CD".repeat(32);
        assert_eq!(bad.validate(), Err(field("funding_txid")));
        let mut bad = edge.clone();
        bad.ring_id = "ab".into();
        assert_eq!(bad.validate(), Err(field("ring_id")));

        let closed = |verified: Vec<u8>| RingClosed {
            ring_id: ring.id(),
            verified,
            slashed: vec![],
        };
        let all = closed(vec![0, 1, 2]);
        all.check(&ring).unwrap();
        assert!(all.is_complete(&ring));
        let partial = closed(vec![0, 2]);
        partial.check(&ring).unwrap();
        assert!(!partial.is_complete(&ring));
        closed(vec![]).check(&ring).unwrap();
        assert_eq!(closed(vec![1, 0]).validate(), Err(field("verified")));
        assert_eq!(closed(vec![1, 1]).validate(), Err(field("verified")));
        assert_eq!(closed(vec![5]).validate(), Err(field("verified")));
        // Position 3 exists in a ring of five, not in this one.
        closed(vec![3]).validate().unwrap();
        assert_eq!(
            closed(vec![3]).check(&ring),
            Err(RingMessageError::Mismatch(
                "a position the ring does not have"
            ))
        );
        let mut other = closed(vec![0]);
        other.ring_id = "ef".repeat(32);
        assert_eq!(
            other.check(&ring),
            Err(RingMessageError::Mismatch("another ring id"))
        );

        // Bonds taken: only in a ring that has bonds, never from a member whose channel was
        // confirmed, and each one is owed to the next member.
        let taken = |verified: Vec<u8>, slashed: Vec<u8>| RingClosed {
            ring_id: ring.id(),
            verified,
            slashed,
        };
        assert_eq!(
            taken(vec![0, 1], vec![2]).check(&ring),
            Err(RingMessageError::Mismatch(
                "a bond taken in a ring without bonds"
            ))
        );
        let mut bonded = ring.clone();
        bonded.terms.bond_sat = 50_000;
        let report = RingClosed {
            ring_id: bonded.id(),
            verified: vec![0, 1],
            slashed: vec![2],
        };
        report.check(&bonded).unwrap();
        assert!(!report.is_complete(&bonded));
        // Member 2 never opened to member 0: member 0 is owed, nobody else.
        assert!(report.owed_a_bond(&bonded, 0));
        assert!(!report.owed_a_bond(&bonded, 1));
        assert!(!report.owed_a_bond(&bonded, 2));
        assert!(!report.owed_a_bond(&bonded, 7));
        assert_eq!(taken(vec![0, 1], vec![1]).validate(), Err(field("slashed")));
        assert_eq!(taken(vec![0], vec![2, 1]).validate(), Err(field("slashed")));
        assert_eq!(taken(vec![0], vec![5]).validate(), Err(field("slashed")));
        let beyond = RingClosed {
            ring_id: bonded.id(),
            verified: vec![0],
            slashed: vec![3],
        };
        assert!(beyond.check(&bonded).is_err());

        let invoice = RingInvoice {
            ring_id: ring.id(),
            invoice: format!("lnbcrt500u1{}", "q".repeat(200)),
        };
        invoice.validate().unwrap();
        let mut junk = invoice.clone();
        junk.invoice = "not an invoice".into();
        assert_eq!(junk.validate(), Err(field("invoice")));
        let mut short = invoice;
        short.ring_id = "ab".into();
        assert_eq!(short.validate(), Err(field("ring_id")));
    }

    /// Every ring action with the payload it carries.
    fn all_messages() -> Vec<(Action, RingPayload)> {
        let ms = members(3);
        let offer = offer(&ms[0], 3);
        let roster = roster(&ms, &offer);
        let (ring, _) = roster.check(NOW).unwrap();
        let edge = RingEdge {
            ring_id: ring.id(),
            funding_txid: "cd".repeat(32),
            output_index: 0,
        };
        let bond = RingInvoice {
            ring_id: ring.id(),
            invoice: format!("lnbcrt500u1{}", "q".repeat(200)),
        };
        vec![
            (Action::RingOffer, RingPayload::Offer(offer)),
            (Action::TakeRingSlot, RingPayload::Take(ms[1].seat())),
            (Action::RingRoster, RingPayload::Roster(roster)),
            (
                Action::RingCommit,
                RingPayload::Commit(RingCommit::sign(&ring, &ms[1].keys)),
            ),
            (Action::RingOpen, RingPayload::Open(open(&ms, &ring))),
            (Action::RingEdgeOpened, RingPayload::Edge(edge.clone())),
            (Action::RingEdgeVerified, RingPayload::Edge(edge)),
            (
                Action::RingClosed,
                RingPayload::Closed(RingClosed {
                    ring_id: ring.id(),
                    verified: vec![0, 1, 2],
                    slashed: vec![],
                }),
            ),
            (Action::RingBondInvoice, RingPayload::Invoice(bond.clone())),
            (Action::RingBondClaim, RingPayload::Invoice(bond)),
        ]
    }

    #[test]
    fn every_ring_message_travels_as_json_and_keeps_its_shape() {
        let id = Some(Uuid::new_v4());
        let all = all_messages();
        for (action, payload) in &all {
            assert!(is_ring_action(action));
            payload.validate().unwrap();
            let message = Message::new_order(
                id,
                Some(1),
                None,
                action.clone(),
                Some(Payload::Ring(payload.clone())),
            );
            assert!(message.verify(), "{action:?}");
            let json = message.as_json().unwrap();
            let back = Message::from_json(&json).unwrap();
            assert!(back.verify());
            match &back.get_inner_message_kind().payload {
                Some(Payload::Ring(carried)) => assert_eq!(carried, payload, "{action:?}"),
                other => panic!("{action:?} came back with {other:?}"),
            }

            // Without an order id only a creator's first offer is well-formed.
            let no_id = Message::new_order(
                None,
                None,
                None,
                action.clone(),
                Some(Payload::Ring(payload.clone())),
            );
            assert_eq!(no_id.verify(), *action == Action::RingOffer, "{action:?}");
            // No ring action goes without a payload.
            let empty = Message::new_order(id, None, None, action.clone(), None);
            assert!(!empty.verify(), "{action:?}");
        }

        // Each action takes its own payload and no other action's.
        for (action, _) in &all {
            for (other_action, payload) in &all {
                let pair = |a: &Action, b: &Action| {
                    matches!(a, Action::RingEdgeOpened | Action::RingEdgeVerified)
                        && matches!(b, Action::RingEdgeOpened | Action::RingEdgeVerified)
                        || matches!(a, Action::RingBondInvoice | Action::RingBondClaim)
                            && matches!(b, Action::RingBondInvoice | Action::RingBondClaim)
                };
                let same_payload_kind = action == other_action || pair(action, other_action);
                let message = Message::new_order(
                    id,
                    None,
                    None,
                    action.clone(),
                    Some(Payload::Ring(payload.clone())),
                );
                assert_eq!(
                    message.verify(),
                    same_payload_kind,
                    "{action:?} with the payload of {other_action:?}"
                );
            }
        }

        // A ring payload on an action that is not a ring action is refused, and so is a ring
        // action that is not `shape_ok`'s to judge.
        let (_, payload) = &all[1];
        let fiat = Message::new_order(
            id,
            None,
            None,
            Action::FiatSent,
            Some(Payload::Ring(payload.clone())),
        );
        assert!(!fiat.verify());
        assert!(!is_ring_action(&Action::LeaseOffer));
        assert!(!shape_ok(
            &Action::FiatSent,
            true,
            Some(&Payload::Ring(payload.clone()))
        ));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let ms = members(2);
        let seat = serde_json::to_value(ms[0].seat()).unwrap();
        let mut extra = seat.clone();
        extra["alias"] = serde_json::json!("a node");
        assert!(serde_json::from_value::<RingSeat>(seat).is_ok());
        assert!(serde_json::from_value::<RingSeat>(extra).is_err());

        let mut offer = serde_json::to_value(offer(&ms[0], 2)).unwrap();
        offer["rules"] = serde_json::json!("min_channels=3");
        assert!(serde_json::from_value::<RingOffer>(offer).is_err());

        let mut edge = serde_json::json!({
            "ring_id": "ab".repeat(32),
            "funding_txid": "cd".repeat(32),
            "output_index": 0
        });
        assert!(serde_json::from_value::<RingEdge>(edge.clone()).is_ok());
        edge["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<RingEdge>(edge).is_err());
    }
}
