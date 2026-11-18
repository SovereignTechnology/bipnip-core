//! What travels between a lease's buyer, its seller and the instance (bipnip draft "Liquidity
//! leases"): the payloads of the lease [`Action`]s, with the checks every receiver runs before
//! acting on one.
//!
//! | action | direction | payload |
//! |---|---|---|
//! | `lease-offer` | seller → instance; echoed back with the order id | [`LeasePayload::Offer`] |
//! | `take-lease` | buyer → instance → seller | [`LeasePayload::Take`] |
//! | `lease-invoice` | seller → instance → buyer | [`LeasePayload::Invoice`] |
//! | `lease-channel-opened` | seller → instance → buyer | [`LeasePayload::Channel`] |
//! | `lease-preimage` | buyer → seller, peer to peer, never through the instance | [`LeasePayload::Preimage`] |
//! | `lease-active` | seller → instance → buyer | none |
//! | `lease-completion-invoice` | seller → instance → buyer | [`LeasePayload::Invoice`] |
//! | `lease-bond-invoice` | instance → buyer, when the offer asks for a bond | [`LeasePayload::Invoice`] |
//! | `lease-bond-claim` | instance → seller (none: "you are owed the bond"); seller → instance (its invoice) | none, or [`LeasePayload::Invoice`] |
//!
//! Only bipnip agents and instances send or understand these; upstream Mostro software refuses
//! them as unknown actions. Unknown fields are refused too: a party that does not understand part
//! of a lease message must not act on the rest of it.
//!
//! Everything here is pure: no node, no relay, no clock (callers pass `now`).

use std::fmt;
use std::str::FromStr;

use nostr_sdk::prelude::Event;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lease::{LeaseContract, LeaseError, LeaseTerms, MAX_CAPACITY_SAT, MIN_CAPACITY_SAT};
use crate::message::{Action, Payload};
use crate::node_binding::{
    Action as BindingAction, BindingError, Network, SignedStatement, MAX_FUTURE_SKEW_SECS,
};
use crate::rules::Rules;
#[cfg(test)]
use crate::rules::MAX_MIN_CAPACITY_SAT;

/// Longest binding event (as JSON) a lease message may carry.
pub const MAX_BINDING_JSON_LEN: usize = 4_096;
/// Longest BOLT 11 invoice a lease message may carry.
pub const MAX_INVOICE_LEN: usize = 4_096;
/// Longest `host:port` a lease message may carry (a DNS name is at most 253 bytes).
pub const MAX_NODE_ADDRESS_LEN: usize = 260;

/// Why a lease message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseMessageError {
    /// A field is malformed or out of range; the name says which.
    Field(&'static str),
    /// The terms or the contract are invalid, or do not match the offer.
    Lease(LeaseError),
    /// The binding event is invalid.
    Binding(BindingError),
    /// The binding is valid but is not a current-dated binding of this node to this Nostr key on
    /// this network; the reason says which part differs.
    BindingMismatch(&'static str),
}

impl fmt::Display for LeaseMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseMessageError::Field(what) => write!(f, "invalid lease message: {what}"),
            LeaseMessageError::Lease(e) => write!(f, "{e}"),
            LeaseMessageError::Binding(e) => write!(f, "invalid node binding: {e:?}"),
            LeaseMessageError::BindingMismatch(what) => {
                write!(f, "the node binding does not fit: {what}")
            }
        }
    }
}

impl std::error::Error for LeaseMessageError {}

impl From<LeaseError> for LeaseMessageError {
    fn from(e: LeaseError) -> Self {
        LeaseMessageError::Lease(e)
    }
}

impl From<BindingError> for LeaseMessageError {
    fn from(e: BindingError) -> Self {
        LeaseMessageError::Binding(e)
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(s, 64) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Some(out)
}

fn node_key(s: &str, what: &'static str) -> Result<PublicKey, LeaseMessageError> {
    if !is_lower_hex(s, 66) {
        return Err(LeaseMessageError::Field(what));
    }
    PublicKey::from_str(s).map_err(|_| LeaseMessageError::Field(what))
}

/// `host:port`, where host is a DNS name, an onion name, an IPv4 address, or an IPv6 address in
/// brackets, and port is 1..=65535 without leading zeros. Shape only: nothing is resolved.
pub(crate) fn valid_node_address(s: &str) -> bool {
    if s.len() > MAX_NODE_ADDRESS_LEN {
        return false;
    }
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && !port.starts_with('0')
        && port.parse::<u16>().is_ok();
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => {
            !v6.is_empty()
                && v6
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        }
        None => {
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
                && !host.starts_with(['.', '-'])
                && !host.ends_with(['.', '-'])
        }
    };
    port_ok && host_ok
}

/// BOLT 11 shape only (`ln…`, bech32 characters, bounded length). The buyer's agent parses and
/// checks the invoice itself before paying; this only keeps junk out of the pipeline.
pub(crate) fn valid_invoice_shape(s: &str) -> bool {
    s.len() <= MAX_INVOICE_LEN
        && s.len() > 20
        && s.starts_with("ln")
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Checks a binding event carried in a lease message: the event and the node's signature verify,
/// it is a binding (not a revocation) of `node` to `nostr_pubkey` on `network`, and it is not
/// dated further ahead than the allowed clock skew.
///
/// This proves the node once vouched for the key. It cannot prove the node has not revoked the
/// binding since: a receiver that can reach relays must still look for a newer statement
/// ([`crate::node_binding::is_bound`]).
pub fn check_binding(
    binding_json: &str,
    node: &PublicKey,
    network: Network,
    nostr_pubkey: &str,
    now: u64,
) -> Result<SignedStatement, LeaseMessageError> {
    if binding_json.is_empty() || binding_json.len() > MAX_BINDING_JSON_LEN {
        return Err(LeaseMessageError::Field("binding"));
    }
    let event = Event::from_json(binding_json).map_err(|_| LeaseMessageError::Field("binding"))?;
    let signed = SignedStatement::from_event(&event)?;
    let s = &signed.statement;
    if s.action != BindingAction::Bind {
        return Err(LeaseMessageError::BindingMismatch("it is a revocation"));
    }
    if &s.node_pubkey != node {
        return Err(LeaseMessageError::BindingMismatch("another node"));
    }
    if s.network != network {
        return Err(LeaseMessageError::BindingMismatch("another network"));
    }
    if s.nostr_pubkey != nostr_pubkey {
        return Err(LeaseMessageError::BindingMismatch("another Nostr key"));
    }
    if s.created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(LeaseMessageError::BindingMismatch("dated in the future"));
    }
    Ok(signed)
}

/// A seller's standing offer: any capacity in a range, at one price formula.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseOffer {
    /// The network the seller's node is on.
    pub network: Network,
    /// The seller's node key, 66 lower-case hex characters.
    pub seller_node: String,
    /// The seller's binding event (kind 31735) as JSON; see [`check_binding`].
    pub binding: String,
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
    /// Unix seconds after which the offer can no longer be taken.
    pub expires_at: u64,
    /// What the buyer locks at the instance while the lease is set up, in satoshi; 0 for none.
    /// It goes to the seller if the seller's channel shows in the instance's graph and the buyer
    /// never released the preimage. Needs an announced channel: the instance takes a bond only
    /// on what its own node can see.
    pub bond_sat: u64,
    /// What the buyer's node must show in the public graph to take the offer ([`Rules`]).
    /// Absent when none is set.
    #[serde(default, skip_serializing_if = "Rules::is_none")]
    pub rules: Rules,
}

impl LeaseOffer {
    /// The seller's node key.
    pub fn seller_node_key(&self) -> Result<PublicKey, LeaseMessageError> {
        node_key(&self.seller_node, "seller_node")
    }

    /// Checks the node key's form, the capacity range, and that the terms are valid at both ends
    /// of the range (the fee grows with capacity, so every capacity in between is valid too).
    /// The binding is checked separately ([`LeaseOffer::check_binding`]): it needs the sender's
    /// Nostr key and a clock.
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        self.seller_node_key()?;
        if self.min_capacity_sat > self.max_capacity_sat
            || self.min_capacity_sat < MIN_CAPACITY_SAT
            || self.max_capacity_sat > MAX_CAPACITY_SAT
        {
            return Err(LeaseMessageError::Field("capacity range"));
        }
        self.terms_unchecked(self.min_capacity_sat).validate()?;
        self.terms_unchecked(self.max_capacity_sat).validate()?;
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_JSON_LEN {
            return Err(LeaseMessageError::Field("binding"));
        }
        if self.expires_at == 0 {
            return Err(LeaseMessageError::Field("expires_at"));
        }
        let bond_ok = crate::bond::bond_amount_ok(self.bond_sat)
            && (self.bond_sat == 0 || (self.announce && self.bond_sat <= self.min_capacity_sat));
        if !bond_ok {
            return Err(LeaseMessageError::Field("bond_sat"));
        }
        self.rules
            .validate()
            .map_err(|_| LeaseMessageError::Field("rules"))?;
        Ok(())
    }

    /// The seller's binding, checked against the Nostr key that sent the offer.
    pub fn check_binding(
        &self,
        sender_nostr_pubkey: &str,
        now: u64,
    ) -> Result<SignedStatement, LeaseMessageError> {
        check_binding(
            &self.binding,
            &self.seller_node_key()?,
            self.network,
            sender_nostr_pubkey,
            now,
        )
    }

    /// True once the offer can no longer be taken.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
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

    /// The terms of a lease of `capacity_sat` under this offer; refused outside the range.
    pub fn terms_for(&self, capacity_sat: u64) -> Result<LeaseTerms, LeaseMessageError> {
        if !(self.min_capacity_sat..=self.max_capacity_sat).contains(&capacity_sat) {
            return Err(LeaseMessageError::Field("capacity outside the offer"));
        }
        let terms = self.terms_unchecked(capacity_sat);
        terms.validate()?;
        Ok(terms)
    }

    /// Checks that a buyer's contract is this offer taken at an allowed capacity: same network,
    /// same seller node, and terms exactly those the offer gives for the contract's capacity.
    /// Seller and instance both run this before going on; nothing a buyer writes into a contract
    /// can change the price.
    pub fn check_contract(&self, contract: &LeaseContract) -> Result<(), LeaseMessageError> {
        contract.validate()?;
        if contract.network != self.network {
            return Err(LeaseMessageError::Field("contract network"));
        }
        if contract.seller_node != self.seller_node_key()? {
            return Err(LeaseMessageError::Field("contract seller node"));
        }
        if contract.terms != self.terms_for(contract.terms.capacity_sat)? {
            return Err(LeaseMessageError::Field(
                "contract terms differ from the offer",
            ));
        }
        Ok(())
    }
}

/// A buyer takes an offer: the contract it made (which names its node and carries the payment
/// hash, never the preimage), its binding, and where its node can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTake {
    /// The canonical contract text ([`LeaseContract::text`]).
    pub contract: String,
    /// The buyer's binding event (kind 31735) as JSON; see [`check_binding`].
    pub binding: String,
    /// `host:port` of the buyer's node, when the seller's node cannot find it in the graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_address: Option<String>,
}

impl LeaseTake {
    /// Parses the contract and checks the other fields' form. The binding is checked separately
    /// ([`LeaseTake::check_binding`]).
    pub fn validate(&self) -> Result<LeaseContract, LeaseMessageError> {
        let contract = LeaseContract::parse(&self.contract)?;
        if self.binding.is_empty() || self.binding.len() > MAX_BINDING_JSON_LEN {
            return Err(LeaseMessageError::Field("binding"));
        }
        if let Some(address) = &self.node_address {
            if !valid_node_address(address) {
                return Err(LeaseMessageError::Field("node_address"));
            }
        }
        Ok(contract)
    }

    /// The buyer's binding, checked against the contract's buyer node and network and the Nostr
    /// key that sent the take.
    pub fn check_binding(
        &self,
        contract: &LeaseContract,
        sender_nostr_pubkey: &str,
        now: u64,
    ) -> Result<SignedStatement, LeaseMessageError> {
        check_binding(
            &self.binding,
            &contract.buyer_node,
            contract.network,
            sender_nostr_pubkey,
            now,
        )
    }
}

/// An invoice from the seller: the upfront hold invoice (`lease-invoice`) or the completion
/// invoice (`lease-completion-invoice`). The buyer's agent checks the invoice itself against the
/// contract before paying; nothing here vouches for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseInvoice {
    /// The lease id ([`LeaseContract::id`]).
    pub lease_id: String,
    /// The BOLT 11 invoice.
    pub invoice: String,
}

impl LeaseInvoice {
    /// Checks the id's form and the invoice's shape.
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        if !is_lower_hex(&self.lease_id, 64) {
            return Err(LeaseMessageError::Field("lease_id"));
        }
        if !valid_invoice_shape(&self.invoice) {
            return Err(LeaseMessageError::Field("invoice"));
        }
        Ok(())
    }
}

/// The seller reports the channel it opened. A claim only: the buyer's own node decides whether
/// the channel exists and fits the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseChannel {
    /// The lease id ([`LeaseContract::id`]).
    pub lease_id: String,
    /// The funding transaction id, 64 lower-case hex characters.
    pub funding_txid: String,
    /// The funding output's index in that transaction.
    pub output_index: u32,
}

impl LeaseChannel {
    /// Checks the id's and the txid's form.
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        if !is_lower_hex(&self.lease_id, 64) {
            return Err(LeaseMessageError::Field("lease_id"));
        }
        if !is_lower_hex(&self.funding_txid, 64) {
            return Err(LeaseMessageError::Field("funding_txid"));
        }
        Ok(())
    }

    /// The channel point, `<txid>:<index>`.
    pub fn channel_point(&self) -> String {
        format!("{}:{}", self.funding_txid, self.output_index)
    }
}

/// The buyer releases the preimage to the seller. Sent peer to peer only, and only after the
/// buyer's own node has verified the channel; an instance never sees it.
///
/// `Debug` does not print the preimage.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasePreimage {
    /// The lease id ([`LeaseContract::id`]).
    pub lease_id: String,
    /// The preimage, 64 lower-case hex characters.
    pub preimage: String,
}

impl fmt::Debug for LeasePreimage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasePreimage")
            .field("lease_id", &self.lease_id)
            .field("preimage", &"<redacted>")
            .finish()
    }
}

impl LeasePreimage {
    /// Checks the id's and the preimage's form.
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        if !is_lower_hex(&self.lease_id, 64) {
            return Err(LeaseMessageError::Field("lease_id"));
        }
        if hex32(&self.preimage).is_none() {
            return Err(LeaseMessageError::Field("preimage"));
        }
        Ok(())
    }

    /// True when this message is for `contract` and its preimage hashes to the contract's payment
    /// hash. The seller checks this before asking its node to settle.
    pub fn opens(&self, contract: &LeaseContract) -> bool {
        let Some(preimage) = hex32(&self.preimage) else {
            return false;
        };
        let Some(expected) = hex32(&contract.payment_hash) else {
            return false;
        };
        self.lease_id == contract.id() && Sha256::digest(preimage).as_slice() == expected
    }
}

/// The payload of a lease action; see the table in the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePayload {
    /// With [`Action::LeaseOffer`].
    Offer(LeaseOffer),
    /// With [`Action::TakeLease`].
    Take(LeaseTake),
    /// With [`Action::LeaseInvoice`] and [`Action::LeaseCompletionInvoice`].
    Invoice(LeaseInvoice),
    /// With [`Action::LeaseChannelOpened`].
    Channel(LeaseChannel),
    /// With [`Action::LeasePreimage`].
    Preimage(LeasePreimage),
}

impl LeasePayload {
    /// Runs the carried type's own `validate` (form and ranges; no binding, no clock).
    pub fn validate(&self) -> Result<(), LeaseMessageError> {
        match self {
            LeasePayload::Offer(offer) => offer.validate(),
            LeasePayload::Take(take) => take.validate().map(|_| ()),
            LeasePayload::Invoice(invoice) => invoice.validate(),
            LeasePayload::Channel(channel) => channel.validate(),
            LeasePayload::Preimage(preimage) => preimage.validate(),
        }
    }
}

/// True for the actions this module owns.
pub fn is_lease_action(action: &Action) -> bool {
    matches!(
        action,
        Action::LeaseOffer
            | Action::TakeLease
            | Action::LeaseInvoice
            | Action::LeaseChannelOpened
            | Action::LeasePreimage
            | Action::LeaseActive
            | Action::LeaseCompletionInvoice
            | Action::LeaseBondInvoice
            | Action::LeaseBondClaim
    )
}

/// The shape rule [`crate::message::MessageKind::verify`] applies to lease actions: which
/// payload each carries, and that every one but a seller's first `lease-offer` names an order.
/// Returns `false` for any other action.
pub fn shape_ok(action: &Action, has_id: bool, payload: Option<&Payload>) -> bool {
    let lease = match payload {
        Some(Payload::Lease(lease)) => Some(lease),
        Some(_) => return false,
        None => None,
    };
    match action {
        Action::LeaseOffer => matches!(lease, Some(LeasePayload::Offer(_))),
        Action::TakeLease => has_id && matches!(lease, Some(LeasePayload::Take(_))),
        Action::LeaseInvoice | Action::LeaseCompletionInvoice | Action::LeaseBondInvoice => {
            has_id && matches!(lease, Some(LeasePayload::Invoice(_)))
        }
        // Without a payload it is the instance telling the seller it is owed the bond; with an
        // invoice it is the seller's claim.
        Action::LeaseBondClaim => has_id && matches!(lease, None | Some(LeasePayload::Invoice(_))),
        Action::LeaseChannelOpened => has_id && matches!(lease, Some(LeasePayload::Channel(_))),
        Action::LeasePreimage => has_id && matches!(lease, Some(LeasePayload::Preimage(_))),
        Action::LeaseActive => has_id && lease.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, MessageKind};
    use crate::node_binding::{sign_ln_message, Statement};
    use nostr_sdk::prelude::{FinalizeEvent, Keys};
    use secp256k1::{Secp256k1, SecretKey};
    use uuid::Uuid;

    const NOW: u64 = 1_794_800_000;

    fn secret(n: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = n;
        SecretKey::from_slice(&b).expect("key")
    }

    fn node(n: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret(n))
    }

    fn binding(
        action: BindingAction,
        nostr: &Keys,
        node_n: u8,
        network: Network,
        ts: u64,
    ) -> String {
        let statement = Statement::new(
            action,
            network,
            &nostr.public_key().to_hex(),
            node(node_n),
            ts,
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

    fn offer(seller: &Keys) -> LeaseOffer {
        LeaseOffer {
            network: Network::Regtest,
            seller_node: node(1).to_string(),
            binding: binding(BindingAction::Bind, seller, 1, Network::Regtest, NOW - 60),
            min_capacity_sat: 1_000_000,
            max_capacity_sat: 5_000_000,
            duration_blocks: 4_320,
            fee_base_sat: 1_000,
            fee_ppm: 2_500,
            upfront_percent: 50,
            min_confirmations: 3,
            announce: true,
            expires_at: NOW + 86_400,
            bond_sat: 0,
            rules: Rules::default(),
        }
    }

    fn contract(offer: &LeaseOffer, capacity_sat: u64, preimage: [u8; 32]) -> LeaseContract {
        let payment_hash = Sha256::digest(preimage)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        LeaseContract {
            network: offer.network,
            seller_node: offer.seller_node_key().expect("seller"),
            buyer_node: node(2),
            terms: offer.terms_for(capacity_sat).expect("terms"),
            payment_hash,
            created_at: NOW,
        }
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn an_offer_validates_and_prices_every_capacity_in_range() {
        let seller = Keys::generate();
        let o = offer(&seller);
        assert_eq!(o.validate(), Ok(()));
        let t = o.terms_for(2_000_000).expect("in range");
        assert_eq!(t.total_fee_sat(), Ok(6_000));
        assert_eq!(
            o.terms_for(999_999),
            Err(LeaseMessageError::Field("capacity outside the offer"))
        );
        assert_eq!(
            o.terms_for(5_000_001),
            Err(LeaseMessageError::Field("capacity outside the offer"))
        );
        assert!(!o.is_expired(NOW));
        assert!(o.is_expired(NOW + 86_400));
    }

    #[test]
    fn a_bad_offer_is_refused() {
        let seller = Keys::generate();
        let good = offer(&seller);
        let refused = |change: fn(&mut LeaseOffer)| {
            let mut o = good.clone();
            change(&mut o);
            o.validate().is_err()
        };
        assert!(refused(|o| o.seller_node = o.seller_node.to_uppercase()));
        // 0x05 is not a compressed-key prefix.
        assert!(refused(|o| o.seller_node = format!("05{}", "11".repeat(32))));
        assert!(refused(|o| o.min_capacity_sat = o.max_capacity_sat + 1));
        assert!(refused(|o| o.min_capacity_sat = MIN_CAPACITY_SAT - 1));
        assert!(refused(|o| o.max_capacity_sat = MAX_CAPACITY_SAT + 1));
        assert!(refused(|o| o.upfront_percent = 0));
        assert!(refused(|o| o.duration_blocks = 0));
        assert!(refused(|o| o.binding = String::new()));
        assert!(refused(|o| o.binding = "x".repeat(MAX_BINDING_JSON_LEN + 1)));
        assert!(refused(|o| o.expires_at = 0));
        // A fee that is zero at the small end of the range is refused even if it is not at the
        // large end.
        assert!(refused(|o| {
            o.fee_base_sat = 0;
            o.fee_ppm = 1;
            o.min_capacity_sat = MIN_CAPACITY_SAT;
        }));
    }

    #[test]
    fn a_binding_must_be_this_nodes_current_word_for_the_sender() {
        let seller = Keys::generate();
        let other = Keys::generate();
        let o = offer(&seller);
        let me = seller.public_key().to_hex();
        assert!(o.check_binding(&me, NOW).is_ok());
        assert_eq!(
            o.check_binding(&other.public_key().to_hex(), NOW),
            Err(LeaseMessageError::BindingMismatch("another Nostr key"))
        );

        let with = |binding: String| LeaseOffer {
            binding,
            ..o.clone()
        };
        let other_node = with(binding(
            BindingAction::Bind,
            &seller,
            3,
            Network::Regtest,
            NOW,
        ));
        assert_eq!(
            other_node.check_binding(&me, NOW),
            Err(LeaseMessageError::BindingMismatch("another node"))
        );
        let other_net = with(binding(
            BindingAction::Bind,
            &seller,
            1,
            Network::Signet,
            NOW,
        ));
        assert_eq!(
            other_net.check_binding(&me, NOW),
            Err(LeaseMessageError::BindingMismatch("another network"))
        );
        let revoked = with(binding(
            BindingAction::Revoke,
            &seller,
            1,
            Network::Regtest,
            NOW,
        ));
        assert_eq!(
            revoked.check_binding(&me, NOW),
            Err(LeaseMessageError::BindingMismatch("it is a revocation"))
        );
        let ahead = MAX_FUTURE_SKEW_SECS + 1;
        let future = with(binding(
            BindingAction::Bind,
            &seller,
            1,
            Network::Regtest,
            NOW + ahead,
        ));
        assert_eq!(
            future.check_binding(&me, NOW),
            Err(LeaseMessageError::BindingMismatch("dated in the future"))
        );
        // A tampered event fails its own signature.
        let tampered = with(o.binding.replacen("regtest", "signet", 1));
        assert!(matches!(
            tampered.check_binding(&me, NOW),
            Err(LeaseMessageError::Binding(_))
        ));
        assert_eq!(
            with("not json".into()).check_binding(&me, NOW),
            Err(LeaseMessageError::Field("binding"))
        );
    }

    #[test]
    fn a_contract_must_be_the_offer_at_an_allowed_capacity() {
        let seller = Keys::generate();
        let o = offer(&seller);
        let good = contract(&o, 2_000_000, [7; 32]);
        assert_eq!(o.check_contract(&good), Ok(()));

        let mut cheaper = good.clone();
        cheaper.terms.fee_ppm -= 1;
        assert_eq!(
            o.check_contract(&cheaper),
            Err(LeaseMessageError::Field(
                "contract terms differ from the offer"
            ))
        );
        let mut shorter_wait = good.clone();
        shorter_wait.terms.min_confirmations = 1;
        assert!(o.check_contract(&shorter_wait).is_err());
        let mut private = good.clone();
        private.terms.announce = false;
        assert!(o.check_contract(&private).is_err());
        let mut too_big = good.clone();
        too_big.terms.capacity_sat = 5_000_001;
        assert_eq!(
            o.check_contract(&too_big),
            Err(LeaseMessageError::Field("capacity outside the offer"))
        );
        let mut other_seller = good.clone();
        other_seller.seller_node = node(3);
        assert_eq!(
            o.check_contract(&other_seller),
            Err(LeaseMessageError::Field("contract seller node"))
        );
        let mut other_net = good.clone();
        other_net.network = Network::Signet;
        assert_eq!(
            o.check_contract(&other_net),
            Err(LeaseMessageError::Field("contract network"))
        );
        let mut to_self = good;
        to_self.buyer_node = to_self.seller_node;
        assert!(matches!(
            o.check_contract(&to_self),
            Err(LeaseMessageError::Lease(_))
        ));
    }

    #[test]
    fn a_take_carries_a_canonical_contract_and_the_buyers_binding() {
        let seller = Keys::generate();
        let buyer = Keys::generate();
        let o = offer(&seller);
        let c = contract(&o, 2_000_000, [7; 32]);
        let take = LeaseTake {
            contract: c.text(),
            binding: binding(BindingAction::Bind, &buyer, 2, Network::Regtest, NOW - 5),
            node_address: Some("203.0.113.7:9735".into()),
        };
        let parsed = take.validate().expect("valid take");
        assert_eq!(parsed, c);
        assert!(take
            .check_binding(&parsed, &buyer.public_key().to_hex(), NOW)
            .is_ok());
        // The seller's binding does not pass for the buyer.
        let stolen = LeaseTake {
            binding: o.binding.clone(),
            ..take.clone()
        };
        assert!(stolen
            .check_binding(&parsed, &seller.public_key().to_hex(), NOW)
            .is_err());

        let not_canonical = LeaseTake {
            contract: format!("{} ", c.text()),
            ..take.clone()
        };
        assert!(matches!(
            not_canonical.validate(),
            Err(LeaseMessageError::Lease(_))
        ));
        let no_address = LeaseTake {
            node_address: None,
            ..take.clone()
        };
        assert!(no_address.validate().is_ok());
        assert!(!serde_json::to_string(&no_address)
            .expect("json")
            .contains("node_address"));
    }

    #[test]
    fn node_addresses_are_checked_by_shape() {
        for good in [
            "203.0.113.7:9735",
            "node.example.com:9735",
            "[2001:db8::1]:9735",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9735",
            "localhost:1",
        ] {
            assert!(valid_node_address(good), "{good}");
        }
        let long = format!("{}:9735", "a".repeat(254));
        for bad in [
            "",
            "node.example.com",
            ":9735",
            "node.example.com:",
            "node.example.com:0",
            "node.example.com:09735",
            "node.example.com:65536",
            "node.example.com:+973",
            "node example.com:9735",
            "node.example.com:9735\n",
            "user@node.example.com:9735",
            "-node.example.com:9735",
            "node.example.com.:9735",
            "2001:db8::1:9735:x",
            "[]:9735",
            "[2001:db8::1%eth0]:9735",
            "http://node.example.com:9735",
            long.as_str(),
        ] {
            assert!(!valid_node_address(bad), "{bad:?}");
        }
    }

    #[test]
    fn invoice_channel_and_preimage_are_checked_by_form() {
        let id = "ab".repeat(32);
        let invoice = LeaseInvoice {
            lease_id: id.clone(),
            invoice: format!("lnbcrt30u1{}", "q".repeat(200)),
        };
        assert_eq!(invoice.validate(), Ok(()));
        for bad in [
            "".to_string(),
            "lnbcrt1".to_string(),
            format!("LNBCRT30U1{}", "Q".repeat(200)),
            format!("bc1q{}", "q".repeat(200)),
            format!("lnbcrt30u1{} ", "q".repeat(200)),
            format!("ln{}", "q".repeat(MAX_INVOICE_LEN)),
        ] {
            let i = LeaseInvoice {
                invoice: bad,
                ..invoice.clone()
            };
            assert_eq!(i.validate(), Err(LeaseMessageError::Field("invoice")));
        }
        let short_id = LeaseInvoice {
            lease_id: "ab".repeat(31),
            ..invoice
        };
        assert_eq!(
            short_id.validate(),
            Err(LeaseMessageError::Field("lease_id"))
        );

        let channel = LeaseChannel {
            lease_id: id.clone(),
            funding_txid: "cd".repeat(32),
            output_index: 1,
        };
        assert_eq!(channel.validate(), Ok(()));
        assert_eq!(channel.channel_point(), format!("{}:1", "cd".repeat(32)));
        let upper = LeaseChannel {
            funding_txid: "CD".repeat(32),
            ..channel
        };
        assert_eq!(
            upper.validate(),
            Err(LeaseMessageError::Field("funding_txid"))
        );

        let preimage = LeasePreimage {
            lease_id: id,
            preimage: "zz".repeat(32),
        };
        assert_eq!(
            preimage.validate(),
            Err(LeaseMessageError::Field("preimage"))
        );
    }

    #[test]
    fn only_the_right_preimage_for_this_lease_opens_it() {
        let seller = Keys::generate();
        let o = offer(&seller);
        let c = contract(&o, 2_000_000, [7; 32]);
        let good = LeasePreimage {
            lease_id: c.id(),
            preimage: hex([7; 32]),
        };
        assert_eq!(good.validate(), Ok(()));
        assert!(good.opens(&c));
        let wrong = LeasePreimage {
            preimage: hex([8; 32]),
            ..good.clone()
        };
        assert!(!wrong.opens(&c));
        // The right preimage under another lease's id is refused too.
        let other = contract(&o, 3_000_000, [7; 32]);
        assert!(!good.opens(&other));
        let malformed = LeasePreimage {
            preimage: "07".repeat(31),
            ..good
        };
        assert!(!malformed.opens(&c));
    }

    #[test]
    fn debug_never_prints_the_preimage() {
        let secret_hex = hex([7; 32]);
        let p = LeasePreimage {
            lease_id: "ab".repeat(32),
            preimage: secret_hex.clone(),
        };
        let direct = format!("{p:?}");
        let nested = format!("{:?}", Payload::Lease(LeasePayload::Preimage(p.clone())));
        let message = format!(
            "{:?}",
            Message::Order(MessageKind::new(
                Some(Uuid::new_v4()),
                None,
                None,
                Action::LeasePreimage,
                Some(Payload::Lease(LeasePayload::Preimage(p))),
            ))
        );
        for text in [direct, nested, message] {
            assert!(!text.contains(&secret_hex), "{text}");
            assert!(text.contains("<redacted>"));
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let seller = Keys::generate();
        let mut json = serde_json::to_value(offer(&seller)).expect("json");
        assert!(serde_json::from_value::<LeaseOffer>(json.clone()).is_ok());
        json["fee_discount"] = serde_json::json!(100);
        assert!(serde_json::from_value::<LeaseOffer>(json).is_err());
        let extra = r#"{"lease_id":"ab","preimage":"cd","note":"x"}"#;
        assert!(serde_json::from_str::<LeasePreimage>(extra).is_err());
        let unknown_network = r#""mainnet""#;
        assert!(serde_json::from_str::<Network>(unknown_network).is_err());
    }

    #[test]
    fn wire_format_is_stable() {
        let id = Uuid::parse_str("308e1272-d5f4-47e6-bd97-3504baea9c23").expect("uuid");
        let channel = LeaseChannel {
            lease_id: "ab".repeat(32),
            funding_txid: "cd".repeat(32),
            output_index: 1,
        };
        let message = Message::Order(MessageKind::new(
            Some(id),
            None,
            None,
            Action::LeaseChannelOpened,
            Some(Payload::Lease(LeasePayload::Channel(channel))),
        ));
        let json = message.as_json().expect("json");
        let expected = format!(
            concat!(
                r#"{{"order":{{"version":{},"request_id":null,"trade_index":null,"#,
                r#""id":"308e1272-d5f4-47e6-bd97-3504baea9c23","#,
                r#""action":"lease-channel-opened","payload":{{"lease":{{"channel":{{"#,
                r#""lease_id":"{}","funding_txid":"{}","output_index":1}}}}}}}}}}"#
            ),
            crate::prelude::PROTOCOL_VER,
            "ab".repeat(32),
            "cd".repeat(32)
        );
        assert_eq!(json, expected);
        let back = Message::from_json(&json).expect("parses");
        assert!(back.verify());
        assert_eq!(back.inner_action(), Some(Action::LeaseChannelOpened));

        for (action, name) in [
            (Action::LeaseOffer, "lease-offer"),
            (Action::TakeLease, "take-lease"),
            (Action::LeaseInvoice, "lease-invoice"),
            (Action::LeaseChannelOpened, "lease-channel-opened"),
            (Action::LeasePreimage, "lease-preimage"),
            (Action::LeaseActive, "lease-active"),
            (Action::LeaseCompletionInvoice, "lease-completion-invoice"),
            (Action::LeaseBondInvoice, "lease-bond-invoice"),
            (Action::LeaseBondClaim, "lease-bond-claim"),
        ] {
            assert!(is_lease_action(&action));
            assert_eq!(
                serde_json::to_string(&action).expect("json"),
                format!("\"{name}\"")
            );
        }
        assert!(!is_lease_action(&Action::NewOrder));
        assert_eq!(
            serde_json::to_string(&Network::Testnet4).expect("json"),
            "\"testnet4\""
        );
    }

    #[test]
    fn each_action_takes_only_its_own_payload() {
        let seller = Keys::generate();
        let buyer = Keys::generate();
        let o = offer(&seller);
        let c = contract(&o, 2_000_000, [7; 32]);
        let id = "ab".repeat(32);
        let payloads = [
            LeasePayload::Offer(o.clone()),
            LeasePayload::Take(LeaseTake {
                contract: c.text(),
                binding: binding(BindingAction::Bind, &buyer, 2, Network::Regtest, NOW),
                node_address: None,
            }),
            LeasePayload::Invoice(LeaseInvoice {
                lease_id: id.clone(),
                invoice: format!("lnbcrt30u1{}", "q".repeat(200)),
            }),
            LeasePayload::Channel(LeaseChannel {
                lease_id: id.clone(),
                funding_txid: "cd".repeat(32),
                output_index: 0,
            }),
            LeasePayload::Preimage(LeasePreimage {
                lease_id: id,
                preimage: hex([7; 32]),
            }),
        ];
        // (action, index of the one payload it takes; None = no payload at all)
        let rules = [
            (Action::LeaseOffer, Some(0)),
            (Action::TakeLease, Some(1)),
            (Action::LeaseInvoice, Some(2)),
            (Action::LeaseCompletionInvoice, Some(2)),
            (Action::LeaseBondInvoice, Some(2)),
            (Action::LeaseChannelOpened, Some(3)),
            (Action::LeasePreimage, Some(4)),
            (Action::LeaseActive, None),
        ];
        let kind = |action: &Action, id: bool, payload: Option<Payload>| {
            MessageKind::new(id.then(Uuid::new_v4), None, None, action.clone(), payload)
        };
        for (action, takes) in &rules {
            for (i, payload) in payloads.iter().enumerate() {
                assert_eq!(payload.validate(), Ok(()));
                let with = kind(action, true, Some(Payload::Lease(payload.clone())));
                assert_eq!(with.verify(), *takes == Some(i), "{action:?} with {i}");
            }
            assert_eq!(kind(action, true, None).verify(), takes.is_none());
            let foreign = kind(action, true, Some(Payload::TextMessage("hi".into())));
            assert!(!foreign.verify(), "{action:?} with a text payload");
            // Only a seller's first offer may come without an order id.
            let own = takes.map(|i| Payload::Lease(payloads[i].clone()));
            assert_eq!(
                kind(action, false, own).verify(),
                *action == Action::LeaseOffer,
                "{action:?} without an id"
            );
        }
        // The bond claim travels both ways: without a payload it tells the seller it is owed
        // the bond; with an invoice it is the seller's claim. Nothing else fits it.
        for (i, payload) in payloads.iter().enumerate() {
            let with = kind(
                &Action::LeaseBondClaim,
                true,
                Some(Payload::Lease(payload.clone())),
            );
            assert_eq!(with.verify(), i == 2, "lease-bond-claim with {i}");
        }
        assert!(kind(&Action::LeaseBondClaim, true, None).verify());
        assert!(!kind(&Action::LeaseBondClaim, false, None).verify());

        // A bond needs an announced channel and cannot exceed the smallest channel on offer.
        let mut bonded = o.clone();
        bonded.bond_sat = 50_000;
        assert_eq!(bonded.validate(), Ok(()));
        let mut private = bonded.clone();
        private.announce = false;
        assert_eq!(
            private.validate(),
            Err(LeaseMessageError::Field("bond_sat"))
        );
        let mut huge = bonded.clone();
        huge.bond_sat = huge.min_capacity_sat + 1;
        assert_eq!(huge.validate(), Err(LeaseMessageError::Field("bond_sat")));
        let mut dust = bonded.clone();
        dust.bond_sat = crate::bond::MIN_BOND_SAT - 1;
        assert_eq!(dust.validate(), Err(LeaseMessageError::Field("bond_sat")));

        // Upstream actions refuse a lease payload.
        for action in [
            Action::Release,
            Action::Cancel,
            Action::SendDm,
            Action::FiatSent,
        ] {
            let smuggled = kind(&action, true, Some(Payload::Lease(payloads[4].clone())));
            assert!(!smuggled.verify(), "{action:?}");
        }
        let as_order = kind(
            &Action::NewOrder,
            false,
            Some(Payload::Lease(payloads[0].clone())),
        );
        assert!(!as_order.verify());
    }

    #[test]
    fn an_offer_without_rules_is_written_as_before_and_one_with_rules_carries_them() {
        let seller = Keys::generate();
        let plain = offer(&seller);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("rules").is_none(), "{json}");
        let mut strict = plain.clone();
        strict.rules.min_channels = 3;
        let json = serde_json::to_value(&strict).unwrap();
        assert_eq!(json["rules"], serde_json::json!({"min_channels": 3}));
        assert_eq!(serde_json::from_value::<LeaseOffer>(json).unwrap(), strict);
        strict.rules.min_capacity_sat = MAX_MIN_CAPACITY_SAT + 1;
        assert_eq!(strict.validate(), Err(LeaseMessageError::Field("rules")));
    }
}
