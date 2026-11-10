//! Lightning node ↔ Nostr key binding (bipnip NIP draft "Lightning node ↔ Nostr key").
//!
//! A binding is a statement signed by **both** keys:
//!
//! * the Lightning node signs a canonical text statement with its identity key, in the
//!   message-signing format every implementation shares (LND `signmessage`, Core Lightning
//!   `signmessage` (`zbase`), LDK `util::message_signing`, ldk-node `sign_message`):
//!   `zbase32(31 + recid ‖ compact_sig(sha256d("Lightning Signed Message:" ‖ statement)))`;
//! * the Nostr key signs the addressable event ([`KIND_NODE_BINDING`]) that carries the statement
//!   and the node's signature.
//!
//! Anyone can check both signatures offline: the node key is *recovered* from its signature here,
//! never asked of a Lightning node (whose `verifymessage` only accepts keys in its own graph).
//!
//! The node key is the authority over its bindings: for one node, the newest node-signed
//! statement wins, and a revocation is a node-signed `revoke` statement. A stolen Nostr key
//! therefore cannot keep a binding alive after the node revokes it, and replaying an old
//! binding event loses to the newer revocation.
//!
//! Statement text (ASCII, `:`-separated, no spaces):
//!
//! ```text
//! nostr-node-binding:v1:<bind|revoke>:<network>:<nostr x-only pubkey, 64 hex>:<node pubkey, 66 hex>:<unix seconds>
//! ```

use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::{sha256d, Hash};
use nostr_sdk::prelude::{Event, EventBuilder, Kind, Tag, Timestamp};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message as SecpMessage, PublicKey, Secp256k1, SecretKey};

/// Prefix every Lightning implementation puts in front of a message before hashing it.
pub const LN_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";

/// Kind of a binding event (addressable; `d` = the node's compressed public key in hex).
/// Provisional until the NIP draft is agreed.
pub const KIND_NODE_BINDING: u16 = 31735;

/// First field of every statement.
pub const STATEMENT_TAG: &str = "nostr-node-binding";
/// Version field of every statement this module writes and accepts.
pub const STATEMENT_VERSION: &str = "v1";

/// Length of a zbase32-encoded 65-byte recoverable signature.
pub const ZBASE32_SIG_LEN: usize = 104;

/// Why a signature, statement or binding event was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The zbase32 text is not a 65-byte recoverable signature.
    SignatureEncoding,
    /// The recovery header byte is not 31..=34 (a compressed-key signature).
    RecoveryHeader(u8),
    /// The signature does not recover to a public key.
    Recovery,
    /// The statement text breaks the canonical form; the reason names the field.
    Statement(&'static str),
    /// The recovered node key is not the key the statement names.
    WrongSigner,
    /// The event breaks the binding-event rules; the reason names the rule.
    Event(&'static str),
    /// The Nostr event's own id or signature is invalid.
    EventSignature(String),
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::SignatureEncoding => {
                write!(
                    f,
                    "node signature is not a zbase32 65-byte recoverable signature"
                )
            }
            BindingError::RecoveryHeader(b) => {
                write!(
                    f,
                    "node signature header {b} is not 31..=34 (compressed key)"
                )
            }
            BindingError::Recovery => write!(f, "node signature does not recover to a public key"),
            BindingError::Statement(why) => write!(f, "invalid binding statement: {why}"),
            BindingError::WrongSigner => {
                write!(
                    f,
                    "node signature was made by a different key than the statement names"
                )
            }
            BindingError::Event(why) => write!(f, "invalid binding event: {why}"),
            BindingError::EventSignature(e) => write!(f, "binding event signature: {e}"),
        }
    }
}

impl std::error::Error for BindingError {}

/// zbase32 (Zooko's human-oriented base-32), as Lightning message signatures use it.
pub mod zbase32 {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    /// Encodes `data`, most significant bit first, without padding.
    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for &byte in data {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
        }
        out
    }

    /// Decodes zbase32 text. Rejects characters outside the alphabet (case-sensitive: the
    /// alphabet is lower-case) and non-zero leftover bits, so every byte string has exactly one
    /// accepted encoding.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() * 5 / 8);
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for c in text.bytes() {
            let value = ALPHABET.iter().position(|&a| a == c)? as u32;
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((buffer >> bits) & 0xff) as u8);
            }
            buffer &= (1 << bits) - 1;
        }
        if buffer != 0 || bits >= 5 {
            return None;
        }
        Some(out)
    }
}

/// `sha256d("Lightning Signed Message:" ‖ msg)`: the digest a Lightning node signs.
pub fn ln_message_digest(msg: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(LN_MESSAGE_PREFIX.len() + msg.len());
    data.extend_from_slice(LN_MESSAGE_PREFIX);
    data.extend_from_slice(msg);
    sha256d::Hash::hash(&data).to_byte_array()
}

/// Signs `msg` the way a Lightning node's `signmessage` does (used for tests and for keys the
/// agent holds itself; a real node signs through its own RPC).
pub fn sign_ln_message(msg: &[u8], secret_key: &SecretKey) -> String {
    let secp = Secp256k1::signing_only();
    let digest = SecpMessage::from_digest(ln_message_digest(msg));
    let sig = secp.sign_ecdsa_recoverable(&digest, secret_key);
    let (recid, compact) = sig.serialize_compact();
    let mut bytes = Vec::with_capacity(65);
    bytes.push(31 + i32::from(recid) as u8);
    bytes.extend_from_slice(&compact);
    zbase32::encode(&bytes)
}

fn decode_recoverable(zsig: &str) -> Result<RecoverableSignature, BindingError> {
    if zsig.len() != ZBASE32_SIG_LEN {
        return Err(BindingError::SignatureEncoding);
    }
    let bytes = zbase32::decode(zsig).ok_or(BindingError::SignatureEncoding)?;
    if bytes.len() != 65 {
        return Err(BindingError::SignatureEncoding);
    }
    let header = bytes[0];
    if !(31..=34).contains(&header) {
        return Err(BindingError::RecoveryHeader(header));
    }
    let recid = RecoveryId::try_from(i32::from(header - 31))
        .map_err(|_| BindingError::RecoveryHeader(header))?;
    RecoverableSignature::from_compact(&bytes[1..], recid)
        .map_err(|_| BindingError::SignatureEncoding)
}

/// Recovers the public key that produced a Lightning `signmessage` signature over `msg`.
pub fn recover_ln_signer(msg: &[u8], zsig: &str) -> Result<PublicKey, BindingError> {
    let sig = decode_recoverable(zsig)?;
    let secp = Secp256k1::verification_only();
    let digest = SecpMessage::from_digest(ln_message_digest(msg));
    secp.recover_ecdsa(&digest, &sig)
        .map_err(|_| BindingError::Recovery)
}

/// True when `zsig` is `node_key`'s Lightning signature over `msg`.
pub fn verify_ln_message(msg: &[u8], zsig: &str, node_key: &PublicKey) -> bool {
    matches!(recover_ln_signer(msg, zsig), Ok(k) if &k == node_key)
}

/// Converts a hex-encoded 65-byte recoverable signature (Eclair's `signmessage` output) into the
/// zbase32 form binding events carry.
pub fn hex_signature_to_zbase32(hex_sig: &str) -> Result<String, BindingError> {
    if hex_sig.len() != 130 {
        return Err(BindingError::SignatureEncoding);
    }
    let bytes = decode_lower_hex(hex_sig).ok_or(BindingError::SignatureEncoding)?;
    let z = zbase32::encode(&bytes);
    decode_recoverable(&z)?;
    Ok(z)
}

fn decode_lower_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some((digit(p[0])? << 4) | digit(p[1])?))
        .collect()
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Bitcoin network a node runs on; part of the signed statement so a signet binding can't be
/// replayed as a mainnet one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Mainnet.
    Bitcoin,
    /// Testnet3.
    Testnet,
    /// Testnet4.
    Testnet4,
    /// Signet.
    Signet,
    /// Regtest.
    Regtest,
}

impl Network {
    /// Canonical lower-case name used in statements and tags.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Bitcoin => "bitcoin",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
}

impl FromStr for Network {
    type Err = BindingError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "testnet4" => Ok(Network::Testnet4),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(BindingError::Statement("unknown network")),
        }
    }
}

/// Whether the node binds or revokes the Nostr key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// The node vouches for the Nostr key.
    Bind,
    /// The node withdraws a binding to the Nostr key.
    Revoke,
}

impl Action {
    /// Canonical name used in statements.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Bind => "bind",
            Action::Revoke => "revoke",
        }
    }
}

/// The text a node signs: who binds or revokes whom, on which network, when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Bind or revoke.
    pub action: Action,
    /// Network of the node.
    pub network: Network,
    /// The Nostr key, as 64 lower-case hex characters (x-only, as in Nostr events).
    pub nostr_pubkey: String,
    /// The node's identity key (compressed).
    pub node_pubkey: PublicKey,
    /// Unix seconds; the newest node-signed statement for a node wins.
    pub created_at: u64,
}

impl Statement {
    /// A new statement. `nostr_pubkey` must be 64 lower-case hex characters.
    pub fn new(
        action: Action,
        network: Network,
        nostr_pubkey: &str,
        node_pubkey: PublicKey,
        created_at: u64,
    ) -> Result<Self, BindingError> {
        if !is_lower_hex(nostr_pubkey, 64) {
            return Err(BindingError::Statement(
                "nostr pubkey must be 64 lower-case hex",
            ));
        }
        Ok(Statement {
            action,
            network,
            nostr_pubkey: nostr_pubkey.to_string(),
            node_pubkey,
            created_at,
        })
    }

    /// The canonical text the node signs.
    pub fn text(&self) -> String {
        format!(
            "{STATEMENT_TAG}:{STATEMENT_VERSION}:{}:{}:{}:{}:{}",
            self.action.as_str(),
            self.network.as_str(),
            self.nostr_pubkey,
            self.node_pubkey,
            self.created_at
        )
    }

    /// Parses canonical statement text; anything not byte-identical to [`Statement::text`]'s
    /// output for the parsed values is rejected.
    pub fn parse(text: &str) -> Result<Self, BindingError> {
        let fields: Vec<&str> = text.split(':').collect();
        if fields.len() != 7 {
            return Err(BindingError::Statement("expected 7 ':'-separated fields"));
        }
        if fields[0] != STATEMENT_TAG {
            return Err(BindingError::Statement("wrong statement tag"));
        }
        if fields[1] != STATEMENT_VERSION {
            return Err(BindingError::Statement("unsupported version"));
        }
        let action = match fields[2] {
            "bind" => Action::Bind,
            "revoke" => Action::Revoke,
            _ => return Err(BindingError::Statement("action must be bind or revoke")),
        };
        let network = Network::from_str(fields[3])?;
        if !is_lower_hex(fields[5], 66) {
            return Err(BindingError::Statement(
                "node pubkey must be 66 lower-case hex",
            ));
        }
        let node_pubkey = PublicKey::from_str(fields[5])
            .map_err(|_| BindingError::Statement("node pubkey is not a curve point"))?;
        let ts = fields[6];
        if ts.is_empty() || ts.len() > 20 || !ts.bytes().all(|c| c.is_ascii_digit()) {
            return Err(BindingError::Statement("created_at must be decimal digits"));
        }
        if ts.len() > 1 && ts.starts_with('0') {
            return Err(BindingError::Statement("created_at has a leading zero"));
        }
        let created_at: u64 = ts
            .parse()
            .map_err(|_| BindingError::Statement("created_at out of range"))?;
        let statement = Statement::new(action, network, fields[4], node_pubkey, created_at)?;
        if statement.text() != text {
            return Err(BindingError::Statement("not in canonical form"));
        }
        Ok(statement)
    }
}

/// A statement with the node's signature over its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatement {
    /// What the node states.
    pub statement: Statement,
    /// The node's zbase32 `signmessage` signature over `statement.text()`.
    pub node_signature: String,
}

impl SignedStatement {
    /// Checks the node signature recovers to the statement's node key.
    pub fn verify(&self) -> Result<(), BindingError> {
        let recovered = recover_ln_signer(self.statement.text().as_bytes(), &self.node_signature)?;
        if recovered != self.statement.node_pubkey {
            return Err(BindingError::WrongSigner);
        }
        Ok(())
    }

    /// The unsigned binding event: kind [`KIND_NODE_BINDING`], `d` = node key, the statement
    /// and node signature as tags, `created_at` = the statement's. The Nostr key named in the
    /// statement must sign it.
    pub fn to_event_builder(&self) -> EventBuilder {
        let node_hex = self.statement.node_pubkey.to_string();
        EventBuilder::new(Kind::Custom(KIND_NODE_BINDING), "")
            .tags([
                Tag::identifier(node_hex.clone()),
                Tag::custom("node", vec![node_hex]),
                Tag::custom("network", vec![self.statement.network.as_str().to_string()]),
                Tag::custom("statement", vec![self.statement.text()]),
                Tag::custom("node_sig", vec![self.node_signature.clone()]),
            ])
            .custom_created_at(Timestamp::from(self.statement.created_at))
    }

    /// Reads and fully checks a binding event: the event's own id and Schnorr signature, the
    /// kind, exactly one of each tag, tags consistent with the statement, the statement's Nostr
    /// key = the event author, `created_at` = the statement's, and the node signature.
    pub fn from_event(event: &Event) -> Result<Self, BindingError> {
        event
            .verify()
            .map_err(|e| BindingError::EventSignature(e.to_string()))?;
        if event.kind != Kind::Custom(KIND_NODE_BINDING) {
            return Err(BindingError::Event("wrong kind"));
        }
        let one = |name: &str| -> Result<String, BindingError> {
            let mut found = event
                .tags
                .iter()
                .map(|t| t.as_slice())
                .filter(|s| s.first().map(String::as_str) == Some(name));
            let tag = found.next().ok_or(BindingError::Event("missing tag"))?;
            if found.next().is_some() {
                return Err(BindingError::Event("duplicate tag"));
            }
            if tag.len() != 2 {
                return Err(BindingError::Event("tag must have exactly one value"));
            }
            Ok(tag[1].clone())
        };
        let d = one("d")?;
        let node = one("node")?;
        let network = one("network")?;
        let text = one("statement")?;
        let node_signature = one("node_sig")?;
        let statement = Statement::parse(&text)?;
        let node_hex = statement.node_pubkey.to_string();
        if d != node_hex || node != node_hex {
            return Err(BindingError::Event(
                "d/node tags differ from the statement's node",
            ));
        }
        if network != statement.network.as_str() {
            return Err(BindingError::Event(
                "network tag differs from the statement",
            ));
        }
        // A binding needs the Nostr key's consent, so its author must be that key. A revocation
        // is the node's word alone (its signature is checked below), so any key may publish it:
        // a node that lost its Nostr key can still revoke the binding.
        if statement.action == Action::Bind && event.pubkey.to_hex() != statement.nostr_pubkey {
            return Err(BindingError::Event(
                "event author is not the statement's Nostr key",
            ));
        }
        if event.created_at.as_secs() != statement.created_at {
            return Err(BindingError::Event("created_at differs from the statement"));
        }
        let signed = SignedStatement {
            statement,
            node_signature,
        };
        signed.verify()?;
        Ok(signed)
    }
}

/// How far ahead of the verifier's clock a statement may be dated and still count (10 minutes).
/// Without a bound, a statement dated years ahead would outrank every later revocation.
pub const MAX_FUTURE_SKEW_SECS: u64 = 600;

/// The node's current word on bindings, from statements that already passed
/// [`SignedStatement::verify`]: for the given node, among statements dated no later than
/// `now + MAX_FUTURE_SKEW_SECS`, the one with the greatest `created_at` wins, and at equal times a
/// revocation wins over a binding. `now` is the verifier's clock in unix seconds.
pub fn latest_for_node<'a, I>(
    node: &PublicKey,
    statements: I,
    now: u64,
) -> Option<&'a SignedStatement>
where
    I: IntoIterator<Item = &'a SignedStatement>,
{
    let horizon = now.saturating_add(MAX_FUTURE_SKEW_SECS);
    statements
        .into_iter()
        .filter(|s| &s.statement.node_pubkey == node && s.statement.created_at <= horizon)
        .max_by_key(|s| {
            (
                s.statement.created_at,
                matches!(s.statement.action, Action::Revoke),
            )
        })
}

/// True when, after resolving every verified statement for `node` at time `now`, the node
/// currently binds `nostr_pubkey` on `network`. One node binds one Nostr key at a time: its newest
/// statement decides, so a new binding to another key replaces the old one.
pub fn is_bound<'a, I>(
    node: &PublicKey,
    nostr_pubkey: &str,
    network: Network,
    statements: I,
    now: u64,
) -> bool
where
    I: IntoIterator<Item = &'a SignedStatement>,
{
    match latest_for_node(node, statements, now) {
        Some(s) => {
            s.statement.action == Action::Bind
                && s.statement.nostr_pubkey == nostr_pubkey
                && s.statement.network == network
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{FinalizeEvent, Keys};

    /// The verifier clock used by resolution tests (statements in them are dated 100..=300).
    const NOW: u64 = 1_000;

    fn one_key() -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = 1;
        SecretKey::from_slice(&b).expect("valid key")
    }

    fn pubkey(sk: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::signing_only(), sk)
    }

    // rust-lightning `util::message_signing::tests::test_sign` (secret key = 1).
    const LDK_TEST_SIG: &str = "d9tibmnic9t5y41hg7hkakdcra94akas9ku3rmmj4ag9mritc8ok4p5qzefs78c9pqfhpuftqqzhydbdwfg7u6w6wdxcqpqn4sj4e73e";

    #[test]
    fn signs_like_ldk() {
        assert_eq!(sign_ln_message(b"test message", &one_key()), LDK_TEST_SIG);
    }

    #[test]
    fn recovers_ldk_vector() {
        let pk = recover_ln_signer(b"test message", LDK_TEST_SIG).expect("recovers");
        assert_eq!(pk, pubkey(&one_key()));
        assert!(verify_ln_message(b"test message", LDK_TEST_SIG, &pk));
        assert!(!verify_ln_message(b"test messagE", LDK_TEST_SIG, &pk));
    }

    // Core Lightning tests/test_misc.py corpus (lnd-produced signatures), copied byte for byte
    // from rust-lightning `util::message_signing::tests::test_verify_ground_truth_ish`.
    const CLN_CORPUS: [[&str; 3]; 3] = [
        [
            "is this compatible?",
            "rbgfioj114mh48d8egqx8o9qxqw4fmhe8jbeeabdioxnjk8z3t1ma1hu1fiswpakgucwwzwo6ofycffbsqusqdimugbh41n1g698hr9t",
            "02b80cabdf82638aac86948e4c06e82064f547768dcef977677b9ea931ea75bab5",
        ],
        [
            "hi",
            "rnrphcjswusbacjnmmmrynh9pqip7sy5cx695h6mfu64iac6qmcmsd8xnsyczwmpqp9shqkth3h4jmkgyqu5z47jfn1q7gpxtaqpx4xg",
            "02de60d194e1ca5947b59fe8e2efd6aadeabfb67f2e89e13ae1a799c1e08e4a43b",
        ],
        [
            "hi",
            "ry8bbsopmduhxy3dr5d9ekfeabdpimfx95kagdem7914wtca79jwamtbw4rxh69hg7n6x9ty8cqk33knbxaqftgxsfsaeprxkn1k48p3",
            "022b8ece90ee891cbcdac0c1cc6af46b73c47212d8defbce80265ac81a6b794931",
        ],
    ];

    // Produced by real nodes on regtest in bipnip's M0 spike (spikes/ln-m0, 2026-11-10): LND
    // v0.21.5-beta `lncli signmessage` and ldk-node 0.7.1 `Node::sign_message`. Throwaway keys.
    const SPIKE_MSG: &str = "bipnip M0 spike: Lightning signed message";
    const SPIKE_VECTORS: [[&str; 3]; 3] = [
        [
            "lnd-v0.21.5-beta-alice",
            "ryc5mqfxokuhz58kipdrx4jcw7kofsi4cjehi4h3ttxa79ccqaacrmi1hq4rogiman19c3pwh3dauw7jzq5j71s55fstraghx3rs3ou5",
            "02a2c49f01de3015a832c1551745106ee704c8c9aab1fef9dab8de5125d6dbab5f",
        ],
        [
            "lnd-v0.21.5-beta-bob",
            "d9ywkc1i89foksxw1gc4ksr3zeijb9wfaeehrqtdmzjwgzkk1au94hik7axn3ktbbzr4aokhtunnwjpgnxp4echkrzg97s7dcgbkw7gs",
            "02290bfd8a728a5c65d925f0abec649d3dcdabd391218f3a507d8f5a404cfbcd32",
        ],
        [
            "ldk-node-0.7.1",
            "dhuz1i8qnr8jj3pwxeughzw3x3nfb1i4dxdi8y3jk1ggbeek1qttqfku88iz3s78yhshfm1euw1sp5xw7pa45eoknxu9q43cxifh94tt",
            "0371e42290241390eea888ce76b14537797568b111f1e43ec47e4d35ae356ba245",
        ],
    ];
    // Binding statements signed by the same LND nodes (`lncli signmessage <statement>`).
    const SPIKE_STATEMENTS: [[&str; 2]; 2] = [
        [
            "nostr-node-binding:v1:bind:regtest:abababababababababababababababababababababababababababababababab:02a2c49f01de3015a832c1551745106ee704c8c9aab1fef9dab8de5125d6dbab5f:1794302273",
            "ryjpprs859mhcy1ck5fq1n8c4i34zg6bp7rz6borxhdycqyqcbddnic73j5rqk463y5x8n5ix9yynxg8y73m8o9acozgbykps13mgpn4",
        ],
        [
            "nostr-node-binding:v1:bind:regtest:abababababababababababababababababababababababababababababababab:02290bfd8a728a5c65d925f0abec649d3dcdabd391218f3a507d8f5a404cfbcd32:1794302273",
            "rdiu4zwr7ez6msk9sxz6zttmxrepkb93n9yhutk5hi9cyo5sfayaejpt7n4jdcq586kj8wgsnmj5t7x6xtjux5p8spabqx9qp8nzy8kq",
        ],
    ];

    #[test]
    fn real_node_signatures_recover() {
        for [name, sig, key] in SPIKE_VECTORS {
            let pk = recover_ln_signer(SPIKE_MSG.as_bytes(), sig).expect(name);
            assert_eq!(pk.to_string(), key, "{name}");
        }
    }

    #[test]
    fn real_node_binding_statements_verify() {
        for [text, sig] in SPIKE_STATEMENTS {
            let statement = Statement::parse(text).expect("parses");
            let signed = SignedStatement {
                statement,
                node_signature: sig.to_string(),
            };
            assert_eq!(signed.verify(), Ok(()));
            // The same signature over a different timestamp does not verify.
            let mut moved = signed.clone();
            moved.statement.created_at += 1;
            assert_eq!(moved.verify(), Err(BindingError::WrongSigner));
        }
    }

    #[test]
    fn cln_corpus_recovers_exact_keys() {
        for [msg, sig, key] in CLN_CORPUS {
            let pk = recover_ln_signer(msg.as_bytes(), sig).expect("recovers");
            assert_eq!(pk.to_string(), key, "message {msg:?}");
            let other = if msg == "hi" { "hi!" } else { "hi" };
            assert!(!verify_ln_message(other.as_bytes(), sig, &pk));
        }
    }

    #[test]
    fn zbase32_round_trip_and_strictness() {
        for len in 0..70 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = zbase32::encode(&data);
            assert_eq!(zbase32::decode(&enc).expect("decodes"), data);
        }
        assert!(
            zbase32::decode("Y").is_none(),
            "upper case is outside the alphabet"
        );
        assert!(zbase32::decode("yl").is_none(), "l is outside the alphabet");
        // "yo" = 00000 10000: one byte (0x04) and two zero leftover bits, so it is canonical.
        assert_eq!(zbase32::decode("yo"), Some(vec![0x04]));
        // "yb" = 00000 00001: one byte and leftover bits "01", which no encoder writes.
        assert!(zbase32::decode("yb").is_none(), "non-zero leftover bits");
        // A lone character carries 5 bits, never a whole byte.
        assert!(zbase32::decode("y").is_none(), "dangling character");
    }

    #[test]
    fn rejects_bad_headers_and_lengths() {
        let mut bytes = zbase32::decode(LDK_TEST_SIG).expect("decodes");
        bytes[0] = 27; // uncompressed-key header
        let z = zbase32::encode(&bytes);
        assert_eq!(
            recover_ln_signer(b"test message", &z),
            Err(BindingError::RecoveryHeader(27))
        );
        assert_eq!(
            recover_ln_signer(b"test message", &LDK_TEST_SIG[..103]),
            Err(BindingError::SignatureEncoding)
        );
    }

    #[test]
    fn hex_signature_converts() {
        let bytes = zbase32::decode(LDK_TEST_SIG).expect("decodes");
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex_signature_to_zbase32(&hex).expect("converts"),
            LDK_TEST_SIG
        );
        assert!(hex_signature_to_zbase32(&hex.to_uppercase()).is_err());
    }

    fn signed(action: Action, nostr: &Keys, node_sk: &SecretKey, ts: u64) -> SignedStatement {
        let statement = Statement::new(
            action,
            Network::Regtest,
            &nostr.public_key().to_hex(),
            pubkey(node_sk),
            ts,
        )
        .expect("statement");
        let node_signature = sign_ln_message(statement.text().as_bytes(), node_sk);
        SignedStatement {
            statement,
            node_signature,
        }
    }

    #[test]
    fn statement_text_round_trips_and_is_strict() {
        let nostr = Keys::generate();
        let s = signed(Action::Bind, &nostr, &one_key(), 1_762_732_800).statement;
        assert_eq!(Statement::parse(&s.text()).expect("parses"), s);
        let text = s.text();
        assert!(Statement::parse(&text.replace(":bind:", ":Bind:")).is_err());
        assert!(Statement::parse(&text.replace(":regtest:", ":mainnet:")).is_err());
        assert!(Statement::parse(&format!("{text}:extra")).is_err());
        assert!(Statement::parse(&text.replace(":1762732800", ":01762732800")).is_err());
        assert!(Statement::parse(&text.replace(":v1:", ":v2:")).is_err());
        let upper = text.replacen(&s.nostr_pubkey, &s.nostr_pubkey.to_uppercase(), 1);
        if upper != text {
            assert!(Statement::parse(&upper).is_err());
        }
    }

    #[test]
    fn event_round_trip_verifies_both_keys() {
        let nostr = Keys::generate();
        let node_sk = one_key();
        let s = signed(Action::Bind, &nostr, &node_sk, 1_762_732_800);
        let event = s.to_event_builder().finalize(&nostr).expect("signs");
        let back = SignedStatement::from_event(&event).expect("verifies");
        assert_eq!(back, s);
    }

    #[test]
    fn event_from_another_nostr_key_is_rejected() {
        let nostr = Keys::generate();
        let thief = Keys::generate();
        let s = signed(Action::Bind, &nostr, &one_key(), 1_762_732_800);
        let event = s.to_event_builder().finalize(&thief).expect("signs");
        assert_eq!(
            SignedStatement::from_event(&event),
            Err(BindingError::Event(
                "event author is not the statement's Nostr key"
            ))
        );
    }

    #[test]
    fn revocation_may_be_published_by_any_key() {
        let lost = Keys::generate();
        let publisher = Keys::generate();
        let s = signed(Action::Revoke, &lost, &one_key(), 1_762_732_900);
        let event = s.to_event_builder().finalize(&publisher).expect("signs");
        assert_eq!(SignedStatement::from_event(&event).expect("verifies"), s);
    }

    #[test]
    fn forged_revocation_without_node_signature_is_rejected() {
        let nostr = Keys::generate();
        let mut s = signed(Action::Revoke, &nostr, &one_key(), 1_762_732_900);
        // Re-use the node's signature over a different statement (the bind at an earlier time).
        let bind = signed(Action::Bind, &nostr, &one_key(), 1_762_732_800);
        s.node_signature = bind.node_signature;
        let event = s.to_event_builder().finalize(&nostr).expect("signs");
        assert_eq!(
            SignedStatement::from_event(&event),
            Err(BindingError::WrongSigner)
        );
    }

    #[test]
    fn node_signature_from_another_node_is_rejected() {
        let nostr = Keys::generate();
        let mut s = signed(Action::Bind, &nostr, &one_key(), 1_762_732_800);
        let mut other = [0u8; 32];
        other[31] = 2;
        let other = SecretKey::from_slice(&other).expect("key");
        s.node_signature = sign_ln_message(s.statement.text().as_bytes(), &other);
        assert_eq!(s.verify(), Err(BindingError::WrongSigner));
    }

    #[test]
    fn newest_node_statement_wins_and_revocation_beats_replay() {
        let nostr = Keys::generate();
        let node_sk = one_key();
        let node = pubkey(&node_sk);
        let npub = nostr.public_key().to_hex();
        let bind = signed(Action::Bind, &nostr, &node_sk, 100);
        let revoke = signed(Action::Revoke, &nostr, &node_sk, 200);
        assert!(is_bound(&node, &npub, Network::Regtest, [&bind], NOW));
        // A replayed old binding next to the newer revocation loses.
        assert!(!is_bound(
            &node,
            &npub,
            Network::Regtest,
            [&bind, &revoke],
            NOW
        ));
        // Same timestamp: revocation wins.
        let revoke_same = signed(Action::Revoke, &nostr, &node_sk, 100);
        assert!(!is_bound(
            &node,
            &npub,
            Network::Regtest,
            [&bind, &revoke_same],
            NOW
        ));
        // Wrong network never counts.
        assert!(!is_bound(&node, &npub, Network::Bitcoin, [&bind], NOW));
        // A newer binding to another Nostr key replaces the first.
        let other = Keys::generate();
        let rebind = signed(Action::Bind, &other, &node_sk, 300);
        assert!(!is_bound(
            &node,
            &npub,
            Network::Regtest,
            [&bind, &rebind],
            NOW
        ));
        assert!(is_bound(
            &node,
            &other.public_key().to_hex(),
            Network::Regtest,
            [&bind, &rebind],
            NOW
        ));
    }

    #[test]
    fn statements_dated_beyond_the_skew_are_ignored() {
        let nostr = Keys::generate();
        let node_sk = one_key();
        let node = pubkey(&node_sk);
        let npub = nostr.public_key().to_hex();
        let far_future_bind = signed(Action::Bind, &nostr, &node_sk, NOW + 3_600);
        let revoke_now = signed(Action::Revoke, &nostr, &node_sk, NOW);
        // The far-future binding does not count yet, so the revocation decides.
        assert!(!is_bound(
            &node,
            &npub,
            Network::Regtest,
            [&far_future_bind],
            NOW
        ));
        assert_eq!(
            latest_for_node(&node, [&far_future_bind, &revoke_now], NOW),
            Some(&revoke_now)
        );
        // Within the skew it counts.
        let soon_bind = signed(Action::Bind, &nostr, &node_sk, NOW + MAX_FUTURE_SKEW_SECS);
        assert!(is_bound(&node, &npub, Network::Regtest, [&soon_bind], NOW));
    }
}
