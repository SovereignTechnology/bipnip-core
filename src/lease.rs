//! Liquidity leases (bipnip draft "Liquidity leases"): the terms two node runners agree on, the
//! fee arithmetic, and the contract both refer to.
//!
//! A seller opens a channel of `capacity_sat` to the buyer and keeps it open for
//! `duration_blocks`; the buyer pays a fee, split into an upfront share (a hold invoice on a hash
//! the **buyer** chose, released only after the buyer's own node has verified the channel) and a
//! completion share (paid at lease end if the channel is still open).
//!
//! Everything here is pure: no node, no relay, no clock. All amounts are integers; fee rounding is
//! specified once, here, so buyer, seller and instance always compute the same numbers.

use std::fmt;

use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::node_binding::Network;

/// Smallest channel a lease may be for (the usual minimum channel size of public nodes).
pub const MIN_CAPACITY_SAT: u64 = 20_000;
/// Largest channel a lease may be for (10 BTC); a bound against overflow and typos, not a policy.
pub const MAX_CAPACITY_SAT: u64 = 1_000_000_000;
/// Longest lease: about two years of blocks.
pub const MAX_DURATION_BLOCKS: u32 = 105_120;
/// Largest proportional fee: 20 % of capacity.
pub const MAX_FEE_PPM: u32 = 200_000;
/// Most confirmations a buyer may ask for before releasing the preimage.
pub const MAX_MIN_CONFIRMATIONS: u32 = 144;
/// Longest a hold invoice for the upfront share may stay payable or held: 48 hours. A held HTLC
/// ties up liquidity on every node in the payment path.
pub const MAX_HOLD_SECS: u32 = 48 * 3600;

/// Why lease terms or a contract were rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// A term is outside its allowed range; the name says which.
    Term(&'static str),
    /// The fee would be zero or does not fit the arithmetic.
    Fee(&'static str),
    /// The contract text is not in canonical form; the name says which field.
    Contract(&'static str),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseError::Term(why) => write!(f, "invalid lease term: {why}"),
            LeaseError::Fee(why) => write!(f, "invalid lease fee: {why}"),
            LeaseError::Contract(why) => write!(f, "invalid lease contract: {why}"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// What is leased and for how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTerms {
    /// Channel capacity the seller funds, in satoshi.
    pub capacity_sat: u64,
    /// How long the seller keeps the channel open, in blocks from the funding confirmation.
    pub duration_blocks: u32,
    /// Flat part of the fee, in satoshi.
    pub fee_base_sat: u64,
    /// Proportional part of the fee, in parts per million of the capacity.
    pub fee_ppm: u32,
    /// Share of the fee paid upfront (through the hold invoice), in percent, 1..=100. The rest is
    /// paid at lease end.
    pub upfront_percent: u8,
    /// Confirmations of the funding transaction the buyer waits for before releasing the preimage.
    pub min_confirmations: u32,
    /// Whether the channel is announced to the network.
    pub announce: bool,
}

impl LeaseTerms {
    /// Checks every term's range and that the fee and both shares are computable and non-zero.
    pub fn validate(&self) -> Result<(), LeaseError> {
        if !(MIN_CAPACITY_SAT..=MAX_CAPACITY_SAT).contains(&self.capacity_sat) {
            return Err(LeaseError::Term("capacity_sat"));
        }
        if self.duration_blocks == 0 || self.duration_blocks > MAX_DURATION_BLOCKS {
            return Err(LeaseError::Term("duration_blocks"));
        }
        if self.fee_ppm > MAX_FEE_PPM {
            return Err(LeaseError::Term("fee_ppm"));
        }
        if self.fee_base_sat > self.capacity_sat {
            return Err(LeaseError::Term("fee_base_sat"));
        }
        if !(1..=100).contains(&self.upfront_percent) {
            return Err(LeaseError::Term("upfront_percent"));
        }
        if self.min_confirmations == 0 || self.min_confirmations > MAX_MIN_CONFIRMATIONS {
            return Err(LeaseError::Term("min_confirmations"));
        }
        if self.total_fee_sat()? == 0 {
            return Err(LeaseError::Fee("the fee is zero"));
        }
        if self.upfront_sat()? == 0 {
            return Err(LeaseError::Fee("the upfront share is zero"));
        }
        Ok(())
    }

    /// The whole fee: `fee_base_sat + floor(capacity_sat × fee_ppm / 1_000_000)`.
    pub fn total_fee_sat(&self) -> Result<u64, LeaseError> {
        let proportional = u128::from(self.capacity_sat) * u128::from(self.fee_ppm) / 1_000_000;
        let proportional = u64::try_from(proportional)
            .map_err(|_| LeaseError::Fee("proportional fee overflow"))?;
        self.fee_base_sat
            .checked_add(proportional)
            .ok_or(LeaseError::Fee("fee overflow"))
    }

    /// The upfront share: `ceil(total × upfront_percent / 100)`. Rounding up means the completion
    /// share never exceeds what the percentages say, and a non-zero fee has a non-zero upfront.
    pub fn upfront_sat(&self) -> Result<u64, LeaseError> {
        let total = u128::from(self.total_fee_sat()?);
        let upfront = (total * u128::from(self.upfront_percent)).div_ceil(100);
        u64::try_from(upfront).map_err(|_| LeaseError::Fee("upfront overflow"))
    }

    /// The completion share: the whole fee minus the upfront share.
    pub fn completion_sat(&self) -> Result<u64, LeaseError> {
        Ok(self.total_fee_sat()? - self.upfront_sat()?)
    }
}

/// The agreement both parties refer to: terms, the two nodes, the network and the payment hash
/// of the upfront hold invoice. Its canonical text is what both sign; its id names the lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseContract {
    /// The network both nodes are on.
    pub network: Network,
    /// The node that opens the channel and is paid.
    pub seller_node: PublicKey,
    /// The node that receives the channel and pays.
    pub buyer_node: PublicKey,
    /// The terms.
    pub terms: LeaseTerms,
    /// SHA-256 of the buyer's preimage, 64 lower-case hex characters.
    pub payment_hash: String,
    /// Unix seconds when the buyer made the contract.
    pub created_at: u64,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_num<T: std::str::FromStr>(s: &str, what: &'static str) -> Result<T, LeaseError> {
    let canonical = !s.is_empty()
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if !canonical {
        return Err(LeaseError::Contract(what));
    }
    s.parse().map_err(|_| LeaseError::Contract(what))
}

impl LeaseContract {
    /// Checks the terms, the payment hash form, and that buyer and seller are different nodes.
    pub fn validate(&self) -> Result<(), LeaseError> {
        self.terms.validate()?;
        if !is_lower_hex(&self.payment_hash, 64) {
            return Err(LeaseError::Contract("payment_hash"));
        }
        if self.seller_node == self.buyer_node {
            return Err(LeaseError::Contract("buyer and seller are the same node"));
        }
        Ok(())
    }

    /// The canonical text (ASCII, `:`-separated, no spaces):
    ///
    /// ```text
    /// bipnip-lease:v1:<network>:<seller node>:<buyer node>:<capacity_sat>:<duration_blocks>:
    /// <fee_base_sat>:<fee_ppm>:<upfront_percent>:<min_confirmations>:<announce 0|1>:
    /// <payment_hash>:<created_at>
    /// ```
    pub fn text(&self) -> String {
        let t = &self.terms;
        format!(
            "bipnip-lease:v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.network.as_str(),
            self.seller_node,
            self.buyer_node,
            t.capacity_sat,
            t.duration_blocks,
            t.fee_base_sat,
            t.fee_ppm,
            t.upfront_percent,
            t.min_confirmations,
            u8::from(t.announce),
            self.payment_hash,
            self.created_at
        )
    }

    /// The lease id: SHA-256 of the canonical text, lower-case hex.
    pub fn id(&self) -> String {
        Sha256::digest(self.text().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Parses canonical text. Anything not byte-identical to [`LeaseContract::text`]'s output for
    /// the parsed values, or failing [`LeaseContract::validate`], is rejected.
    pub fn parse(text: &str) -> Result<Self, LeaseError> {
        let f: Vec<&str> = text.split(':').collect();
        if f.len() != 14 || f[0] != "bipnip-lease" || f[1] != "v1" {
            return Err(LeaseError::Contract("header"));
        }
        let network = f[2]
            .parse::<Network>()
            .map_err(|_| LeaseError::Contract("network"))?;
        let node = |s: &str, what: &'static str| -> Result<PublicKey, LeaseError> {
            if !is_lower_hex(s, 66) {
                return Err(LeaseError::Contract(what));
            }
            s.parse().map_err(|_| LeaseError::Contract(what))
        };
        let announce = match f[11] {
            "0" => false,
            "1" => true,
            _ => return Err(LeaseError::Contract("announce")),
        };
        let contract = LeaseContract {
            network,
            seller_node: node(f[3], "seller node")?,
            buyer_node: node(f[4], "buyer node")?,
            terms: LeaseTerms {
                capacity_sat: parse_num(f[5], "capacity_sat")?,
                duration_blocks: parse_num(f[6], "duration_blocks")?,
                fee_base_sat: parse_num(f[7], "fee_base_sat")?,
                fee_ppm: parse_num(f[8], "fee_ppm")?,
                upfront_percent: parse_num(f[9], "upfront_percent")?,
                min_confirmations: parse_num(f[10], "min_confirmations")?,
                announce,
            },
            payment_hash: f[12].to_string(),
            created_at: parse_num(f[13], "created_at")?,
        };
        contract.validate()?;
        if contract.text() != text {
            return Err(LeaseError::Contract("not in canonical form"));
        }
        Ok(contract)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn terms() -> LeaseTerms {
        LeaseTerms {
            capacity_sat: 2_000_000,
            duration_blocks: 4_320,
            fee_base_sat: 1_000,
            fee_ppm: 2_500,
            upfront_percent: 50,
            min_confirmations: 3,
            announce: true,
        }
    }

    fn node(n: u8) -> PublicKey {
        let mut b = [0u8; 32];
        b[31] = n;
        PublicKey::from_secret_key(
            &Secp256k1::signing_only(),
            &SecretKey::from_slice(&b).expect("key"),
        )
    }

    fn contract() -> LeaseContract {
        LeaseContract {
            network: Network::Regtest,
            seller_node: node(1),
            buyer_node: node(2),
            terms: terms(),
            payment_hash: "ab".repeat(32),
            created_at: 1_794_800_000,
        }
    }

    #[test]
    fn fee_arithmetic_is_exact() {
        let t = terms();
        // 1_000 + 2_000_000 × 2_500 / 1_000_000 = 1_000 + 5_000
        assert_eq!(t.total_fee_sat(), Ok(6_000));
        assert_eq!(t.upfront_sat(), Ok(3_000));
        assert_eq!(t.completion_sat(), Ok(3_000));
        assert_eq!(t.validate(), Ok(()));
    }

    #[test]
    fn shares_always_sum_to_the_fee_and_upfront_rounds_up() {
        for percent in 1..=100u8 {
            for base in [0u64, 1, 7, 999] {
                let t = LeaseTerms {
                    fee_base_sat: base,
                    fee_ppm: 333,
                    upfront_percent: percent,
                    ..terms()
                };
                let (total, up, rest) = (
                    t.total_fee_sat().expect("total"),
                    t.upfront_sat().expect("upfront"),
                    t.completion_sat().expect("completion"),
                );
                assert_eq!(up + rest, total);
                assert!(u128::from(up) * 100 >= u128::from(total) * u128::from(percent));
                assert!((1..=total).contains(&up));
            }
        }
        let all_upfront = LeaseTerms {
            upfront_percent: 100,
            ..terms()
        };
        assert_eq!(all_upfront.completion_sat(), Ok(0));
    }

    #[test]
    fn proportional_fee_rounds_down() {
        let t = LeaseTerms {
            capacity_sat: 1_999_999,
            fee_base_sat: 0,
            fee_ppm: 1,
            ..terms()
        };
        assert_eq!(t.total_fee_sat(), Ok(1));
        let t = LeaseTerms {
            capacity_sat: 999_999,
            fee_base_sat: 0,
            fee_ppm: 1,
            ..terms()
        };
        assert_eq!(t.total_fee_sat(), Ok(0));
        assert_eq!(t.validate(), Err(LeaseError::Fee("the fee is zero")));
    }

    #[test]
    fn terms_out_of_range_are_rejected_by_name() {
        let cases: [(LeaseTerms, &str); 8] = [
            (
                LeaseTerms {
                    capacity_sat: MIN_CAPACITY_SAT - 1,
                    ..terms()
                },
                "capacity_sat",
            ),
            (
                LeaseTerms {
                    capacity_sat: MAX_CAPACITY_SAT + 1,
                    ..terms()
                },
                "capacity_sat",
            ),
            (
                LeaseTerms {
                    duration_blocks: 0,
                    ..terms()
                },
                "duration_blocks",
            ),
            (
                LeaseTerms {
                    fee_ppm: MAX_FEE_PPM + 1,
                    ..terms()
                },
                "fee_ppm",
            ),
            (
                LeaseTerms {
                    fee_base_sat: 2_000_001,
                    ..terms()
                },
                "fee_base_sat",
            ),
            (
                LeaseTerms {
                    upfront_percent: 0,
                    ..terms()
                },
                "upfront_percent",
            ),
            (
                LeaseTerms {
                    upfront_percent: 101,
                    ..terms()
                },
                "upfront_percent",
            ),
            (
                LeaseTerms {
                    min_confirmations: 0,
                    ..terms()
                },
                "min_confirmations",
            ),
        ];
        for (t, name) in cases {
            assert_eq!(t.validate(), Err(LeaseError::Term(name)));
        }
        let max = LeaseTerms {
            capacity_sat: MAX_CAPACITY_SAT,
            fee_base_sat: MAX_CAPACITY_SAT,
            fee_ppm: MAX_FEE_PPM,
            ..terms()
        };
        assert_eq!(max.total_fee_sat(), Ok(1_200_000_000));
    }

    #[test]
    fn contract_text_round_trips_and_names_the_lease() {
        let c = contract();
        let text = c.text();
        assert!(
            text.starts_with("bipnip-lease:v1:regtest:02")
                || text.starts_with("bipnip-lease:v1:regtest:03")
        );
        assert_eq!(LeaseContract::parse(&text), Ok(c.clone()));
        assert_eq!(c.id().len(), 64);
        let mut later = c.clone();
        later.created_at += 1;
        assert_ne!(later.id(), c.id());
    }

    #[test]
    fn contract_parsing_is_strict() {
        let c = contract();
        let text = c.text();
        for (bad, why) in [
            (
                text.replace("bipnip-lease:v1", "bipnip-lease:v2"),
                "version",
            ),
            (text.replace(":regtest:", ":mainnet:"), "network"),
            (text.replace(":2000000:", ":02000000:"), "leading zero"),
            (
                text.replace(&"ab".repeat(32), &"AB".repeat(32)),
                "upper-case hash",
            ),
            (format!("{text}:1"), "extra field"),
            (text.replace(":50:", ":150:"), "upfront out of range"),
            (text.replacen(":1:", ":2:", 1), "announce flag"),
        ] {
            assert!(LeaseContract::parse(&bad).is_err(), "{why}: {bad}");
        }
        let mut same = contract();
        same.buyer_node = same.seller_node;
        assert_eq!(
            same.validate(),
            Err(LeaseError::Contract("buyer and seller are the same node"))
        );
        assert!(LeaseContract::parse(&same.text()).is_err());
    }
}
