//! bipnip: the amounts and limits of a bond on a liquidity order.
//!
//! A bond is the one place where an instance holds a member's money: a hold invoice on the
//! instance's own node, paid before anything is opened and cancelled when the member did what
//! it signed up for. The rules here keep that small and bounded:
//!
//! - a bond is at least [`MIN_BOND_SAT`], so what is paid out of it is never zero;
//! - a bond that is taken is paid on to the member that was let down, less a routing reserve
//!   ([`payout_sat`]); the instance pays the routing fee out of that reserve and keeps what is
//!   left of it;
//! - a bond invoice never asks for a longer lock than [`MAX_BOND_CLTV_DELTA`] blocks;
//! - a member has [`BOND_CLAIM_WINDOW_SECS`] to claim a bond it is owed.

/// The smallest bond, in satoshi.
pub const MIN_BOND_SAT: u64 = 1_000;

/// The share of a taken bond set aside for routing it on, in parts per million (1%).
pub const BOND_ROUTING_RESERVE_PPM: u64 = 10_000;

/// The longest final CLTV delta a bond invoice may ask for, in blocks (about five days).
pub const MAX_BOND_CLTV_DELTA: u32 = 720;

/// How long a member has to claim a bond it is owed: seven days.
pub const BOND_CLAIM_WINDOW_SECS: u64 = 7 * 24 * 3_600;

/// True for an amount an order may ask as a bond: none, or at least [`MIN_BOND_SAT`].
pub fn bond_amount_ok(bond_sat: u64) -> bool {
    bond_sat == 0 || bond_sat >= MIN_BOND_SAT
}

/// The routing reserve kept back from a taken bond: 1%, rounded up.
pub fn routing_reserve_sat(bond_sat: u64) -> u64 {
    (u128::from(bond_sat) * u128::from(BOND_ROUTING_RESERVE_PPM)).div_ceil(1_000_000) as u64
}

/// What the member that was let down is paid from a taken bond: the bond less the routing
/// reserve. This is the exact amount its claim invoice must ask for.
pub fn payout_sat(bond_sat: u64) -> u64 {
    bond_sat - routing_reserve_sat(bond_sat)
}

/// The final CLTV delta for a bond held over `window_secs`: the window at ten minutes a block,
/// half as much again in case blocks come fast, and a day on top to judge and settle; never more
/// than [`MAX_BOND_CLTV_DELTA`].
pub fn bond_cltv_delta(window_secs: u64) -> u32 {
    let blocks = window_secs / 600;
    let wanted = blocks.saturating_add(blocks / 2).saturating_add(144);
    u32::try_from(wanted)
        .unwrap_or(MAX_BOND_CLTV_DELTA)
        .min(MAX_BOND_CLTV_DELTA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bond_is_none_or_at_least_the_minimum() {
        assert!(bond_amount_ok(0));
        assert!(!bond_amount_ok(1));
        assert!(!bond_amount_ok(MIN_BOND_SAT - 1));
        assert!(bond_amount_ok(MIN_BOND_SAT));
        assert!(bond_amount_ok(u64::MAX));
    }

    #[test]
    fn the_payout_is_the_bond_less_one_percent_rounded_up() {
        assert_eq!(routing_reserve_sat(1_000), 10);
        assert_eq!(payout_sat(1_000), 990);
        assert_eq!(routing_reserve_sat(1_001), 11);
        assert_eq!(payout_sat(1_001), 990);
        assert_eq!(payout_sat(50_000), 49_500);
        // No overflow, and the payout is never more than the bond.
        assert!(payout_sat(u64::MAX) < u64::MAX);
        for bond in [MIN_BOND_SAT, 1_234, 99_999, 21_000_000 * 100_000_000] {
            assert!(payout_sat(bond) > 0 && payout_sat(bond) < bond);
            assert_eq!(payout_sat(bond) + routing_reserve_sat(bond), bond);
        }
    }

    #[test]
    fn the_lock_covers_the_window_and_is_capped() {
        assert_eq!(bond_cltv_delta(0), 144);
        assert_eq!(bond_cltv_delta(3_600), 6 + 3 + 144);
        assert_eq!(bond_cltv_delta(48 * 3_600), 288 + 144 + 144);
        assert_eq!(bond_cltv_delta(14 * 24 * 3_600), MAX_BOND_CLTV_DELTA);
        assert_eq!(bond_cltv_delta(u64::MAX), MAX_BOND_CLTV_DELTA);
    }
}
