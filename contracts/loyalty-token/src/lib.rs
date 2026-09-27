#![no_std]

//! # AfriPay Loyalty Token — SEP-41 Compatible Fungible Token
//!
//! Issues loyalty points to users for each transaction and allows redemption
//! for fee discounts via a configurable tiered system.
//!
//! ## Earn rate
//! 1 loyalty point per 1 XLM (or XLM-equivalent) of transaction volume.
//! The backend calls [`mint`] after each successful payment.
//!
//! ## Tiers (defaults)
//! | Index | Threshold | Discount |
//! |-------|-----------|----------|
//! |   0   |    50 pts |    10 %  |
//! |   1   |   100 pts |    25 %  |
//! |   2   |   500 pts |    50 %  |
//! |   3   |  1000 pts |    75 %  |
//!
//! ## Redemption
//! Call [`redeem`] with a `tier_index` to burn that tier's threshold points
//! and record the discount entitlement. The backend calls [`get_discount`]
//! to determine the highest tier the user qualifies for without burning tokens.
//!
//! ## SEP-41 interface
//! Implements the full SEP-41 token interface:
//! `allowance`, `approve`, `balance`, `burn`, `burn_from`,
//! `decimals`, `mint`, `name`, `symbol`, `total_supply`,
//! `transfer`, `transfer_from`.

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, IntoVal, String, Symbol,
    Vec,
};

// ── KYC Tier enum ────────────────────────────────────────────────────────────────
// Replicated from kyc-attestation contract for type safety in cross-contract calls.
#[derive(Clone, Copy)]
#[contracttype]
#[repr(u32)]
pub enum KycTier {
    Basic = 0,
    Enhanced = 1,
    Business = 2,
}

#[contracttype]
pub struct AllowanceValue {
    pub amount: i128,
    pub expires_at: u64,
}

mod test;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    TotalSupply,
    MaxSupply,
    TransferFeeBps,
    Balance(Address),
    Allowance(Address, Address), // (owner, spender)
    KycContractAddress,
    /// Snapshot counter used to assign the next snapshot id.
    SnapshotCounter,
    /// Number of active snapshots currently stored.
    SnapshotCount,
    /// Ledger sequence at which a snapshot was taken.
    SnapshotLedger(u32),
    /// Per-account checkpoint history: `Vec<(ledger, balance)>` written lazily
    /// on every balance change. Used to reconstruct historical balances without
    /// iterating over all holders.
    Checkpoints(Address),
    /// Maps a tier index (0–4) to its Tier configuration.
    Tier(u32),
}

// ── Tier type ─────────────────────────────────────────────────────────────────

/// A single redemption tier: points required and the fee-discount awarded.
#[derive(Clone)]
#[contracttype]
pub struct Tier {
    /// Points the user must hold (and will burn) to redeem this tier.
    pub threshold: i128,
    /// Fee discount in basis points (e.g. 2500 = 25 %). Max 9000 (90 %).
    pub discount_bps: u32,
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of tiers supported (indices 0 – 4).
const MAX_TIERS: u32 = 5;

/// Hard cap on discount_bps to prevent 100 % fee waivers.
const MAX_DISCOUNT_BPS: u32 = 9_000;

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct LoyaltyTokenContract;

#[contractimpl]
impl LoyaltyTokenContract {
    // ── Admin ─────────────────────────────────────────────────────────────────

    /// Initialise the contract. Must be called once before any other function.
    ///
    /// Sets up four default tiers:
    /// * Tier 0 — 50 pts → 10 % discount (1 000 bps)
    /// * Tier 1 — 100 pts → 25 % discount (2 500 bps)
    /// * Tier 2 — 500 pts → 50 % discount (5 000 bps)
    /// * Tier 3 — 1 000 pts → 75 % discount (7 500 bps)
    ///
    /// # Arguments
    /// * `admin`      — Address authorised to mint tokens (the AfriPay backend).
    /// * `max_supply` — Hard ceiling on total points that can ever be minted (must be > 0).
    pub fn initialize(env: Env, admin: Address, max_supply: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if max_supply <= 0 {
            panic!("max_supply must be positive");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::TotalSupply, &0i128);
        env.storage().persistent().set(&DataKey::MaxSupply, &max_supply);
        // transfer_fee_bps defaults to 0 (fees disabled at init).
        env.storage().persistent().set(&DataKey::TransferFeeBps, &0u32);
        env.storage().persistent().set(&DataKey::SnapshotCounter, &0u32);
        env.storage().persistent().set(&DataKey::SnapshotCount, &0u32);

        // Install default tiers.
        env.storage().persistent().set(
            &DataKey::Tier(0),
            &Tier { threshold: 50, discount_bps: 1_000 },
        );
        env.storage().persistent().set(
            &DataKey::Tier(1),
            &Tier { threshold: 100, discount_bps: 2_500 },
        );
        env.storage().persistent().set(
            &DataKey::Tier(2),
            &Tier { threshold: 500, discount_bps: 5_000 },
        );
        env.storage().persistent().set(
            &DataKey::Tier(3),
            &Tier { threshold: 1_000, discount_bps: 7_500 },
        );
    }

    // ── SEP-41: token metadata ────────────────────────────────────────────────

    pub fn name(env: Env) -> String {
        String::from_str(&env, "AfriPay Loyalty Points")
    }

    pub fn symbol(env: Env) -> String {
        String::from_str(&env, "ALP")
    }

    /// Loyalty points have no sub-unit — decimals = 0.
    pub fn decimals(_env: Env) -> u32 {
        0
    }

    // ── SEP-41: supply & balances ─────────────────────────────────────────────

    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    pub fn max_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::MaxSupply)
            .expect("not initialized")
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    /// Create a snapshot checkpoint. Admin only. Returns the generated snapshot id.
    ///
    /// Snapshots no longer iterate over all holders. Instead, the ledger sequence
    /// is recorded and per-account balances are reconstructed lazily from the
    /// checkpoint history written on every balance change (see [`snapshot_balance`]).
    pub fn create_snapshot(env: Env, admin: Address) -> u32 {
        admin.require_auth();

        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if admin != stored_admin {
            panic!("unauthorized: caller is not admin");
        }

        let active_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SnapshotCount)
            .unwrap_or(0);
        if active_count >= 10 {
            panic!("Snapshot limit reached");
        }

        let snapshot_id: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SnapshotCounter)
            .unwrap_or(0)
            + 1;
        env.storage().persistent().set(&DataKey::SnapshotCounter, &snapshot_id);
        env.storage()
            .persistent()
            .set(&DataKey::SnapshotCount, &(active_count + 1));
        env.storage()
            .persistent()
            .set(&DataKey::SnapshotLedger(snapshot_id), &env.ledger().sequence());

        snapshot_id
    }

    /// Return the balance recorded for a holder at the specified snapshot.
    ///
    /// Reconstructed from the per-account checkpoint history: the balance is the
    /// value of the latest checkpoint at or before the snapshot's ledger. Returns
    /// 0 when the account had no balance at that ledger.
    pub fn snapshot_balance(env: Env, snapshot_id: u32, user: Address) -> i128 {
        let ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SnapshotLedger(snapshot_id))
            .unwrap_or(0);
        Self::balance_at(env, user, ledger)
    }

    /// Reconstruct an account's balance as of a given ledger from its checkpoints.
    fn balance_at(env: Env, user: Address, ledger: u32) -> i128 {
        let checkpoints: Vec<(u32, i128)> = env
            .storage()
            .persistent()
            .get(&DataKey::Checkpoints(user))
            .unwrap_or_else(|| Vec::new(&env));
        let mut result: i128 = 0;
        for i in 0..checkpoints.len() {
            let (cp_ledger, cp_balance) = checkpoints.get(i).unwrap();
            if cp_ledger <= ledger {
                result = cp_balance;
            } else {
                break;
            }
        }
        result
    }

    /// Append a checkpoint for `user` recording their balance at the current ledger.
    /// Called lazily on every balance change so snapshots need no holder scan.
    fn _checkpoint(env: &Env, user: &Address, balance: i128) {
        let mut checkpoints: Vec<(u32, i128)> = env
            .storage()
            .persistent()
            .get(&DataKey::Checkpoints(user.clone()))
            .unwrap_or_else(|| Vec::new(env));
        checkpoints.push_back((env.ledger().sequence(), balance));
        env.storage()
            .persistent()
            .set(&DataKey::Checkpoints(user.clone()), &checkpoints);
    }

    /// Delete a snapshot. Admin only. Removes the snapshot ledger entry and
    /// decrements the active snapshot count. Per-account checkpoints are retained
    /// so historical balances remain reconstructable.
    pub fn delete_snapshot(env: Env, admin: Address, snapshot_id: u32) {
        admin.require_auth();

        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if admin != stored_admin {
            panic!("unauthorized: caller is not admin");
        }

        if !env
            .storage()
            .persistent()
            .has(&DataKey::SnapshotLedger(snapshot_id))
        {
            panic!("snapshot not found");
        }

        env.storage()
            .persistent()
            .remove(&DataKey::SnapshotLedger(snapshot_id));

        let active_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SnapshotCount)
            .unwrap_or(0);
        if active_count > 0 {
            env.storage()
                .persistent()
                .set(&DataKey::SnapshotCount, &(active_count - 1));
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Credit `amount` to `to` and record a checkpoint. Constant work regardless
    /// of the number of holders.
    fn _credit(env: &Env, to: &Address, amount: i128) {
        let new_balance = Self::balance(env.clone(), to.clone()) + amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &new_balance);
        Self::_checkpoint(env, to, new_balance);
    }

    /// Debit `amount` from `from` and record a checkpoint. Constant work.
    fn _debit(env: &Env, from: &Address, amount: i128) {
        let new_balance = Self::balance(env.clone(), from.clone()) - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &new_balance);
        Self::_checkpoint(env, from, new_balance);
    }

    // ── SEP-41: mint / burn ───────────────────────────────────────────────────

    /// Mint `amount` loyalty points to `to`. Admin only.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let total: i128 = Self::total_supply(env.clone());
        let max: i128 = Self::max_supply(env.clone());
        if total + amount > max {
            panic!("max supply exceeded");
        }

        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total + amount));
        Self::_credit(&env, &to, amount);
    }

    /// Burn `amount` points from `from`. Requires `from`'s authorisation.
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            panic!("insufficient balance");
        }

        let total: i128 = Self::total_supply(env.clone());
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total - amount));
        Self::_debit(&env, &from, amount);
    }

    /// Burn `amount` points from `from` using `spender`'s allowance.
    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let allowance = Self::allowance(env.clone(), from.clone(), spender.clone());
        if allowance < amount {
            panic!("insufficient allowance");
        }

        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            panic!("insufficient balance");
        }

        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone()),
            &(allowance - amount),
        );

        let total: i128 = Self::total_supply(env.clone());
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total - amount));
        Self::_debit(&env, &from, amount);
    }

    // ── SEP-41: transfers ─────────────────────────────────────────────────────

    /// Transfer `amount` points from `from` to `to`. Requires `from`'s authorisation.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            panic!("insufficient balance");
        }

        Self::_debit(&env, &from, amount);
        Self::_credit(&env, &to, amount);
    }

    /// Transfer `amount` points from `from` to `to` using `spender`'s allowance.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let allowance = Self::allowance(env.clone(), from.clone(), spender.clone());
        if allowance < amount {
            panic!("insufficient allowance");
        }

        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            panic!("insufficient balance");
        }

        env.storage().persistent().set(
            &DataKey::Allowance(from.clone(), spender.clone()),
            &(allowance - amount),
        );

        Self::_debit(&env, &from, amount);
        Self::_credit(&env, &to, amount);
    }

    // ── SEP-41: allowances ────────────────────────────────────────────────────

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(owner, spender))
            .unwrap_or(0)
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128, expires_at: u64) {
        owner.require_auth();
        env.storage().persistent().set(
            &DataKey::Allowance(owner, spender),
            &AllowanceValue { amount, expires_at },
        );
    }

    // ── Tiers & redemption ────────────────────────────────────────────────────

    /// Return the highest tier index the account qualifies for, or `None`.
    pub fn get_discount(env: Env, user: Address) -> Option<u32> {
        let bal = Self::balance(env.clone(), user);
        let mut best: Option<u32> = None;
        for i in 0..MAX_TIERS {
            if let Some(tier) = env
                .storage()
                .persistent()
                .get::<DataKey, Tier>(&DataKey::Tier(i))
            {
                if bal >= tier.threshold {
                    best = Some(i);
                }
            }
        }
        best
    }

    /// Burn the tier's threshold points and return the discount in basis points.
    pub fn redeem(env: Env, user: Address, tier_index: u32) -> u32 {
        user.require_auth();

        if tier_index >= MAX_TIERS {
            panic!("invalid tier");
        }

        let tier: Tier = env
            .storage()
            .persistent()
            .get(&DataKey::Tier(tier_index))
            .expect("tier not configured");

        let bal = Self::balance(env.clone(), user.clone());
        if bal < tier.threshold {
            panic!("insufficient points for tier");
        }

        let total: i128 = Self::total_supply(env.clone());
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total - tier.threshold));
        Self::_debit(&env, &user, tier.threshold);

        tier.discount_bps
    }

    // ── Admin: fee config ─────────────────────────────────────────────────────

    pub fn set_transfer_fee_bps(env: Env, admin: Address, bps: u32) {
        admin.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if admin != stored_admin {
            panic!("unauthorized: caller is not admin");
        }
        if bps > MAX_DISCOUNT_BPS {
            panic!("fee too high");
        }
        env.storage().persistent().set(&DataKey::TransferFeeBps, &bps);
    }

    pub fn transfer_fee_bps(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::TransferFeeBps)
            .unwrap_or(0)
            .get(&DataKey::KycContractAddress);

        if let Some(kyc_addr) = kyc_contract {
            // Cross-contract call to kyc-attestation contract
            // Pass both user address and KYC tier (Basic as default)
            let kyc_client = env.invoke_contract::<bool>(
                &kyc_addr,
                &Symbol::new(env, "is_verified"),
                soroban_sdk::vec![env, from.clone().into_val(env), KycTier::Basic.into_val(env)],
            );

            if !kyc_client {
                panic!("Transfer requires KYC verification");
            }

            let kyc_client_to = env.invoke_contract::<bool>(
                &kyc_addr,
                &Symbol::new(env, "is_verified"),
                soroban_sdk::vec![env, to.clone().into_val(env), KycTier::Basic.into_val(env)],
            );

            if !kyc_client_to {
                panic!("Transfer requires KYC verification");
            }
        }
    }

    // ── Admin: KYC ────────────────────────────────────────────────────────────

    pub fn set_kyc_contract(env: Env, admin: Address, kyc: Address) {
        admin.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if admin != stored_admin {
            panic!("unauthorized: caller is not admin");
        }
        env.storage()
            .persistent()
            .set(&DataKey::KycContractAddress, &kyc);
    }

    pub fn kyc_contract(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::KycContractAddress)
    }
}
