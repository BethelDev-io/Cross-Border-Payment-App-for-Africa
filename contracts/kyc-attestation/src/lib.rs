#![no_std]

//! # KYC Attestation Contract
//!
//! On-chain KYC attestation for AfriPay. Stores a SHA-256 hash of the user's
//! KYC data — never raw PII. Any Stellar ecosystem participant can call
//! [`is_valid_and_unexpired`] to check a wallet's KYC status without trusting
//! AfriPay's centralized database.
//!
//! ## Access control
//! - `attest` and `revoke` — admin only
//! - `is_valid_and_unexpired` — public
//!
//! ## Expiry-aware vs. non-expiry-aware checks
//! - [`is_valid_and_unexpired`] is the **expiry-aware** check: it returns `true`
//!   only when an attestation exists, has not been revoked, **and** has not
//!   expired. All fund-gating decisions MUST use this variant.
//! - [`has_ever_attested`] is the **non-expiry-aware** check: it returns `true`
//!   when an attestation exists and has not been revoked, **ignoring expiry**.
//!   It is retained only for historical/audit purposes and MUST NOT be used to
//!   gate fund-moving actions.

use soroban_sdk::{contract, contractimpl, contracttype, bytes, Address, Bytes, Env, Symbol};

mod test;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[contracttype]
#[repr(u32)]
pub enum KycTier {
    Basic = 0,
    Enhanced = 1,
    Business = 2,
}

#[contracttype]
pub enum DataKey {
    Admin,
    TieredAttestation(Address, KycTier),
    Attestation(Address),
    AttestationByTier(Address, KycTier),
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// Supported KYC tiers for attestation records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[contracttype]
pub enum KycTier {
    Basic,
    Standard,
    Premium,
}

/// On-chain KYC attestation record.
#[derive(Clone)]
#[contracttype]
pub struct Attestation {
    /// SHA-256 hash of the off-chain KYC document bundle (hex-encoded bytes).
    /// Raw PII is never stored on-chain.
    pub kyc_hash: Bytes,
    /// Unix timestamp when the attestation was issued.
    pub attested_at: u64,
    /// Unix timestamp when the attestation was revoked, or 0 if still active.
    pub revoked_at: u64,
    /// Unix ledger timestamp after which the attestation is considered expired.
    /// 0 means the attestation never expires.
    pub expires_at: u64,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
#[contracttype]
pub struct AttestationRevoked {
    pub user: Address,
    pub tier: KycTier,
}

#[derive(Clone)]
#[contracttype]
pub struct BatchRevocationCompleted {
    pub count: u32,
    pub admin: Address,
    pub timestamp: u64,
}

#[contract]
pub struct KycAttestationContract;

#[contractimpl]
impl KycAttestationContract {
    /// Initialise the contract. Must be called once.
    ///
    /// # Arguments
    /// * `admin` — The AfriPay admin address authorised to attest and revoke.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Record a KYC attestation for `user`.
    ///
    /// Only the admin may call this. Panics if the user already has an active
    /// (non-revoked) attestation.
    ///
    /// # Arguments
    /// * `admin`      — Must match the admin set during `initialize`.
    /// * `user`       — Stellar address of the verified user.
    /// * `kyc_hash`   — SHA-256 hash of the KYC document bundle. Never raw PII.
    /// * `expires_at` — Ledger timestamp after which the attestation expires.
    ///                  Pass 0 for no expiry.
    pub fn attest(
        env: Env,
        admin: Address,
        user: Address,
        tier: KycTier,
        kyc_hash: Bytes,
        expires_at: u64,
    ) {
        admin.require_auth();
        Self::assert_admin(&env, &admin);

        if kyc_hash.len() == 0 {
            panic!("kyc_hash must not be empty");
        }
        if expires_at != 0 && expires_at <= env.ledger().timestamp() {
            panic!("expires_at must be greater than current timestamp");
        }

        let key = DataKey::TieredAttestation(user.clone(), tier.clone());

        // Allow re-attestation: update existing attestation if present
        let original_attested_at = if let Some(existing) = env.storage().persistent().get::<_, Attestation>(&key) {
            existing.attested_at
        } else {
            0
        };

        let record = Attestation {
            kyc_hash,
            attested_at: if original_attested_at > 0 { original_attested_at } else { env.ledger().timestamp() },
            revoked_at: 0,
            expires_at,
        };
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .set(&DataKey::Attestation(user.clone()), &record);
        env.storage().persistent().set(
            &DataKey::AttestationByTier(user.clone(), KycTier::Basic),
            &record,
        );

        env.events().publish((Symbol::new(&env, "KycAttested"),), (user, tier));
    }

    /// Revoke an existing attestation for `user` and `tier`.
    ///
    /// Only the admin may call this. Panics if no active attestation exists.
    ///
    /// # Arguments
    /// * `admin` — Must match the admin set during `initialize`.
    /// * `user`  — Stellar address whose attestation should be revoked.
    /// * `tier`  — KYC tier to revoke.
    pub fn revoke(env: Env, admin: Address, user: Address, tier: KycTier) {
        admin.require_auth();
        Self::assert_admin(&env, &admin);

        let key = DataKey::TieredAttestation(user.clone(), tier.clone());
        let mut record: Attestation = env
            .storage()
            .persistent()
            .get(&key)
            .expect("no attestation found for user and tier");

        if record.revoked_at != 0 {
            panic!("attestation already revoked");
        }

        record.revoked_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .set(&DataKey::Attestation(user.clone()), &record);
        env.storage().persistent().set(
            &DataKey::AttestationByTier(user.clone(), KycTier::Basic),
            &record,
        );

        env.events().publish((Symbol::new(&env, "KycRevoked"),), (user, tier));
    }

    /// Returns `true` if `user` has a current, non-revoked, non-expired KYC attestation for `tier`.
    ///
    /// This is the **expiry-aware** check and the canonical entry point for any
    /// fund-gating decision (e.g. escrow creation). It returns `false` when the
    /// attestation is missing, has been revoked, or has passed its `expires_at`
    /// timestamp.
    ///
    /// Public — any caller may invoke this.
    ///
    /// # Arguments
    /// * `user` — Stellar address to check.
    /// * `tier` — KYC tier to verify.
    pub fn is_valid_and_unexpired(env: Env, user: Address, tier: KycTier) -> bool {
        match env
            .storage()
            .persistent()
            .get::<_, Attestation>(&DataKey::TieredAttestation(user, tier))
        {
            Some(record) => {
                if record.revoked_at != 0 {
                    return false;
                }
                if record.expires_at != 0 && env.ledger().timestamp() > record.expires_at {
                    return false;
                }
                true
            }
            None => false,
        }
    }

    /// Returns `true` if `user` has ever been attested for `tier` and that
    /// attestation has not been explicitly revoked — **ignoring expiry**.
    ///
    /// This is the **non-expiry-aware** check. It is retained only for
    /// historical/audit purposes and MUST NOT be used to gate fund-moving
    /// actions; use [`is_valid_and_unexpired`] for that instead.
    ///
    /// Public — any caller may invoke this.
    ///
    /// # Arguments
    /// * `user` — Stellar address to check.
    /// * `tier` — KYC tier to check.
    pub fn has_ever_attested(env: Env, user: Address, tier: KycTier) -> bool {
        match env
            .storage()
            .persistent()
            .get::<_, Attestation>(&DataKey::TieredAttestation(user, tier))
        {
            Some(record) => record.revoked_at == 0,
            None => false,
        }
    }

    /// Returns the highest verified tier for `user`, or `None` if no tier is verified.
    ///
    /// Uses the expiry-aware [`is_valid_and_unexpired`] check.
    pub fn get_highest_tier(env: Env, user: Address) -> Option<KycTier> {
        for tier in [KycTier::Business, KycTier::Enhanced, KycTier::Basic] {
            if Self::is_valid_and_unexpired(env.clone(), user.clone(), tier.clone()) {
                return Some(tier);
            }
        }
        None
    }

    /// Revoke attestations for multiple users atomically.
    ///
    /// Only the admin may call this. Skips users with no active attestation
    /// rather than panicking, to allow partial-valid batches.
    ///
    /// # Arguments
    /// * `admin` — Must match the admin set during `initialize`.
    /// * `users` — List of Stellar addresses to revoke.
    pub fn revoke_batch(env: Env, admin: Address, users: soroban_sdk::Vec<Address>) {
        admin.require_auth();
        Self::assert_admin(&env, &admin);

        let now = env.ledger().timestamp();
        for user in users.iter() {
            for tier in [KycTier::

/* … truncated 3642 chars — edit only what you need near the top … */
