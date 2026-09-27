#![no_std]

//! # Fee Distributor Contract
//!
//! On-chain platform fee accumulation and withdrawal for AfriPay.
//! Makes the fee model fully transparent and auditable on Stellar.
//!
//! ## Access control
//! - `deposit_fee`           — any caller (typically the backend service account)
//! - `get_accumulated_fees`  — public
//! - `get_all_accumulated_fees` — public
//! - `get_agent_pool_fees`   — public
//! - `withdraw_fees`         — admin only
//! - `distribute_agent_pool` — admin only
//! - `update_split`          — admin only
//!
//! ## Agent pool lifecycle
//! Each `deposit_fee` splits the deposit into a platform portion
//! (`AccumulatedFees(token)`) and an agent reward portion
//! (`AgentPoolFees(token)`) according to `split_bps`.  The agent pool is
//! distributed to individual agent addresses via `distribute_agent_pool`, which
//! transfers the requested amounts to each recipient and emits an
//! `AgentPoolDistributed` event per recipient.  There is no admin self-withdraw
//! path for the agent pool: funds can only leave it to the agent addresses
//! supplied by the admin.  Every outbound transfer (`withdraw_fees` and
//! `distribute_agent_pool`) panics while the contract is `Paused`.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, vec, Address, Env, Symbol, Vec,
};

mod test;

// ── Constants ─────────────────────────────────────────────────────────────────

// SECURITY: i128 max is ~170 trillion USDC in stroops.
// MAX_DEPOSIT_AMOUNT caps a single deposit at 1,000,000 USDC (10_000_000_000_000 stroops),
// consistent with the MAX_ESCROW_AMOUNT ceiling in escrow.rs.  This provides a
// contract-level backstop against caller-side unit/precision bugs (e.g. a
// decimal-precision mismatch depositing an amount 10,000× too large).
const MAX_DEPOSIT_AMOUNT: i128 = 10_000_000_000_000;

// ── Storage keys ──────────────────────────────────────────────────────────────

// SC-014: Removed the duplicate, single-fee-rate design's dead storage keys
// (`UsdcAddress`, non-parameterised `AccumulatedFees`, `PlatformFeeBps`) that
// conflicted with the current split-pool model's token-keyed
// `AccumulatedFees(Address)` variant.  The canonical design is the
// split_bps/multi-token model whose storage keys are used throughout the rest
// of this file (`AccumulatedFees(Address)`, `AgentPoolFees(Address)`,
// `SplitBps`, `TokenList`).  The old single-fee-rate variants were leftover
// dead code from an earlier design iteration.
#[contracttype]
pub enum DataKey {
    /// The admin address authorised to withdraw fees and update settings.
    Admin,
    /// Per-token platform treasury accumulator.
    AccumulatedFees(Address),
    /// Per-token agent reward pool accumulator.
    AgentPoolFees(Address),
    /// Basis points allocated to the agent reward pool (0–5000).
    SplitBps,
    /// Ordered list of every token address that has ever received a deposit.
    /// Used by `get_all_accumulated_fees` to enumerate per-token balances.
    TokenList,
    /// Whether the contract is currently paused.
    Paused,
}

// ── Event payloads ────────────────────────────────────────────────────────────

#[derive(Clone)]
#[contracttype]
pub struct EvtFeeDeposited {
    pub depositor: Address,
    pub token: Address,
    pub amount: i128,
    pub total: i128,
    pub source: Option<Address>,
}

#[derive(Clone)]
#[contracttype]
pub struct EvtFeesWithdrawn {
    pub admin: Address,
    pub token: Address,
    pub amount: i128,
    pub remaining: i128,
    pub timestamp: u64,
}

/// Emitted once per recipient when the agent pool is distributed.
#[derive(Clone)]
#[contracttype]
pub struct EvtAgentPoolDistributed {
    pub admin: Address,
    pub token: Address,
    pub agent: Address,
    pub amount: i128,
    pub remaining: i128,
    pub timestamp: u64,
}

// SC-016 fix: `FeeRateUpdated` struct was missing its closing brace.
// Added `}` after `updated_by` field.
#[derive(Clone)]
#[contracttype]
pub struct FeeRateUpdated {
    pub old_bps: u32,
    pub new_bps: u32,
    pub updated_by: Address,
}

/// Emitted when the admin changes the fee split ratio.
#[derive(Clone)]
#[contracttype]
pub struct EvtSplitUpdated {
    pub old_split_bps: u32,
    pub new_split_bps: u32,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Append `token` to the on-chain `TokenList` if it is not already present.
/// This is O(n) in the number of distinct tokens, which is expected to be small.
// SC-016 fix: `register_token` was missing its closing brace.
// The `if !list.contains(token) { ... }` inner block was correctly closed but
// the function itself was never closed.  Added `}` after the inner block.
fn register_token(env: &Env, token: &Address) {
    let mut list: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::TokenList)
        .unwrap_or_else(|| vec![env]);

    if !list.contains(token) {
        list.push_back(token.clone());
        env.storage().persistent().set(&DataKey::TokenList, &list);
    }
}

#[derive(Clone)]
#[contracttype]
pub struct EvtContractPaused {
    pub admin: Address,
    pub paused_at: u64,
}

#[derive(Clone)]
#[contracttype]
pub struct EvtContractUnpaused {
    pub admin: Address,
    pub unpaused_at: u64,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct FeeDistributorContract;

#[contractimpl]
impl FeeDistributorContract {
    /// Initialise the contract. Must be called once.
    ///
    /// SC-014: Removed the duplicate `initialize(env, admin, usdc_address,
    /// platform_fee_bps)` overload that was left over from an earlier
    /// single-fee-rate design.  It conflicted with this function
    /// (`error[E0592]: duplicate definitions with name 'initialize'`) and used
    /// dead storage keys (`UsdcAddress`, non-parameterised `AccumulatedFees`,
    /// `PlatformFeeBps`) that are not used anywhere else in the file.
    ///
    /// # Arguments
    /// * `admin`     — Address authorised to withdraw accumulated fees.
    /// * `split_bps` — Basis points (0–5000) of each deposit routed to the
    ///                 agent reward pool. E.g. 2000 = 20 %. Must not exceed 5000.
    pub fn initialize(env: Env, admin: Address, split_bps: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if split_bps > 5000 {
            panic!("split_bps exceeds maximum of 5000");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::SplitBps, &split_bps);
        // Initialise an empty token list.
        let empty: Vec<Address> = vec![&env];
        env.storage().persistent().set(&DataKey::TokenList, &empty);
    }

    /// Deposit a platform fee into the contract for a specific token.
    ///
    /// Transfers `amount` of `token` from `depositor` into the contract and
    /// splits the deposit between the platform treasury
    /// (`AccumulatedFees(token)`) and the agent reward pool
    /// (`AgentPoolFees(token)`) according to the current `split_bps`.
    /// Emits a `FeeDeposited` event where `total` reflects the platform portion.
    ///
    /// # Arguments
    /// * `depositor` — Address sending the fee (must authorise this call).
    /// * `token`     — Asset contract address for the fee token (e.g. USDC or XLM).
    /// * `amount`    — Fee amount in token stroops (must be > 0).
    /// * `source`    — Optional originating address for audit purposes.
    pub fn deposit_fee(
        env: Env,
        depositor: Address,
        token: Address,
        amount: i128,
        source: Option<Address>,
    ) {
        if amount <= 0 {
            panic!("amount must be positive");
        }
        if amount > MAX_DEPOSIT_AMOUNT {
            panic!("amount exceeds maximum deposit limit");
        }

        if env.storage().persistent().get(&DataKey::Paused).unwrap_or(false) {
            panic!("Contract is paused");
        }

        depositor.require_auth();

        // Transfer the full amount from the depositor to this contract.
        token::Client::new(&env, &token).transfer(
            &depositor,
            &env.current_contract_address(),
            &amount,
        );

        // Compute the agent-pool portion and the platform portion.
        let split_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SplitBps)
            .unwrap_or(0);

        let agent_portion: i128 = amount * (split_bps as i128) / 10_000;
        let platform_portion: i128 = amount - agent_portion;

        // Update per-token platform treasury.
        let total: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AccumulatedFees(token.clone()))
            .unwrap_or(0)
            + platform_portion;
        env.storage()
            .persistent()
            .set(&DataKey::AccumulatedFees(token.clone()), &total);

        // Update per-token agent reward pool.
        let pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AgentPoolFees(token.clone()))
            .unwrap_or(0)
            + agent_portion;
        env.storage()
            .persistent()
            .set(&DataKey::AgentPoolFees(token.clone()), &pool);

        register_token(&env, &token);

        env.events().publish(
            (Symbol::new(&env, "FeeDeposited"), depositor.clone()),
            EvtFeeDeposited {
                depositor,
                token,
                amount,
                total,
                source,
            },
        );
    }

    /// Withdraw accumulated platform fees to the admin.
    ///
    /// Panics while the contract is paused.
    pub fn withdraw_fees(env: Env, admin: Address, token: Address, amount: i128) {
        if env.storage().persistent().get(&DataKey::Paused).unwrap_or(false) {
            panic!("Contract is paused");
        }

        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AccumulatedFees(token.clone()))
            .unwrap_or(0);
        if amount > current {
            panic!("insufficient accumulated fees");
        }

        let remaining = current - amount;
        env.storage()
            .persistent()
            .set(&DataKey::AccumulatedFees(token.clone()), &remaining);

        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &admin,
            &amount,
        );

        env.events().publish(
            (Symbol::new(&env, "FeesWithdrawn"), admin.clone()),
            EvtFeesWithdrawn {
                admin,
                token,
                amount,
                remaining,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    /// Distribute agent-pool funds to individual agent addresses.
    ///
    /// The admin supplies a list of `(agent, amount)` pairs; each amount is
    /// transferred from the contract to the corresponding agent address and an
    /// `AgentPoolDistributed` event is emitted per recipient.  This replaces the
    /// old admin self-withdraw path so the agent pool can no longer be drained
    /// to the admin's own address.
    ///
    /// Panics while the contract is paused.
    ///
    /// # Arguments
    /// * `admin`        — Must be the stored admin and authorise this call.
    /// * `token`        — Asset contract address for the pool token.
    /// * `recipients`   — `(agent, amount)` pairs; each amount must be > 0.
    pub fn distribute_agent_pool(
        env: Env,
        admin: Address,
        token: Address,
        recipients: Vec<(Address, i128)>,
    ) {
        if env.storage().persistent().get(&DataKey::Paused).unwrap_or(false) {
            panic!("Contract is paused");
        }

        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();

        if recipients.is_empty() {
            panic!("recipients must not be empty");
        }

        let mut pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AgentPoolFees(token.clone()))
            .unwrap_or(0);

        let token_client = token::Client::new(&env, &token);
        let contract = env.current_contract_address();

        for (agent, amount) in recipients.iter() {
            if amount <= 0 {
                panic!("amount must be positive");
            }
            if amount > pool {
                panic!("insufficient agent pool fees");
            }

            pool -= amount;

            token_client.transfer(&contract, &agent, &amount);

            env.events().publish(
                (Symbol::new(&env, "AgentPoolDistributed"), agent.clone()),
                EvtAgentPoolDistributed {
                    admin: admin.clone(),
                    token: token.clone(),
                    agent,
                    amount,
                    remaining: pool,
                    timestamp: env.ledger().timestamp(),
                },
            );
        }

        env.storage()
            .persistent()
            .set(&DataKey::AgentPoolFees(token.clone()), &pool);
    }

    /// Read the accumulated platform fees for a token.
    pub fn get_accumulated_fees(env: Env, token: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::AccumulatedFees(token))
            .unwrap_or(0)
    }

    /// Read the accumulated agent-pool fees for a token.
    pub fn get_agent_pool_fees(env: Env, token: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::AgentPoolFees(token))
            .unwrap_or(0)
    }

    /// Update the agent-pool split ratio. Admin only.
    pub fn update_split(env: Env, admin: Address, new_split_bps: u32) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();

        if new_split_bps > 5000 {
            panic!("split_bps exceeds maximum of 5000");
        }

        let old_split_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SplitBps)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::SplitBps, &new_split_bps);

        env.events().publish(
            (Symbol::new(&env, "SplitUpdated"), admin.clone()),
            EvtSplitUpdated {
                old_split_bps,
                new_split_bps,
            },
        );
    }

    /// Pause the contract. Admin only.
    pub fn pause(env: Env, admin: Address) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();

        env.storage().persistent().set(&DataKey::Paused, &true);

        env.events().publish(
            (Symbol::new(&env, "ContractPaused"), admin.clone()),
            EvtContractPaused {
                admin,
                paused_at: env.ledger().timestamp(),
            },
        );
    }

    /// Unpause the contract. Admin only.
    pub fn unpause(env: Env, admin: Address) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();

        env.storage().persistent().set(&DataKey::Paused, &false);

        env.events().publish(
            (Symbol::new(&env, "ContractUnpaused"), admin.clone()),
            EvtContractUnpaused {
                admin,
                unpaused_at: env.ledger().timestamp(),
            },
        );
    }

    /// Whether the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage().persistent().get(&DataKey::Paused).unwrap_or(false)
    }
}
