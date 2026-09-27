#![cfg(test)]

use soroban_sdk::{testutils::{Address as _, Ledger}, Address, Bytes, Env};

use crate::{KycAttestationContract, KycAttestationContractClient, KycTier};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup() -> (Env, KycAttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, KycAttestationContract);
    let client = KycAttestationContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

fn hash(env: &Env) -> Bytes {
    // Simulate a 32-byte SHA-256 hash
    Bytes::from_array(env, &[0xabu8; 32])
}

// ── initialize ────────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "already initialized")]
fn test_double_initialize_panics() {
    let (_, client, admin) = setup();
    client.initialize(&admin);
}

// ── attest ────────────────────────────────────────────────────────────────────

#[test]
fn test_attest_stores_record() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);

    let record = client.get_attestation(&user, KycTier::Basic);
    assert_eq!(record.revoked_at, 0);
    assert!(record.attested_at > 0);
}

#[test]
fn test_attest_makes_user_verified() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    assert!(client.is_verified(&user, KycTier::Basic));
}

#[test]
#[should_panic(expected = "unauthorized: caller is not admin")]
fn test_attest_non_admin_panics() {
    let (env, client, _) = setup();
    let impostor = Address::generate(&env);
    let user = Address::generate(&env);
    client.attest(&impostor, &user, KycTier::Basic, &hash(&env), 0);
}

#[test]
#[should_panic(expected = "kyc_hash must not be empty")]
fn test_attest_empty_hash_panics() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &Bytes::new(&env), 0);
}

#[test]
#[should_panic(expected = "user already has an active attestation")]
fn test_attest_duplicate_active_panics() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
}

#[test]
fn test_attest_after_revoke_succeeds() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    env.ledger().with_mut(|li| li.timestamp += 1);
    client.revoke(&admin, &user, KycTier::Basic);
    // Re-attest after revocation should succeed
    env.ledger().with_mut(|li| li.timestamp += 1);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    assert!(client.is_verified(&user, KycTier::Basic));
}

// ── revoke ────────────────────────────────────────────────────────────────────

#[test]
fn test_revoke_sets_revoked_at() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    env.ledger().with_mut(|li| li.timestamp += 100);
    client.revoke(&admin, &user, KycTier::Basic);

    let record = client.get_attestation(&user, KycTier::Basic);
    assert!(record.revoked_at > 0);
}

#[test]
fn test_revoke_makes_user_unverified() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.revoke(&admin, &user, KycTier::Basic);
    assert!(!client.is_verified(&user, KycTier::Basic));
}

#[test]
#[should_panic(expected = "unauthorized: caller is not admin")]
fn test_revoke_non_admin_panics() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    let impostor = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.revoke(&impostor, &user, KycTier::Basic);
}

#[test]
#[should_panic(expected = "no attestation found for user and tier")]
fn test_revoke_nonexistent_panics() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.revoke(&admin, &user, KycTier::Basic);
}

#[test]
#[should_panic(expected = "attestation already revoked")]
fn test_revoke_twice_panics() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.revoke(&admin, &user, KycTier::Basic);
    client.revoke(&admin, &user, KycTier::Basic);
}

// ── is_verified ───────────────────────────────────────────────────────────────

#[test]
fn test_is_verified_false_for_unknown_user() {
    let (env, client, _) = setup();
    let user = Address::generate(&env);
    assert!(!client.is_verified(&user, KycTier::Basic));
}

#[test]
fn test_is_verified_true_after_attest() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    assert!(client.is_verified(&user, KycTier::Basic));
}

#[test]
fn test_is_verified_false_after_revoke() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.revoke(&admin, &user, KycTier::Basic);
    assert!(!client.is_verified(&user, KycTier::Basic));
}

#[test]
fn test_multiple_users_independent() {
    let (env, client, admin) = setup();
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    client.attest(&admin, &user1, KycTier::Basic, &hash(&env), 0);
    assert!(client.is_verified(&user1, KycTier::Basic));
    assert!(!client.is_verified(&user2, KycTier::Basic));
}

// ── get_attestation ───────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "no attestation found for user and tier")]
fn test_get_attestation_nonexistent_panics() {
    let (env, client, _) = setup();
    client.get_attestation(&Address::generate(&env), KycTier::Basic);
}

#[test]
fn test_get_attestation_hash_matches() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);
    let h = hash(&env);
    client.attest(&admin, &user, KycTier::Basic, &h, 0);
    assert_eq!(client.get_attestation(&user, KycTier::Basic).kyc_hash, h);
}

#[test]
fn test_attest_all_tiers_and_verify_independently() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Enhanced, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);

    assert!(client.is_verified(&user, KycTier::Basic));
    assert!(client.is_verified(&user, KycTier::Enhanced));
    assert!(client.is_verified(&user, KycTier::Business));
}

#[test]
fn test_revoke_one_tier_leaves_others_verified() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Enhanced, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);

    client.revoke(&admin, &user, KycTier::Enhanced);

    assert!(client.is_verified(&user, KycTier::Basic));
    assert!(!client.is_verified(&user, KycTier::Enhanced));
    assert!(client.is_verified(&user, KycTier::Business));
}

// ── tier mirroring (SC-110) ───────────────────────────────────────────────────

#[test]
fn test_attest_business_does_not_touch_basic_tier() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    // Attest only at Business; the Basic slot must remain untouched.
    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);

    assert!(!client.is_verified(&user, KycTier::Basic));
    assert!(client.is_verified(&user, KycTier::Business));
}

#[test]
fn test_attest_business_does_not_overwrite_existing_basic() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    let basic_before = client.get_attestation(&user, KycTier::Basic);

    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);

    let basic_after = client.get_attestation(&user, KycTier::Basic);
    assert_eq!(basic_before.kyc_hash, basic_after.kyc_hash);
    assert_eq!(basic_before.attested_at, basic_after.attested_at);
    assert_eq!(basic_after.revoked_at, 0);
    assert!(client.is_verified(&user, KycTier::Basic));
}

#[test]
fn test_revoke_enhanced_does_not_touch_basic_or_business() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Enhanced, &hash(&env), 0);
    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);

    let basic_before = client.get_attestation(&user, KycTier::Basic);
    let business_before = client.get_attestation(&user, KycTier::Business);

    client.revoke(&admin, &user, KycTier::Enhanced);

    let basic_after = client.get_attestation(&user, KycTier::Basic);
    let business_after = client.get_attestation(&user, KycTier::Business);

    assert_eq!(basic_before.kyc_hash, basic_after.kyc_hash);
    assert_eq!(basic_after.revoked_at, 0);
    assert_eq!(business_before.kyc_hash, business_after.kyc_hash);
    assert_eq!(business_after.revoked_at, 0);

    assert!(client.is_verified(&user, KycTier::Basic));
    assert!(!client.is_verified(&user, KycTier::Enhanced));
    assert!(client.is_verified(&user, KycTier::Business));
}

#[test]
fn test_get_highest_tier_returns_correct_tier() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    assert_eq!(client.get_highest_tier(&user), None);

    client.attest(&admin, &user, KycTier::Basic, &hash(&env), 0);
    assert_eq!(client.get_highest_tier(&user), Some(KycTier::Basic));

    client.attest(&admin, &user, KycTier::Enhanced, &hash(&env), 0);
    assert_eq!(client.get_highest_tier(&user), Some(KycTier::Enhanced));

    client.attest(&admin, &user, KycTier::Business, &hash(&env), 0);
    assert_eq!(client.get_highest_tier(&user), Some(KycTier::Business));
}
