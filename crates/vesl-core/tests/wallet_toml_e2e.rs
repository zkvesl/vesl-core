//! End-to-end exercise of the TOML config-toggle pattern.
//!
//! Builds a `SettlementToml` shaped like a real `vesl.toml` would be —
//! `[wallet]` plus `[wallet.intent]` and `[wallet.payment]` sub-blocks
//! — resolves it to a `SettlementConfig`, derives both the intent
//! signer and the payment signer from the same wallet, signs two
//! messages with each key, and verifies both signatures via
//! `vesl-signing`.
//!
//! Asserts the core promise of the pattern: same code path, different
//! TOML role section, different key.

use nockchain_math::belt::Belt;
use vesl_core::SigningError;
use vesl_core::config::{
    SettlementCliOverrides, SettlementConfig, SettlementMode, SettlementToml, WalletRoleToml,
    WalletToml,
};
use vesl_signing::prelude::Belt as VeslBelt;
use vesl_signing::schnorr::{SchnorrPrivateKey, schnorr_sign, schnorr_verify};

/// Canonical BIP-39 12-word test vector ("abandon×11 + about").
const CANONICAL_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon about";

fn settlement_toml_with_wallet() -> SettlementToml {
    SettlementToml {
        chain_endpoint: Some("http://node:9090".into()),
        wallet: Some(WalletToml {
            seed_phrase: Some(CANONICAL_MNEMONIC.into()),
            // Defaults applied for everything else: VESL_COIN_TYPE_PLACEHOLDER,
            // account = 0, intent.role = ROLE_INTENT, payment.role = ROLE_X402.
            intent: Some(WalletRoleToml {
                role: None,
                index: Some(7),
            }),
            payment: Some(WalletRoleToml {
                role: None,
                index: Some(13),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Convert vesl-core's `[Belt; 8]` into a `SchnorrPrivateKey` so the
/// integration test can sign through the vesl-signing API directly.
fn key_from_belts(belts: &[Belt; 8]) -> SchnorrPrivateKey {
    let vesl_belts: [VeslBelt; 8] = std::array::from_fn(|i| VeslBelt(belts[i].0));
    SchnorrPrivateKey::from_belts(&vesl_belts).expect("derived scalar must be in (0, G_ORDER)")
}

#[test]
fn nested_toml_drives_intent_and_payment_to_distinct_keys() {
    let toml = settlement_toml_with_wallet();
    let cfg = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            ..Default::default()
        },
        &toml,
        None,
    )
    .expect("dumbnet with wallet seed phrase resolves");

    let intent_belts = cfg
        .intent_signer_belts()
        .expect("intent derivation succeeds");
    let payment_belts = cfg
        .payment_signer_belts()
        .expect("payment derivation succeeds");

    assert_ne!(
        intent_belts, payment_belts,
        "intent and payment must derive distinct scalars"
    );
}

#[test]
fn same_code_signs_under_intent_and_payment_keys_via_toml_toggle() {
    // The full role-toggle round-trip: write TOML once, derive both
    // role keys via the same SettlementConfig surface, sign two
    // messages, verify both signatures, and confirm the keys don't
    // accidentally verify each other's signatures.
    let toml = settlement_toml_with_wallet();
    let cfg = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            ..Default::default()
        },
        &toml,
        None,
    )
    .unwrap();

    let intent_key = key_from_belts(&cfg.intent_signer_belts().expect("intent key present"));
    let payment_key = key_from_belts(&cfg.payment_signer_belts().expect("payment key present"));

    let intent_msg = [VeslBelt(11), VeslBelt(22), VeslBelt(33), VeslBelt(44), VeslBelt(55)];
    let payment_msg = [VeslBelt(99), VeslBelt(98), VeslBelt(97), VeslBelt(96), VeslBelt(95)];

    let (i_chal, i_sig) = schnorr_sign(&intent_key, &intent_msg).unwrap();
    let (p_chal, p_sig) = schnorr_sign(&payment_key, &payment_msg).unwrap();

    schnorr_verify(
        &intent_key.public_key().unwrap(),
        &intent_msg,
        &i_chal,
        &i_sig,
    )
    .expect("intent signature verifies under its own pubkey");
    schnorr_verify(
        &payment_key.public_key().unwrap(),
        &payment_msg,
        &p_chal,
        &p_sig,
    )
    .expect("payment signature verifies under its own pubkey");

    // Cross-verify: each pubkey rejects the other's signature.
    assert!(
        schnorr_verify(
            &intent_key.public_key().unwrap(),
            &payment_msg,
            &p_chal,
            &p_sig
        )
        .is_err(),
        "intent pubkey must NOT verify a payment-key signature"
    );
    assert!(
        schnorr_verify(
            &payment_key.public_key().unwrap(),
            &intent_msg,
            &i_chal,
            &i_sig
        )
        .is_err(),
        "payment pubkey must NOT verify an intent-key signature"
    );
}

#[test]
fn wallet_toml_indices_round_trip_into_signing_keys() {
    // Index changes propagate from TOML into the derived key (i.e. the
    // role index is honoured rather than being silently zeroed).
    let mut toml_a = settlement_toml_with_wallet();
    toml_a.wallet.as_mut().unwrap().intent = Some(WalletRoleToml {
        role: None,
        index: Some(0),
    });
    let mut toml_b = settlement_toml_with_wallet();
    toml_b.wallet.as_mut().unwrap().intent = Some(WalletRoleToml {
        role: None,
        index: Some(1),
    });

    let cfg_a = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            ..Default::default()
        },
        &toml_a,
        None,
    )
    .unwrap();
    let cfg_b = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            ..Default::default()
        },
        &toml_b,
        None,
    )
    .unwrap();

    let key_a = cfg_a.intent_signer_belts().unwrap();
    let key_b = cfg_b.intent_signer_belts().unwrap();
    assert_ne!(
        key_a, key_b,
        "different `intent.index` must derive different scalars"
    );
}

#[test]
fn cli_account_override_propagates_to_derived_key() {
    // Verifies CLI > TOML for the `account` field. Two configs that
    // differ only in `account` (one from TOML default 0, one from CLI
    // override 5) must derive different keys.
    let toml = settlement_toml_with_wallet();
    let cfg_default_account = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            ..Default::default()
        },
        &toml,
        None,
    )
    .unwrap();
    let cfg_overridden = SettlementConfig::resolve_checked(
        &SettlementCliOverrides {
            mode: Some(SettlementMode::Dumbnet),
            account: Some(5),
            ..Default::default()
        },
        &toml,
        None,
    )
    .unwrap();

    let k0 = cfg_default_account.intent_signer_belts().unwrap();
    let k5 = cfg_overridden.intent_signer_belts().unwrap();
    assert_ne!(
        k0, k5,
        "CLI account override must produce a different derived key"
    );
}

#[test]
fn missing_wallet_block_yields_no_signing_keys() {
    let toml = SettlementToml::default();
    let cfg =
        SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None).unwrap();
    assert!(cfg.wallet.is_none());
    assert!(matches!(
        cfg.intent_signer_belts(),
        Err(SigningError::NoSeedPhrase)
    ));
    assert!(matches!(
        cfg.payment_signer_belts(),
        Err(SigningError::NoSeedPhrase)
    ));
}
