//! Settlement mode configuration — generic SDK layer.
//!
//! Centralizes the three settlement modes (local, fakenet, dumbnet) and
//! the resolution logic: CLI flags > env vars > toml > mode defaults.
//!
//! Domain-specific config (VeslConfig with ollama_url, etc.) stays in the
//! hull crate. This module provides the settlement-related subset.

use std::fmt;

use nockchain_math::belt::Belt;
use vesl_wallet::{ROLE_INTENT, ROLE_X402, VESL_COIN_TYPE_PLACEHOLDER, VeslWallet};

use crate::signing;

// ---------------------------------------------------------------------------
// Settlement mode enum
// ---------------------------------------------------------------------------

/// Settlement mode — determines how (or whether) the hull interacts with
/// the Nockchain ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum SettlementMode {
    /// No chain interaction. Development and unit testing.
    Local,
    /// Localhost fakenet with a deterministic signing key.
    Fakenet,
    /// Live network with real keys from wallet init.
    Dumbnet,
}

impl fmt::Display for SettlementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Fakenet => write!(f, "fakenet"),
            Self::Dumbnet => write!(f, "dumbnet"),
        }
    }
}

impl std::str::FromStr for SettlementMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "fakenet" => Ok(Self::Fakenet),
            "dumbnet" => Ok(Self::Dumbnet),
            other => Err(format!("unknown settlement mode: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Settlement-related toml fields (generic, no domain-specific fields)
// ---------------------------------------------------------------------------

/// Settlement-related fields from a TOML config file.
///
/// Domain hulls embed these in their own config struct and convert via `From`.
///
/// The `[wallet]` block is the entry point for the per-role config-toggle
/// pattern: an intent app reads `[wallet.intent]`, a payment app reads
/// `[wallet.payment]`. Same code, different role.
#[derive(Debug, Default)]
pub struct SettlementToml {
    pub settlement_mode: Option<String>,
    pub chain_endpoint: Option<String>,
    pub tx_fee: Option<u64>,
    pub coinbase_timelock_min: Option<u64>,
    pub accept_timeout_secs: Option<u64>,
    pub wallet: Option<WalletToml>,
}

/// `[wallet]` TOML block — BIP-39 + BIP-44 derivation parameters consumed
/// by `vesl-wallet`.
///
/// Example:
/// ```toml
/// [wallet]
/// seed_phrase = "..."
/// coin_type = 0x7E51C0DE     # optional — defaults to VESL_COIN_TYPE_PLACEHOLDER
/// account = 0
///
/// [wallet.intent]
/// role = 0                    # optional — defaults to ROLE_INTENT
/// index = 0
///
/// [wallet.payment]
/// role = 4                    # optional — defaults to ROLE_X402
/// index = 0
/// ```
#[derive(Debug, Default, Clone)]
pub struct WalletToml {
    pub seed_phrase: Option<String>,
    pub coin_type: Option<u32>,
    pub account: Option<u32>,
    pub intent: Option<WalletRoleToml>,
    pub payment: Option<WalletRoleToml>,
}

/// `[wallet.intent]` / `[wallet.payment]` TOML sub-block. Either field
/// may be omitted; absent fields fall through to the defaults
/// (`ROLE_INTENT` / `ROLE_X402` for `role`, `0` for `index`).
#[derive(Debug, Default, Clone, Copy)]
pub struct WalletRoleToml {
    pub role: Option<u32>,
    pub index: Option<u32>,
}

// ---------------------------------------------------------------------------
// CLI override surface
// ---------------------------------------------------------------------------

/// CLI-supplied overrides for settlement resolution.
///
/// Grouped so adding a new CLI flag isn't a breaking change at every callsite
/// (audit MAINTENANCE_AUDIT_LOG.md §3.1, deferred from commit 9c446dd).
/// Resolution order: CLI > env > toml > mode defaults.
///
/// CLI-side wallet overrides are intentionally minimal: `account` (the
/// per-agent account index) is the one knob commonly worth a flag.
/// Per-role index/role overrides live in TOML only — flipping them on
/// the command line would silently re-derive a different key, the
/// footgun the `[wallet]` config-toggle pattern exists to avoid.
#[derive(Debug, Default)]
pub struct SettlementCliOverrides {
    pub mode: Option<SettlementMode>,
    pub chain_endpoint: Option<String>,
    pub submit: bool,
    pub tx_fee: Option<u64>,
    pub coinbase_timelock_min: Option<u64>,
    pub accept_timeout: Option<u64>,
    pub seed_phrase: Option<String>,
    /// Override `[wallet] account = N` from the command line.
    pub account: Option<u32>,
}

// ---------------------------------------------------------------------------
// Resolved wallet configuration (all defaults applied)
// ---------------------------------------------------------------------------

/// Fully-resolved wallet configuration: every field has a concrete
/// value, defaults applied. Held inside [`SettlementConfig::wallet`].
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// BIP-39 mnemonic. None when no phrase was supplied (the resolved
    /// config is then "wallet shape, no seed" — useful for tests).
    pub seed_phrase: Option<String>,
    pub coin_type: u32,
    pub account: u32,
    pub intent: WalletRoleConfig,
    pub payment: WalletRoleConfig,
}

/// Resolved per-role derivation parameters.
#[derive(Debug, Clone, Copy)]
pub struct WalletRoleConfig {
    pub role: u32,
    pub index: u32,
}

impl WalletConfig {
    /// Defaults: intent → ROLE_INTENT/0, payment → ROLE_X402/0,
    /// coin_type → VESL_COIN_TYPE_PLACEHOLDER, account → 0, no
    /// seed phrase.
    pub fn default_shape() -> Self {
        Self {
            seed_phrase: None,
            coin_type: VESL_COIN_TYPE_PLACEHOLDER,
            account: 0,
            intent: WalletRoleConfig {
                role: ROLE_INTENT,
                index: 0,
            },
            payment: WalletRoleConfig {
                role: ROLE_X402,
                index: 0,
            },
        }
    }

    /// Build a `VeslWallet` from this config. Returns `Ok(None)` when
    /// no seed phrase is configured.
    pub fn build_wallet(&self) -> Result<Option<VeslWallet>, signing::SigningError> {
        match self.seed_phrase.as_ref() {
            None => Ok(None),
            Some(phrase) => {
                let wallet = VeslWallet::from_seed_phrase(phrase, "", self.coin_type)?;
                Ok(Some(wallet))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime settlement config (resolved from all sources)
// ---------------------------------------------------------------------------

/// Fully-resolved settlement configuration used at runtime.
#[derive(Clone)]
pub struct SettlementConfig {
    pub mode: SettlementMode,
    /// gRPC endpoint (e.g. "http://localhost:9090"). None for local mode.
    pub chain_endpoint: Option<String>,
    /// Signing key. None for local mode (and dumbnet until a wallet
    /// seed phrase is supplied).
    pub signing_key: Option<[Belt; 8]>,
    pub coinbase_timelock_min: u64,
    pub tx_fee: u64,
    /// Whether to auto-submit settlement transactions on-chain.
    pub auto_submit: bool,
    /// How long to wait for TX acceptance before giving up (seconds).
    /// Fakenet: 300s, dumbnet: 900s (blocks are ~10min). Local mode uses
    /// u64::MAX as a sentinel: it never submits on-chain (can_submit() is
    /// false), so this is never consumed as a real timeout (audit M-31).
    pub accept_timeout_secs: u64,
    /// Resolved wallet configuration. None when neither CLI nor TOML
    /// supplied a `[wallet]` block.
    pub wallet: Option<WalletConfig>,
}

impl SettlementConfig {
    /// Local mode — zero config, zero chain.
    pub fn local() -> Self {
        Self {
            mode: SettlementMode::Local,
            chain_endpoint: None,
            signing_key: None,
            coinbase_timelock_min: 1,
            tx_fee: 256,
            auto_submit: false,
            accept_timeout_secs: u64::MAX,
            wallet: None,
        }
    }

    /// Resolve config from CLI args, toml, and mode defaults.
    ///
    /// Resolution order: CLI > env > toml > mode defaults.
    /// Backward compat: `--chain-endpoint` without `--settlement-mode` infers fakenet.
    ///
    /// `default_signing_key`: the signing key for fakenet mode. Typically
    /// the demo key, but callers can provide any key.
    ///
    /// AUDIT 2026-04-19 L-14: returns `Result` instead of `.expect`-ing
    /// on misconfiguration, so main.rs can print an operator-actionable
    /// error and exit cleanly rather than a Rust panic trace.
    pub fn resolve_checked(
        overrides: &SettlementCliOverrides,
        toml: &SettlementToml,
        default_signing_key: Option<[Belt; 8]>,
    ) -> Result<Self, String> {
        // 1. Determine mode: CLI > toml > infer from flags > local
        let mode = overrides
            .mode
            .or_else(|| toml.settlement_mode.as_deref().and_then(|s| s.parse().ok()))
            .unwrap_or_else(|| {
                // Backward compat: --chain-endpoint or --submit without mode -> fakenet
                if overrides.chain_endpoint.is_some() || overrides.submit {
                    SettlementMode::Fakenet
                } else {
                    SettlementMode::Local
                }
            });

        // 2. Resolve seed phrase: CLI > env > toml.wallet.seed_phrase
        let seed_phrase = overrides
            .seed_phrase
            .clone()
            .or_else(|| std::env::var("VESL_SEED_PHRASE").ok())
            .or_else(|| toml.wallet.as_ref().and_then(|w| w.seed_phrase.clone()));

        // 3. Resolve wallet shape if either side touched it.
        let wallet_cfg = resolve_wallet(toml.wallet.as_ref(), overrides.account, seed_phrase);

        match mode {
            SettlementMode::Local => Ok(Self::resolve_local(wallet_cfg)),
            SettlementMode::Fakenet => Ok(Self::resolve_fakenet(
                overrides, toml, default_signing_key, wallet_cfg,
            )),
            SettlementMode::Dumbnet => Self::resolve_dumbnet(overrides, toml, wallet_cfg),
        }
    }

    /// Local mode — zero chain, zero signing key, mode defaults only.
    fn resolve_local(wallet_cfg: Option<WalletConfig>) -> Self {
        Self {
            mode: SettlementMode::Local,
            chain_endpoint: None,
            signing_key: None,
            coinbase_timelock_min: 1,
            tx_fee: 256,
            auto_submit: false,
            accept_timeout_secs: u64::MAX,
            wallet: wallet_cfg,
        }
    }

    /// Fakenet mode — endpoint falls back to localhost, signing key is
    /// the caller-supplied deterministic key. Infallible: every field
    /// has a default.
    fn resolve_fakenet(
        overrides: &SettlementCliOverrides,
        toml: &SettlementToml,
        default_signing_key: Option<[Belt; 8]>,
        wallet_cfg: Option<WalletConfig>,
    ) -> Self {
        Self {
            mode: SettlementMode::Fakenet,
            chain_endpoint: Some(
                overrides
                    .chain_endpoint
                    .clone()
                    .or_else(|| toml.chain_endpoint.clone())
                    .unwrap_or_else(|| "http://localhost:9090".into()),
            ),
            signing_key: default_signing_key,
            coinbase_timelock_min: overrides
                .coinbase_timelock_min
                .or(toml.coinbase_timelock_min)
                .unwrap_or(1),
            tx_fee: overrides.tx_fee.or(toml.tx_fee).unwrap_or(256),
            auto_submit: true,
            accept_timeout_secs: overrides
                .accept_timeout
                .or(toml.accept_timeout_secs)
                .unwrap_or(300),
            wallet: wallet_cfg,
        }
    }

    /// Dumbnet mode — the one fallible resolver: a chain endpoint is
    /// required (no localhost default), and signing-key derivation can
    /// fail on a bad seed phrase.
    fn resolve_dumbnet(
        overrides: &SettlementCliOverrides,
        toml: &SettlementToml,
        wallet_cfg: Option<WalletConfig>,
    ) -> Result<Self, String> {
        let endpoint = overrides
            .chain_endpoint
            .clone()
            .or_else(|| toml.chain_endpoint.clone())
            .ok_or_else(|| {
                "dumbnet mode requires --chain-endpoint or \
                 chain_endpoint in config"
                    .to_string()
            })?;

        // Derive the legacy [Belt; 8] signing_key at the resolved
        // wallet's intent role/index. New consumers should use the
        // `intent_signer_belts` / `payment_signer_belts` helpers below
        // instead.
        let sk = match wallet_cfg.as_ref() {
            Some(w) => wallet_role_belts(w, w.intent.role, w.intent.index)
                .map_err(|e| format!("intent derivation failed: {e}"))?,
            None => None,
        };

        Ok(Self {
            mode: SettlementMode::Dumbnet,
            chain_endpoint: Some(endpoint),
            signing_key: sk,
            coinbase_timelock_min: overrides
                .coinbase_timelock_min
                .or(toml.coinbase_timelock_min)
                .unwrap_or(1),
            tx_fee: overrides.tx_fee.or(toml.tx_fee).unwrap_or(256),
            auto_submit: true,
            accept_timeout_secs: overrides
                .accept_timeout
                .or(toml.accept_timeout_secs)
                .unwrap_or(900),
            wallet: wallet_cfg,
        })
    }

    /// True if this config has everything needed for on-chain submission.
    pub fn can_submit(&self) -> bool {
        self.auto_submit && self.chain_endpoint.is_some() && self.signing_key.is_some()
    }

    /// Build a `ChainConfig` using this settlement config's endpoint and timeout.
    /// Returns `None` for local mode (no endpoint).
    pub fn chain_config(&self) -> Option<nockchain_client_rs::ChainConfig> {
        self.chain_endpoint
            .as_ref()
            .map(|ep| nockchain_client_rs::ChainConfig {
                endpoint: ep.clone(),
                poll_interval: std::time::Duration::from_secs(5),
                accept_timeout: std::time::Duration::from_secs(self.accept_timeout_secs),
            })
    }

    /// Return the per-role intent signer as a legacy `[Belt; 8]`. The
    /// TOML config-toggle pattern: an intent app calls this. Returns
    /// `Err(SigningError::NoSeedPhrase)` when no wallet seed phrase is
    /// configured — callers that treat that as "not an error" can
    /// `.ok()`-discard.
    pub fn intent_signer_belts(&self) -> Result<[Belt; 8], signing::SigningError> {
        self.derive_role_belts(|w| (w.intent.role, w.intent.index))
    }

    /// Return the per-role payment signer as a legacy `[Belt; 8]`. The
    /// TOML config-toggle pattern: a payment app calls this. Returns
    /// `Err(SigningError::NoSeedPhrase)` when no wallet seed phrase is
    /// configured — callers that treat that as "not an error" can
    /// `.ok()`-discard.
    pub fn payment_signer_belts(&self) -> Result<[Belt; 8], signing::SigningError> {
        self.derive_role_belts(|w| (w.payment.role, w.payment.index))
    }

    fn derive_role_belts<F>(&self, pick: F) -> Result<[Belt; 8], signing::SigningError>
    where
        F: FnOnce(&WalletConfig) -> (u32, u32),
    {
        let wallet_cfg = self
            .wallet
            .as_ref()
            .ok_or(signing::SigningError::NoSeedPhrase)?;
        let (role, index) = pick(wallet_cfg);
        wallet_role_belts(wallet_cfg, role, index)?.ok_or(signing::SigningError::NoSeedPhrase)
    }
}

/// Derive the legacy `[Belt; 8]` signing key at a given role/index from
/// a resolved [`WalletConfig`]. Returns `Ok(None)` when no seed phrase
/// is configured (resolve-time happy path); `Err` only on a genuine
/// derivation failure. Shared by `resolve_dumbnet` (pre-construction)
/// and `derive_role_belts` (post-construction). Single canonical
/// derivation site so the two paths can't diverge.
fn wallet_role_belts(
    cfg: &WalletConfig,
    role: u32,
    index: u32,
) -> Result<Option<[Belt; 8]>, signing::SigningError> {
    let wallet = match cfg.build_wallet()? {
        None => return Ok(None),
        Some(w) => w,
    };
    let path = vesl_wallet::DerivationPath::new(cfg.coin_type, cfg.account, role, index);
    let derived = wallet.derive(path).map_err(signing::SigningError::from)?;
    Ok(Some(intent_key_to_belts8(&derived.private_key)))
}

impl fmt::Display for SettlementConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mode={}", self.mode)?;
        if let Some(ref ep) = self.chain_endpoint {
            write!(f, " endpoint={ep}")?;
        }
        if self.signing_key.is_some() {
            write!(f, " key=present")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a vesl-signing `SchnorrPrivateKey` to nockchain-math `[Belt; 8]`.
/// Mirrors `signing::vesl_belts8_to_nock` but stays here to avoid widening
/// that module's pub(crate) surface.
fn intent_key_to_belts8(key: &vesl_signing::schnorr::SchnorrPrivateKey) -> [Belt; 8] {
    let vesl_belts = key.to_belts();
    std::array::from_fn(|i| Belt(vesl_belts[i].0))
}

/// Resolve the wallet shape: applies CLI account override, TOML
/// account/role/index, and the placeholder defaults. Returns
/// `Some(WalletConfig)` whenever any wallet-related signal is present
/// (TOML block, CLI account, or a seed phrase resolved from any
/// source). Returns `None` only when nothing requested a wallet.
fn resolve_wallet(
    toml: Option<&WalletToml>,
    cli_account: Option<u32>,
    seed_phrase: Option<String>,
) -> Option<WalletConfig> {
    if toml.is_none() && cli_account.is_none() && seed_phrase.is_none() {
        return None;
    }
    let mut cfg = WalletConfig::default_shape();
    if let Some(t) = toml {
        if let Some(c) = t.coin_type {
            cfg.coin_type = c;
        }
        if let Some(a) = t.account {
            cfg.account = a;
        }
        if let Some(intent) = t.intent {
            if let Some(r) = intent.role {
                cfg.intent.role = r;
            }
            if let Some(i) = intent.index {
                cfg.intent.index = i;
            }
        }
        if let Some(payment) = t.payment {
            if let Some(r) = payment.role {
                cfg.payment.role = r;
            }
            if let Some(i) = payment.index {
                cfg.payment.index = i;
            }
        }
    }
    // CLI account wins over TOML account.
    if let Some(a) = cli_account {
        cfg.account = a;
    }
    cfg.seed_phrase = seed_phrase;
    Some(cfg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical BIP-39 12-word test vector ("abandon×11 + about").
    const CANONICAL_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    #[test]
    fn default_is_local() {
        let toml = SettlementToml::default();
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Local);
        assert!(cfg.chain_endpoint.is_none());
        assert!(cfg.signing_key.is_none());
        assert!(!cfg.auto_submit);
    }

    #[test]
    fn chain_endpoint_infers_fakenet() {
        let toml = SettlementToml::default();
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                chain_endpoint: Some("http://localhost:9090".into()),
                ..Default::default()
            },
            &toml,
            Some([Belt(1); 8]),
        )
        .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Fakenet);
        assert!(cfg.signing_key.is_some());
        assert!(cfg.auto_submit);
    }

    #[test]
    fn submit_flag_infers_fakenet() {
        let toml = SettlementToml::default();
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                submit: true,
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Fakenet);
    }

    #[test]
    fn explicit_local_ignores_chain_endpoint() {
        let toml = SettlementToml::default();
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Local),
                chain_endpoint: Some("http://localhost:9090".into()),
                submit: true,
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Local);
        assert!(cfg.chain_endpoint.is_none());
        assert!(!cfg.auto_submit);
    }

    #[test]
    fn fakenet_defaults() {
        let toml = SettlementToml::default();
        let demo_key = [Belt(42); 8];
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Fakenet),
                ..Default::default()
            },
            &toml,
            Some(demo_key),
        )
        .unwrap();
        assert_eq!(cfg.chain_endpoint.as_deref(), Some("http://localhost:9090"));
        assert_eq!(cfg.tx_fee, 256);
        assert_eq!(cfg.coinbase_timelock_min, 1);
        assert_eq!(cfg.accept_timeout_secs, 300);
        assert!(cfg.signing_key.is_some());
    }

    #[test]
    fn toml_overrides_defaults() {
        let toml = SettlementToml {
            tx_fee: Some(5000),
            coinbase_timelock_min: Some(10),
            chain_endpoint: Some("http://custom:9090".into()),
            ..Default::default()
        };
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Fakenet),
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        assert_eq!(cfg.tx_fee, 5000);
        assert_eq!(cfg.coinbase_timelock_min, 10);
        assert_eq!(cfg.chain_endpoint.as_deref(), Some("http://custom:9090"));
    }

    #[test]
    fn cli_overrides_toml() {
        let toml = SettlementToml {
            tx_fee: Some(5000),
            ..Default::default()
        };
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Fakenet),
                chain_endpoint: Some("http://cli:9090".into()),
                tx_fee: Some(7000),
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        assert_eq!(cfg.tx_fee, 7000);
        assert_eq!(cfg.chain_endpoint.as_deref(), Some("http://cli:9090"));
    }

    #[test]
    fn toml_settlement_mode_parsed() {
        let toml = SettlementToml {
            settlement_mode: Some("fakenet".into()),
            ..Default::default()
        };
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Fakenet);
    }

    #[test]
    fn dumbnet_with_seed_phrase() {
        let toml = SettlementToml {
            chain_endpoint: Some("http://node:9090".into()),
            ..Default::default()
        };
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Dumbnet),
                seed_phrase: Some(CANONICAL_MNEMONIC.into()),
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        assert_eq!(cfg.mode, SettlementMode::Dumbnet);
        assert!(cfg.signing_key.is_some());
        assert!(cfg.auto_submit);
        assert_eq!(cfg.accept_timeout_secs, 900);
        // The seed phrase plumbed through into `wallet`.
        assert!(cfg.wallet.is_some());
        assert_eq!(
            cfg.wallet.as_ref().unwrap().seed_phrase.as_deref(),
            Some(CANONICAL_MNEMONIC)
        );
    }

    #[test]
    fn can_submit_checks() {
        let local = SettlementConfig::local();
        assert!(!local.can_submit());

        let toml = SettlementToml::default();
        let fakenet = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                mode: Some(SettlementMode::Fakenet),
                ..Default::default()
            },
            &toml,
            Some([Belt(1); 8]),
        )
        .unwrap();
        assert!(fakenet.can_submit());
    }

    #[test]
    fn settlement_mode_display_roundtrip() {
        for mode in [SettlementMode::Local, SettlementMode::Fakenet, SettlementMode::Dumbnet] {
            let s = mode.to_string();
            let parsed: SettlementMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // Nested [wallet] / [wallet.intent] / [wallet.payment] resolution.
    //
    // Replaces the earlier flat `account`/`role` round-trip tests; the
    // shape they were a forward-compat seam for now lives in the nested
    // WalletToml structure.
    // -----------------------------------------------------------------------

    #[test]
    fn wallet_nested_round_trip_through_toml() {
        let toml = SettlementToml {
            wallet: Some(WalletToml {
                seed_phrase: Some(CANONICAL_MNEMONIC.into()),
                coin_type: Some(0xABCD_1234),
                account: Some(7),
                intent: Some(WalletRoleToml {
                    role: Some(2),
                    index: Some(11),
                }),
                payment: Some(WalletRoleToml {
                    role: Some(4),
                    index: Some(99),
                }),
            }),
            ..Default::default()
        };
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        let w = cfg.wallet.expect("wallet config should resolve");
        assert_eq!(w.coin_type, 0xABCD_1234);
        assert_eq!(w.account, 7);
        assert_eq!(w.intent.role, 2);
        assert_eq!(w.intent.index, 11);
        assert_eq!(w.payment.role, 4);
        assert_eq!(w.payment.index, 99);
        assert_eq!(w.seed_phrase.as_deref(), Some(CANONICAL_MNEMONIC));
    }

    #[test]
    fn wallet_cli_account_overrides_toml() {
        let toml = SettlementToml {
            wallet: Some(WalletToml {
                account: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg = SettlementConfig::resolve_checked(
            &SettlementCliOverrides {
                account: Some(99),
                ..Default::default()
            },
            &toml,
            None,
        )
        .unwrap();
        let w = cfg.wallet.expect("wallet config should resolve");
        assert_eq!(w.account, 99);
    }

    #[test]
    fn wallet_defaults_apply_when_omitted() {
        let toml = SettlementToml {
            wallet: Some(WalletToml {
                // No fields set — every default applies.
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        let w = cfg.wallet.expect("wallet config should resolve");
        assert_eq!(w.coin_type, VESL_COIN_TYPE_PLACEHOLDER);
        assert_eq!(w.account, 0);
        assert_eq!(w.intent.role, ROLE_INTENT);
        assert_eq!(w.intent.index, 0);
        assert_eq!(w.payment.role, ROLE_X402);
        assert_eq!(w.payment.index, 0);
        assert!(w.seed_phrase.is_none());
    }

    #[test]
    fn wallet_omitted_yields_no_resolved_wallet() {
        let toml = SettlementToml::default();
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        assert!(cfg.wallet.is_none());
    }

    #[test]
    fn intent_and_payment_signers_resolve_distinct_keys() {
        // The TOML config-toggle pattern: same SettlementConfig, intent
        // and payment signers derive different scalars.
        let toml = SettlementToml {
            wallet: Some(WalletToml {
                seed_phrase: Some(CANONICAL_MNEMONIC.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cfg =
            SettlementConfig::resolve_checked(&SettlementCliOverrides::default(), &toml, None)
                .unwrap();
        let intent = cfg.intent_signer_belts().expect("intent key");
        let payment = cfg.payment_signer_belts().expect("payment key");
        assert_ne!(intent, payment);
    }
}
