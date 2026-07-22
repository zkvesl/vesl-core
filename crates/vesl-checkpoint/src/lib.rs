//! Snapshot / resume wrapper for live NockApps.
//!
//! Closes the RM1 HARD-BUG-1 gap: without a checkpoint API, "does state
//! from earlier profiles survive through composition changes?" — the
//! defining test of the meta-mode dogfood round — is unreachable.
//!
//! Two-call API:
//!
//! ```ignore
//! let snap = vesl_checkpoint::snapshot(&app, snapshot_dir, &app_hoon).await?;
//! drop(app);
//! let resumed = vesl_checkpoint::resume(&jam_path, &snap, "name").await?;
//! ```
//!
//! `snapshot()` writes a `state.jam` (in
//! [`nockapp::nockapp::export::ExportedState`] format) plus a
//! `meta.toml` with the source app.hoon SHA-256, timestamp, and
//! nockapp crate version. `resume()` parses the meta, sets
//! [`nockapp::kernel::boot::Cli::state_jam`] to the snapshot's
//! `state.jam`, and calls [`nockapp::kernel::boot::setup`] — reusing
//! nockapp's existing import path, no companion upstream patch.
//!
//! The schema-migration helper (declarative state-shape diff or
//! per-transition migrators) is intentionally out of scope; wait for
//! cumulative-domain pressure to surface what shape it should take.
//!
//! Reference consumer: the meta-mode dogfood driver documented in
//! `vesl-core/.dev/DOGFOOD_META.md` "Per-transition procedure" Step 5
//! ("State-shape compatibility check") — see that doc for the
//! `snapshot-state` / `restore-state-and-exercise` driver wiring.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow};
use nockapp::NockApp;
use nockapp::kernel::boot;
use nockapp::nockapp::export::ExportedState;
use nockapp::noun::slab::NockJammer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bundle returned by [`snapshot`] and consumed by [`resume`].
///
/// `dir` holds the snapshot artifacts (`state.jam` plus `meta.toml`).
/// Callers can persist `Snapshot` directly via `serde` for a typed
/// handle, or just hold `dir` and reconstruct via [`Snapshot::load`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Directory holding the snapshot files.
    pub dir: PathBuf,
    /// Hex-encoded SHA-256 of the app.hoon source at snapshot time.
    /// Lets resumes check whether state is loading into a kernel built
    /// from the same Hoon. Mismatches are warnings, not errors —
    /// composition changes are the whole point of snapshot/resume.
    pub source_sha256: String,
    /// Wall-clock when `snapshot` returned.
    pub timestamp: SystemTime,
    /// `CARGO_PKG_VERSION` of the `vesl-checkpoint` crate that wrote
    /// the snapshot. Lets future versions detect format-incompatible
    /// older bundles — forward-looking; no migration logic ships yet.
    pub vesl_checkpoint_version: String,
}

impl Snapshot {
    /// Read a previously written snapshot from `dir` — equivalent to
    /// holding the [`Snapshot`] from [`snapshot`] across a restart.
    pub async fn load(dir: &Path) -> Result<Self> {
        let meta_path = dir.join(META_TOML);
        let bytes = tokio::fs::read(&meta_path)
            .await
            .with_context(|| format!("read {}", meta_path.display()))?;
        let meta: MetaToml = toml::from_str(
            std::str::from_utf8(&bytes)
                .with_context(|| format!("decode {} as utf-8", meta_path.display()))?,
        )
        .with_context(|| format!("parse {}", meta_path.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            source_sha256: meta.snapshot.source_sha256,
            timestamp: parse_timestamp(&meta.snapshot.timestamp)?,
            vesl_checkpoint_version: meta.snapshot.vesl_checkpoint_version,
        })
    }

    /// Path to the bundled `state.jam`. Set this on
    /// [`nockapp::kernel::boot::Cli::state_jam`] (or pass through
    /// [`resume`]) to load the captured kernel state into a fresh boot.
    pub fn state_jam(&self) -> PathBuf {
        self.dir.join(STATE_JAM)
    }
}

/// Capture the live `app`'s kernel state into `dir`.
///
/// Creates `dir` if missing. Writes:
/// - `dir/state.jam` — bincode-encoded
///   [`nockapp::nockapp::export::ExportedState`], ready for
///   `Cli::state_jam` import on resume.
/// - `dir/meta.toml` — source SHA-256, timestamp, nockapp version.
///
/// The app is not consumed; callers can keep poking it after this
/// returns. (Contrast `boot::setup`'s `cli.export_state_jam` path,
/// which exits after writing.)
///
/// `source_app_hoon` is the file this kernel was compiled from; its
/// sha256 is recorded so a future `resume` can detect a mismatched
/// kernel build.
///
/// **Memory pressure (RM4 §6).** `snapshot()` allocates transient
/// memory proportional to the kernel's current state size on top of
/// nockvm's ~8.5 GB stack reservation. After a long poke sequence
/// (50+ events against a populated kernel), peak transient memory
/// can push a 16 GB-class machine past its OS-level OOM threshold
/// and the process is killed (SIGKILL, exit 137) before `snapshot`
/// returns. The workaround is to split long sequences across multiple
/// processes — snapshot at intermediate checkpoints and re-enter via
/// [`resume`] in a fresh process. The reuse of nockapp's existing
/// import path makes the multi-process flow equivalent to a single-
/// process snapshot for state correctness.
pub async fn snapshot(app: &NockApp, dir: &Path, source_app_hoon: &Path) -> Result<Snapshot> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("create snapshot dir {}", dir.display()))?;

    let source_sha256 = sha256_of_file(source_app_hoon)
        .await
        .with_context(|| format!("hash {}", source_app_hoon.display()))?;
    let timestamp = SystemTime::now();
    let vesl_checkpoint_version = env!("CARGO_PKG_VERSION").to_string();

    let state_jam_path = dir.join(STATE_JAM);
    let state = app
        .export()
        .await
        .map_err(|e| anyhow!("export failed: {e}"))?;
    let state_bytes = ExportedState::from_loadstate::<NockJammer>(state)
        .encode()
        .context("encode exported state")?;
    tokio::fs::write(&state_jam_path, state_bytes)
        .await
        .with_context(|| format!("write {}", state_jam_path.display()))?;

    let meta = MetaToml {
        snapshot: MetaSection {
            source_sha256: source_sha256.clone(),
            timestamp: format_timestamp(timestamp),
            vesl_checkpoint_version: vesl_checkpoint_version.clone(),
        },
    };
    let meta_str = toml::to_string_pretty(&meta).context("serialize meta.toml")?;
    let meta_path = dir.join(META_TOML);
    tokio::fs::write(&meta_path, meta_str)
        .await
        .with_context(|| format!("write {}", meta_path.display()))?;

    Ok(Snapshot {
        dir: dir.to_path_buf(),
        source_sha256,
        timestamp,
        vesl_checkpoint_version,
    })
}

/// Boot a fresh `NockApp` from `jam_path` with the snapshot's state
/// imported.
///
/// Reads the kernel jam at `jam_path` (typically the new build's
/// out.jam), constructs a boot `Cli` with `state_jam` pointing at the
/// snapshot's `state.jam`, and runs `boot::setup`. Nockapp's import
/// path picks up `state_jam` and rehydrates kernel state on top of the
/// new kernel definition.
///
/// Mismatch handling: if the new kernel's `++load` arm rejects the
/// snapshotted state shape, `boot::setup` propagates the error. Schema
/// migration is the consumer's responsibility (see crate-level docs).
///
/// **Schema-extension migration (RM4 §1, v0.2).** Same-composition
/// resume (new kernel has the same graft set as the snapshot)
/// roundtrips cleanly — pre- and post-resume pokes both emit effects.
/// **Schema-extension resume** (new kernel adds grafts absent from the
/// snapshot) works in v0.2 via graft-inject codegen at the
/// `nockup:load-defaults` marker: the marker template's `++load` arm
/// ships an identity `old-state` placeholder, and graft-inject
/// replaces it with a `=/ defaults ^*(versioned-state)` +
/// `%_ defaults <field> ^*(<field>-state) ... ==` overlay, so resumed
/// snapshots with a smaller noun shape get type defaults at the new
/// graft axes instead of panicking inside the wrapper's mule guard.
/// Pre-v0.2 (no marker, identity load) silently dropped effects on
/// every graft past the first added priority band; that mode no longer
/// ships. v0.2 resets per-graft state to type defaults on every
/// resume; operators needing data preservation re-poke after resume.
/// `resume` accepts that reset silently — for a loud failure instead,
/// use [`resume_with_data_dir`] with `strict_state_change = true`
/// (AUDIT 2026-05-20 M-26).
pub async fn resume(jam_path: &Path, snapshot: &Snapshot, name: &str) -> Result<NockApp> {
    resume_with_data_dir(jam_path, snapshot, name, None, None, false).await
}

/// Resume with an explicit `data_dir` for the rebooted app.
///
/// Post-PMA, `boot::setup` requires `--state-jam` to be paired with `--new`
/// and refuses `--new` against a non-empty data directory. Callers (especially
/// tests) need a way to point the resumed kernel at a fresh dir so successive
/// runs don't collide. Pass `None` to keep the default-data-dir behavior; pass
/// `Some(path)` to force a clean target.
///
/// `source_app_hoon`: pass `Some(path)` to the new kernel's Hoon source to
/// verify it hashes to the snapshot's recorded SHA-256. A mismatch is logged
/// as a warning — composition changes are expected — and `None` skips the
/// check entirely (AUDIT 2026-05-19 H-20).
///
/// `strict_state_change`: when `true`, a `source_app_hoon` mismatch is a
/// hard error instead of a warning (AUDIT 2026-05-20 M-26). A kernel
/// rebuilt since the snapshot resets per-graft state to type defaults on
/// resume; strict mode turns that silent data loss into a loud failure an
/// operator must consciously override. Requires `source_app_hoon` — with
/// nothing to hash against the snapshot, the call errors. A CLI driving
/// resume surfaces this as `--strict-state-change`.
pub async fn resume_with_data_dir(
    jam_path: &Path,
    snapshot: &Snapshot,
    name: &str,
    data_dir: Option<PathBuf>,
    source_app_hoon: Option<&Path>,
    strict_state_change: bool,
) -> Result<NockApp> {
    let kernel_bytes = tokio::fs::read(jam_path)
        .await
        .with_context(|| format!("read kernel jam at {}", jam_path.display()))?;

    // AUDIT 2026-05-19 H-20 / 2026-05-20 M-26: if the caller supplies the
    // new kernel's source, hash it against the snapshot's recorded
    // SHA-256. A mismatch means the kernel was recompiled since the
    // snapshot, so the resume resets per-graft state to type defaults
    // (see `resume`). Lenient mode warns and proceeds; strict mode
    // refuses, so an operator who did not expect a schema change gets a
    // loud failure instead of silent data loss.
    if strict_state_change && source_app_hoon.is_none() {
        return Err(anyhow!(
            "strict-state-change resume needs the new kernel's Hoon \
             source to compare against the snapshot — pass it as \
             `source_app_hoon`"
        ));
    }
    if let Some(src) = source_app_hoon {
        let current = sha256_of_file(src)
            .await
            .with_context(|| format!("hash {}", src.display()))?;
        if current != snapshot.source_sha256 {
            if strict_state_change {
                return Err(anyhow!(
                    "strict-state-change resume refused: kernel source \
                     SHA-256 {current} differs from snapshot {} — the \
                     kernel was rebuilt, so resuming would reset per-graft \
                     state to type defaults. Resume without strict mode to \
                     proceed anyway.",
                    snapshot.source_sha256
                ));
            }
            eprintln!(
                "  warn: resume kernel source SHA-256 {current} differs \
                 from snapshot {} — resuming across a composition change",
                snapshot.source_sha256
            );
        }
    }

    let mut cli = boot::default_boot_cli(false);
    cli.state_jam = Some(
        snapshot
            .state_jam()
            .to_str()
            .context("snapshot state.jam path is not utf-8")?
            .to_string(),
    );
    // Post-PMA, boot::setup rejects --state-jam without --new (see
    // nockapp::kernel::boot:2241). Resume loads state.jam into a fresh
    // kernel — set both flags together.
    cli.new = true;
    if let Some(dir) = data_dir {
        cli.data_dir = Some(dir);
    }

    boot::setup(&kernel_bytes, cli, &[], name, None)
        .await
        .map_err(|e| anyhow!("boot::setup failed during resume: {e}"))
}

const STATE_JAM: &str = "state.jam";
const META_TOML: &str = "meta.toml";

#[derive(Debug, Serialize, Deserialize)]
struct MetaToml {
    snapshot: MetaSection,
}

#[derive(Debug, Serialize, Deserialize)]
struct MetaSection {
    source_sha256: String,
    timestamp: String,
    vesl_checkpoint_version: String,
}

async fn sha256_of_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

fn format_timestamp(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@unix:{secs}")
}

fn parse_timestamp(s: &str) -> Result<SystemTime> {
    let secs: u64 = s
        .strip_prefix("@unix:")
        .context("meta.toml timestamp missing @unix: prefix")?
        .parse()
        .context("meta.toml timestamp seconds did not parse")?;
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trips() {
        let now = SystemTime::now();
        let s = format_timestamp(now);
        assert!(s.starts_with("@unix:"));
        let back = parse_timestamp(&s).unwrap();
        // Whole-second precision only — drop sub-second fragment.
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let back_secs = back
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(now_secs, back_secs);
    }

    #[test]
    fn meta_toml_round_trips() {
        let meta = MetaToml {
            snapshot: MetaSection {
                source_sha256: "abc123".into(),
                timestamp: "@unix:1700000000".into(),
                vesl_checkpoint_version: "0.1.0".into(),
            },
        };
        let s = toml::to_string_pretty(&meta).unwrap();
        let back: MetaToml = toml::from_str(&s).unwrap();
        assert_eq!(back.snapshot.source_sha256, meta.snapshot.source_sha256);
        assert_eq!(back.snapshot.timestamp, meta.snapshot.timestamp);
        assert_eq!(
            back.snapshot.vesl_checkpoint_version,
            meta.snapshot.vesl_checkpoint_version
        );
    }

    #[tokio::test]
    async fn sha256_matches_known_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        tokio::fs::write(&path, b"hello").await.unwrap();
        let hash = sha256_of_file(&path).await.unwrap();
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
