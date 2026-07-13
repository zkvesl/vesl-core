//! End-to-end snapshot/resume round-trip.
//!
//! Boots a minimal kernel from `templates/counter/out.jam`, snapshots
//! it, drops the app, and resumes from the snapshot. Asserts resume
//! completes without error — i.e., the state.jam written by
//! `snapshot()` is loadable through `Cli::state_jam`.
//!
//! State-equivalence assertions (peek the same value pre/post resume)
//! live in vesl-nockup-side tests, where the `compose_and_compile`
//! machinery and graft-aware peek helpers ship. This upstream test is
//! structural: it proves the bytes survive a round-trip and the API
//! contract holds.

use std::path::PathBuf;

use anyhow::Result;
use tempfile::TempDir;
use vesl_checkpoint::{Snapshot, resume_with_data_dir, snapshot};

fn fixture_kernel() -> PathBuf {
    // CARGO_MANIFEST_DIR = vesl-core/crates/vesl-checkpoint
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/counter/out.jam")
        .canonicalize()
        .expect(
            "fixture kernel templates/counter/out.jam must exist; \
             rebuild the templates if it's missing",
        )
}

fn fixture_app_hoon() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../templates/counter/hoon/app/app.hoon")
        .canonicalize()
        .expect("fixture app.hoon must exist alongside out.jam")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_then_resume_round_trip() -> Result<()> {
    let kernel_path = fixture_kernel();
    let app_hoon = fixture_app_hoon();
    let snapshot_dir: TempDir = tempfile::tempdir()?;
    // Post-PMA, boot::setup persists checkpoints under data_dir (default
    // ~/.local/share/<name>/). Without an explicit override, repeated test
    // runs reuse stale state from prior runs and panic on noun-frame mismatch.
    // Pin data_dir to a fresh TempDir per run.
    let data_dir: TempDir = tempfile::tempdir()?;

    // Boot the fixture kernel.
    let kernel_bytes = tokio::fs::read(&kernel_path).await?;
    let mut cli = nockapp::kernel::boot::default_boot_cli(false);
    cli.data_dir = Some(data_dir.path().to_path_buf());
    let app = nockapp::kernel::boot::setup(&kernel_bytes, cli, &[], "vesl-checkpoint-test", None)
        .await
        .map_err(|e| anyhow::anyhow!("initial boot failed: {e}"))?;

    // Snapshot.
    let snap = snapshot(&app, snapshot_dir.path(), &app_hoon).await?;

    // Snapshot artifacts on disk.
    assert!(snap.state_jam().exists(), "state.jam must be written");
    assert!(
        snapshot_dir.path().join("meta.toml").exists(),
        "meta.toml must be written"
    );
    assert!(
        !snap.source_sha256.is_empty(),
        "source_sha256 must be populated"
    );

    // Re-load the meta from disk via Snapshot::load — round-trip.
    let reloaded = Snapshot::load(snapshot_dir.path()).await?;
    assert_eq!(reloaded.source_sha256, snap.source_sha256);
    assert_eq!(
        reloaded.vesl_checkpoint_version,
        snap.vesl_checkpoint_version
    );

    // Drop the live app before resuming so the resume doesn't race
    // with the snapshotted app's auto-save.
    drop(app);

    // Resume — boot::setup's import path should pick up
    // snapshot.state_jam() through cli.state_jam.
    let resume_dir: TempDir = tempfile::tempdir()?;
    let _resumed = resume_with_data_dir(
        &kernel_path,
        &snap,
        "vesl-checkpoint-test-resumed",
        Some(resume_dir.path().to_path_buf()),
        Some(&app_hoon),
        false,
    )
    .await?;
    // Resume returning Ok is the contract this test asserts; state
    // contents are the vesl-nockup-side test's job.

    // AUDIT 2026-05-20 M-26: strict mode refuses a resume whose kernel
    // source no longer matches the snapshot — a schema change would
    // otherwise silently reset per-graft state. `source_app_hoon` here
    // points at a file whose sha differs from the snapshot's source.
    let stale_source = resume_dir.path().join("stale-source.hoon");
    tokio::fs::write(&stale_source, b"not the snapshot's kernel source").await?;
    let strict = resume_with_data_dir(
        &kernel_path,
        &snap,
        "vesl-checkpoint-test-strict",
        None,
        Some(&stale_source),
        true,
    )
    .await;
    assert!(
        strict.is_err(),
        "strict-state-change resume must refuse a kernel-source mismatch",
    );

    Ok(())
}
