use std::path::PathBuf;
use std::{env, fs};

use sha2::{Digest, Sha256};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir.ancestors().nth(2).expect("project root");
    let jam_path = project_root.join("assets/guard.jam");

    println!("cargo:rerun-if-env-changed=KERNEL_JAM_PATH");
    println!("cargo:rerun-if-changed={}", jam_path.display());

    if env::var_os("KERNEL_JAM_PATH").is_none() {
        println!("cargo:rustc-env=KERNEL_JAM_PATH={}", jam_path.display());
    }

    // AUDIT 2026-04-17 M-07: embed kernel sha256 at build time.
    let effective_jam_path = env::var("KERNEL_JAM_PATH")
        .map(PathBuf::from)
        .unwrap_or(jam_path);
    let jam_bytes = fs::read(&effective_jam_path).unwrap_or_else(|e| {
        panic!(
            "kernels-guard build: read {}: {e}",
            effective_jam_path.display()
        )
    });
    let digest = Sha256::digest(&jam_bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=KERNEL_JAM_SHA256={hex}");
}
