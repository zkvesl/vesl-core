//! Graft poke builders.
//!
//! One module per primitive (settle / mint / guard / forge). Each exposes
//! `build_<primitive>_<verb>_poke(...)` free functions returning a
//! `NounSlab` ready to hand to a kernel `poke`.
//!
//! Every commitment-bearing graft keys its trellis on `hull=@`, so
//! signatures are uniform: `(hull, ...verb-specific...) -> NounSlab`.
//! See `docs/graft-manifest.md` for the full convention.

pub mod batch;
pub mod clock;
pub mod counter;
pub mod forge;
pub mod guard;
pub mod kv;
pub mod log;
pub mod mint;
pub mod queue;
pub mod rbac;
pub mod registry;
pub mod settle;
pub mod validate;
