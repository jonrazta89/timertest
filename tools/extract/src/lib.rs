//! CVE-2026-98260 build extractor.
//!
//! Kernel-side parsers (`boot`, `kallsyms`, `kallsyms_finder`, `btf`, `disasm`)
//! are vendored from `ghostlock-app/tools/extract_rs` (Apache-2.0); `derive`,
//! `kbuilds` and `report` hold the 98260-specific logic.

pub mod boot;
pub mod btf;
pub mod derive;
pub mod disasm;
pub mod error;
pub mod kbuilds;
pub mod kallsyms;
pub mod kallsyms_finder;
pub mod report;
