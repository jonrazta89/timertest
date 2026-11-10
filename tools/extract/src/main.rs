//! `timer-extract`: check whether a kernel still carries CVE-2026-98260 and
//! register its per-build constants in `timer/kbuilds.h`.
//!
//! Exit codes: 0 vulnerable, 3 kernel carries the upstream fix, 1 error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use timer_extract::derive::{derive, Verdict};
use timer_extract::kbuilds;
use timer_extract::report;

#[derive(Parser, Debug)]
#[command(
    name = "timer-extract",
    about = "Derive CVE-2026-98260 per-build constants from an Android boot.img / arm64 Image",
    after_help = "examples:\n  \
        timer-extract boot.img            # detect only\n  \
        timer-extract boot.img --add      # detect and register the profile\n\n\
        exit codes: 0 vulnerable, 3 kernel patched, 1 error."
)]
struct Cli {
    /// boot.img, raw arm64 Image, or gzip Image
    image: PathBuf,
    /// insert (or refresh) the profile row in --kbuilds
    #[arg(long)]
    add: bool,
    /// build registry to edit with --add
    #[arg(long, default_value = kbuilds::REGISTRY_PATH)]
    kbuilds: PathBuf,
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    if !cli.image.is_file() {
        anyhow::bail!("no such image: {}", cli.image.display());
    }
    let facts = derive(&cli.image)?;
    let release = facts
        .release
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("image carries no kernel release string"))?;
    let ident = kbuilds::identifier(release);

    let profile = if cli.add {
        let done = kbuilds::apply(&cli.kbuilds, &facts)?;
        let mut line = format!("{} {}", done.file.label(), done.path.display());
        if done.added_to_registry {
            line.push_str(", registered");
        }
        line
    } else {
        let registry = std::fs::read_to_string(&cli.kbuilds).unwrap_or_default();
        if kbuilds::is_registered(&registry, &ident) {
            "registered".to_string()
        } else {
            format!("missing from {} (re-run with --add)", cli.kbuilds.display())
        }
    };

    print!("{}", report::render_text(&facts, &cli.image, &profile));
    Ok(match facts.verdict {
        Verdict::Vulnerable => 0,
        Verdict::Patched => 3,
    })
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
