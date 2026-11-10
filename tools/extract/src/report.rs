//! Output rendering for the 98260 extractor.

use std::fmt::Write as _;
use std::path::Path;

use crate::derive::{Facts, Verdict};

/// Short report: does the kernel still carry the bug, and is its profile known.
pub fn render_text(facts: &Facts, image: &Path, profile: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "image      {}", image.display());
    let _ = writeln!(
        out,
        "release    {}",
        facts.release.as_deref().unwrap_or("<none>")
    );
    match facts.verdict {
        Verdict::Vulnerable => {
            let _ = writeln!(out, "vulnerable YES");
            let order: Vec<&str> = facts
                .order
                .calls
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            let _ = writeln!(
                out,
                "  begin_new_exec: {} run before posix_cpu_timers_exit",
                order
                    .iter()
                    .take_while(|name| **name != "posix_cpu_timers_exit")
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = writeln!(
                out,
                "  posix_cpu_timer_del: pid_task()==NULL at +0x{:x}, timerqueue_del {} ({})",
                facts.del.null_path,
                if facts.del.dequeues {
                    "called"
                } else {
                    "not called"
                },
                if facts.del.leaves_node_queued {
                    "stale node left in the timerqueue"
                } else {
                    "node dequeued"
                }
            );
        }
        Verdict::Patched => {
            let _ = writeln!(out, "vulnerable NO (upstream fix present: POSIX timers are");
            let _ = writeln!(out, "  cleaned right after de_thread(); no exploit target)");
        }
    }
    let _ = writeln!(out, "profile    {profile}");
    out
}
