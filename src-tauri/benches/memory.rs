//! Memory footprint benchmark for Double Ratchet sessions.
//!
//! `benches/perf.rs` answers "how fast"; this answers "how much". A change
//! that makes each session fatter — extra cached skipped-message keys, a
//! larger header, an eagerly populated buffer — can leave timings almost
//! untouched while quietly multiplying the cost of every active session.
//! That is exactly the regression this target exists to catch.
//!
//! ## Why a counting allocator instead of RSS
//!
//! RSS (/proc/self/statm, GetProcessMemoryInfo, task_info) includes allocator
//! arenas, fragmentation and unrelated process state, and it differs enough
//! between Linux/macOS/Windows that a single CI threshold would either be
//! meaningless or constantly flapping. Counting live bytes (alloc - free)
//! through a `#[global_allocator]` is deterministic and platform independent,
//! so the same threshold is valid everywhere.
//!
//! `harness = false` — this is a plain binary, not a libtest/criterion harness.

use fibemate_lib::double_ratchet::SessionManager;
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const SESSION_COUNTS: [usize; 3] = [100, 500, 1000];
const ROUNDS: usize = 3; // median, to shrug off hash-map capacity jitter

// ── Counting allocator ─────────────────────────────────────────

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

// SAFETY: every method delegates to `System` unchanged and only maintains
// counters, so allocation behaviour (alignment, null on failure, layout
// contracts) is exactly the system allocator's. The counters are relaxed
// atomics: they are statistics for a single-threaded benchmark, never used
// for synchronization, so no ordering is required.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let cur = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(cur, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            let cur = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(cur, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size > layout.size() {
                let cur = LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed)
                    + (new_size - layout.size());
                PEAK.fetch_max(cur, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

// ── Measurement ────────────────────────────────────────────────

/// Live heap held by `n` established sessions, in bytes.
///
/// The manager is kept alive across the second read so the sessions
/// themselves are still allocated when we sample.
fn measure_sessions(n: usize) -> usize {
    // Absorb one-off allocations (lazy statics, thread-locals, first-touch
    // of the map) so the delta reflects session state only.
    let warm = SessionManager::new();
    warm.create_session("warmup", &[0x42u8; 32], true).unwrap();
    drop(warm);

    let before = LIVE.load(Ordering::Relaxed);
    let sm = SessionManager::new();
    for i in 0..n {
        sm.create_session(&format!("session-{i}"), &[0x42u8; 32], true)
            .unwrap();
    }
    let after = LIVE.load(Ordering::Relaxed);
    drop(sm);
    after.saturating_sub(before)
}

fn median(mut xs: Vec<usize>) -> usize {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

fn main() {
    let mut results: Vec<(String, usize)> = Vec::new();

    println!("Double Ratchet session memory footprint (live heap)");
    println!("metric                        sessions        live       per-session");
    println!("--------------------------------------------------------------------");

    for n in SESSION_COUNTS {
        let start = Instant::now();
        let bytes = median((0..ROUNDS).map(|_| measure_sessions(n)).collect());
        // Attribute the whole delta to the sessions: it is dominated by their
        // ratchet state, and any constant overhead is what a regression in
        // per-session cost would show up in anyway.
        let per = bytes / n;
        println!(
            "sessions_{:<20} {:>8} {:>11} B {:>13} B   ({:?})",
            n,
            n,
            bytes,
            per,
            start.elapsed()
        );
        results.push((format!("sessions_{n}"), bytes));
    }

    println!(
        "\npeak live heap during run: {} B",
        PEAK.load(Ordering::Relaxed)
    );

    // Persist for scripts/perf_check.py, which gates the numbers.
    let out_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"))
        .join("criterion");
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("WARNING: cannot create {}: {e}", out_dir.display());
        return;
    }
    let out = out_dir.join("memory.json");
    let map: std::collections::BTreeMap<_, _> = results.into_iter().collect();
    match std::fs::write(&out, serde_json::to_string_pretty(&map).unwrap() + "\n") {
        Ok(()) => println!("wrote {}", out.display()),
        Err(e) => eprintln!("WARNING: cannot write {}: {e}", out.display()),
    }
}
