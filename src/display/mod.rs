mod table;
mod card;
pub mod diagnostic;
pub mod progress;
pub mod theme;

use crate::parser::structs::ScannedDependency;
use std::collections::HashMap;
use std::time::Duration;
use theme::{detect_output_mode, OutputMode, classify_severity, is_tty, SeverityLevel};

// Re-export for scanner module
pub use progress::{create_scan_progress, finish_progress};

/// Source file context for diagnostic rendering.
/// Carries the original file path and content so miette can
/// produce source-annotated vulnerability reports.
#[derive(Debug, Clone)]
pub struct SourceContext {
    pub file_path: String,
    pub content: String,
}

/// Main display entry point — replaces `display_queried()` and `display_summary()`.
///
/// Renders:
/// 1. Results table (vulnerable + safe dependencies)
/// 2. Diagnostic detail cards per vulnerability (with source snippets if available)
/// 3. Summary card with risk level, dep count, and scan time
pub fn display_results(
    collected: &[ScannedDependency],
    imports_info: &mut HashMap<String, String>,
    source: Option<&SourceContext>,
    scan_duration: Duration,
) {
    let mode = detect_output_mode();

    // Separate safe deps by removing vulnerable ones from import_info
    for d in collected.iter() {
        imports_info.remove(d.name.as_str());
    }
    let safe_count = imports_info.len();

    let total_deps = collected.len() + safe_count;
    let risk = overall_risk(collected);

    match mode {
        OutputMode::Rich => render_rich(collected, safe_count, source, total_deps, scan_duration, &risk),
        OutputMode::Plain => render_plain(collected, safe_count, total_deps, scan_duration, &risk),
    }
}

/// Rich TTY rendering — tables, diagnostics, summary card.
fn render_rich(
    collected: &[ScannedDependency],
    safe_count: usize,
    source: Option<&SourceContext>,
    total_deps: usize,
    scan_duration: Duration,
    risk: &SeverityLevel,
) {
    // 1. Results table (sorted by severity, grouped by dep)
    let tbl = table::build_results_table(collected);
    println!("\n{tbl}\n");

    if safe_count > 0 && is_tty() {
        println!("  \x1b[32;2m✔ {} safe dependencies not shown\x1b[0m\n", safe_count);
    }

    // 2. Diagnostic detail cards (sorted in same order as the table)
    if let Some(src) = source {
        let sorted = table::sorted_vuln_indices(collected);
        for (_severity, di, vi) in &sorted {
            let dep = &collected[*di];
            let vuln = &dep.vuln.vulns[*vi];
            let fixed = diagnostic::extract_fixed_version(vuln);
            if let Some(report) = diagnostic::build_diagnostic(
                vuln,
                &src.file_path,
                &src.content,
                &dep.name,
                &fixed,
            ) {
                // miette renders to stderr by convention (like compiler diagnostics)
                eprintln!("{:?}", report);
            }
        }
    }

    // 3. Summary card
    let summary = card::ScanSummary {
        total_deps,
        vuln_count: collected.len(),
        scan_duration,
        risk_level: risk.clone(),
    };
    println!("{}", summary.render());
}

/// Plain non-TTY rendering — tab-separated, grep-able output.
fn render_plain(
    collected: &[ScannedDependency],
    safe_count: usize,
    total_deps: usize,
    scan_duration: Duration,
    risk: &SeverityLevel,
) {
    // Output sorted by severity (same order as TTY table)
    let sorted = table::sorted_vuln_indices(collected);
    for (_severity, di, vi) in &sorted {
        let dep = &collected[*di];
        let vuln = &dep.vuln.vulns[*vi];
        let sev = classify_severity(vuln);
        let fixed = diagnostic::extract_fixed_version(vuln);
        println!(
            "{}\t{}\t{}\t{}\t{}",
            sev.label(),
            dep.name,
            dep.version,
            fixed,
            vuln.id
        );
    }

    if safe_count > 0 {
        println!("{} safe dependencies not shown", safe_count);
    }

    let summary = card::ScanSummary {
        total_deps,
        vuln_count: collected.len(),
        scan_duration,
        risk_level: risk.clone(),
    };
    println!("{}", summary.render());
}

/// Determine overall risk from the worst severity found across all vulns.
fn overall_risk(collected: &[ScannedDependency]) -> SeverityLevel {
    collected
        .iter()
        .flat_map(|d| d.vuln.vulns.iter())
        .map(|v| classify_severity(v))
        .min() // SeverityLevel derives Ord: Critical < High < Medium < Low < Unknown
        .unwrap_or(SeverityLevel::Unknown)
}
