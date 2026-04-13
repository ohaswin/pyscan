use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use super::theme::is_tty;

/// Create the appropriate progress indicator for the scan phase.
///
/// - Small projects (< 20 deps): Spinner with message
/// - Large projects (>= 20 deps): Progress bar with ETA
///
/// Returns `None` if stdout is not a TTY (piped/redirected),
/// because `indicatif` output would corrupt pipeable plain text.
pub fn create_scan_progress(total_deps: usize) -> Option<ProgressBar> {
    if !is_tty() {
        return None;
    }

    if total_deps < 20 {
        // Spinner mode for small projects
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("  {spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]),
        );
        spinner.set_message("Scanning dependencies against OSV...");
        spinner.enable_steady_tick(Duration::from_millis(80));
        Some(spinner)
    } else {
        // Progress bar mode for large dependency trees
        let bar = ProgressBar::new(total_deps as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "  {spinner:.cyan} Scanning [{bar:30.green/dim}] {pos}/{len} {msg}",
            )
            .unwrap()
            .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"])
            .progress_chars("█▓░"),
        );
        bar.set_message("querying OSV...");
        bar.enable_steady_tick(Duration::from_millis(80));
        Some(bar)
    }
}

/// Finish the progress indicator, replacing it with a static completion message.
/// This cleans up the scrollback — no leftover partial lines.
pub fn finish_progress(bar: Option<ProgressBar>, vuln_count: usize) {
    if let Some(bar) = bar {
        bar.set_style(ProgressStyle::with_template("  {msg}").unwrap());

        if vuln_count > 0 {
            bar.finish_with_message(format!(
                "✘ Scan complete — {} vulnerabilit{} found.",
                vuln_count,
                if vuln_count == 1 { "y" } else { "ies" }
            ));
        } else {
            bar.finish_with_message("✔ Scan complete — no vulnerabilities found.".to_string());
        }
    }
}
