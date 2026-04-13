use std::time::Duration;
use super::theme::{SeverityLevel, is_tty};

/// Minimal summary rendered after scan results.
pub struct ScanSummary {
    pub total_deps: usize,
    pub vuln_count: usize,
    pub scan_duration: Duration,
    pub risk_level: SeverityLevel,
}

impl ScanSummary {
    pub fn render(&self) -> String {
        if !is_tty() {
            return self.render_plain();
        }
        self.render_rich()
    }

    fn render_rich(&self) -> String {
        let dim = "\x1b[2m";
        let reset = "\x1b[0m";
        let bold = "\x1b[1m";

        let risk_color = match self.risk_level {
            SeverityLevel::Critical => "\x1b[1;91m",
            SeverityLevel::High     => "\x1b[1;31m",
            SeverityLevel::Medium   => "\x1b[1;33m",
            SeverityLevel::Low      => "\x1b[1;36m",
            SeverityLevel::Unknown  => "\x1b[1;37m",
        };

        let vuln_str = if self.vuln_count > 0 {
            format!("\x1b[1;91m{}\x1b[0m", self.vuln_count)
        } else {
            format!("\x1b[1;32m0\x1b[0m")
        };

        let risk_label = match self.risk_level {
            SeverityLevel::Critical => "CRITICAL",
            SeverityLevel::High     => "HIGH",
            SeverityLevel::Medium   => "MEDIUM",
            SeverityLevel::Low      => "LOW",
            SeverityLevel::Unknown  => "NONE",
        };

        format!(
            "{dim}  ──────────────────────────────────────{reset}\n\
             {dim}  scanned{reset} {bold}{}{reset}  {dim}│{reset}  {dim}vulnerable{reset} {}  {dim}│{reset}  {dim}risk{reset} {risk_color}{}{reset}  {dim}│{reset}  {dim}{:.2}s{reset}\n\
             {dim}  ──────────────────────────────────────{reset}\n",
            self.total_deps,
            vuln_str,
            risk_label,
            self.scan_duration.as_secs_f64(),
            dim = dim,
            reset = reset,
            bold = bold,
            risk_color = risk_color,
        )
    }

    fn render_plain(&self) -> String {
        let risk_label = match self.risk_level {
            SeverityLevel::Critical => "CRITICAL",
            SeverityLevel::High     => "HIGH",
            SeverityLevel::Medium   => "MEDIUM",
            SeverityLevel::Low      => "LOW",
            SeverityLevel::Unknown  => "NONE",
        };

        format!(
            "scanned {}  vulnerable {}  risk {}  {:.2}s\n",
            self.total_deps,
            self.vuln_count,
            risk_label,
            self.scan_duration.as_secs_f64(),
        )
    }
}
