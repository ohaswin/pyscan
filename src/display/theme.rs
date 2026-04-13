use comfy_table::Color;
use is_terminal::IsTerminal;
use std::io;

use crate::scanner::models::Vuln;

// ─── TTY Detection ──────────────────────────────────────────────────────────

/// Check if stdout is a TTY (interactive terminal).
pub fn is_tty() -> bool {
    io::stdout().is_terminal()
}

/// Output mode — determined once per invocation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputMode {
    /// Interactive terminal — full color, icons, tables, progress
    Rich,
    /// Piped or redirected — plain text, no ANSI, no Unicode decorations
    Plain,
}

/// Detect the output mode based on environment variables and TTY status.
/// Respects the `NO_COLOR` convention (https://no-color.org) and
/// `CLICOLOR_FORCE` for forcing color output in piped contexts.
pub fn detect_output_mode() -> OutputMode {
    // Respect NO_COLOR convention
    if std::env::var("NO_COLOR").is_ok() {
        return OutputMode::Plain;
    }

    // Force color even in pipes (e.g., CLICOLOR_FORCE=1)
    if std::env::var("CLICOLOR_FORCE").map_or(false, |v| v != "0") {
        return OutputMode::Rich;
    }

    if is_tty() {
        OutputMode::Rich
    } else {
        OutputMode::Plain
    }
}

// ─── Severity Classification ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl SeverityLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "CRIT",
            Self::High     => "HIGH",
            Self::Medium   => "MED",
            Self::Low      => "LOW",
            Self::Unknown  => "UNKN",
        }
    }
}

/// Classify vulnerability severity from OSV API data.
///
/// Priority:
/// 1. `database_specific.severity` — GitHub Advisory label (CRITICAL/HIGH/MODERATE/LOW)
/// 2. `severity[].score` — CVSS numeric score
/// 3. Fallback → Unknown
pub fn classify_severity(vuln: &Vuln) -> SeverityLevel {
    // Prefer database_specific.severity (GitHub's label)
    if let Some(db) = &vuln.database_specific {
        return match db.severity.to_uppercase().as_str() {
            "CRITICAL" => SeverityLevel::Critical,
            "HIGH"     => SeverityLevel::High,
            "MODERATE" => SeverityLevel::Medium,
            "LOW"      => SeverityLevel::Low,
            _          => SeverityLevel::Unknown,
        };
    }

    // Fallback: parse CVSS score from severity vec
    if let Some(sevs) = &vuln.severity {
        if let Some(sev) = sevs.first() {
            if let Ok(score) = sev.score.parse::<f32>() {
                return match score {
                    s if s >= 9.0 => SeverityLevel::Critical,
                    s if s >= 7.0 => SeverityLevel::High,
                    s if s >= 4.0 => SeverityLevel::Medium,
                    _             => SeverityLevel::Low,
                };
            }
        }
    }

    SeverityLevel::Unknown
}

// ─── Visual Language ────────────────────────────────────────────────────────

/// Map SeverityLevel → comfy-table Color for the severity column.
pub fn severity_color(level: &SeverityLevel) -> Color {
    match level {
        SeverityLevel::Critical => Color::Red,
        SeverityLevel::High     => Color::DarkRed,
        SeverityLevel::Medium   => Color::Yellow,
        SeverityLevel::Low      => Color::Cyan,
        SeverityLevel::Unknown  => Color::White,
    }
}

/// Map SeverityLevel → icon string.
/// Returns plain-text fallbacks when not in a TTY.
pub fn severity_icon(level: &SeverityLevel) -> &'static str {
    if !is_tty() {
        return match level {
            SeverityLevel::Critical | SeverityLevel::High => "!!",
            SeverityLevel::Medium | SeverityLevel::Low    => "??",
            SeverityLevel::Unknown                        => "--",
        };
    }

    match level {
        SeverityLevel::Critical | SeverityLevel::High => "✘",
        SeverityLevel::Medium | SeverityLevel::Low    => "⚠",
        SeverityLevel::Unknown                        => "ℹ",
    }
}
