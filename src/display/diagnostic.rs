use miette::{Diagnostic, SourceSpan, NamedSource, Report};
use thiserror::Error;

use crate::scanner::models::Vuln;

/// A displayable vulnerability diagnostic — not a program error.
/// Uses miette for rich rendering with source snippets and suggestions.
#[derive(Debug, Diagnostic, Error)]
#[error("{vuln_id}: {summary}")]
#[diagnostic(
    code(pyscan::vulnerability),
    help("{suggestion}")
)]
pub struct VulnDiagnostic {
    pub vuln_id: String,
    pub summary: String,
    pub suggestion: String,

    #[source_code]
    pub source_code: NamedSource<String>,

    #[label("{label_text}")]
    pub span: SourceSpan,

    pub label_text: String,
}

use std::path::Path;
use std::fs;

/// Try to find where a dependency is imported in the project's .py files.
fn find_import_source(dep_name: &str, dir: &Path) -> Option<(String, String, usize, usize)> {
    let python_pkg_name = dep_name.replace('-', "_");
    
    // Very simple heuristic search strings
    let t1 = format!("import {}", python_pkg_name);
    let t2 = format!("from {}", python_pkg_name);

    fn search_dir(dir: &Path, targets: &[&str], depth: u8) -> Option<(String, String, usize, usize)> {
        if depth > 3 { return None; } // Limit recursion depth
        let Ok(entries) = fs::read_dir(dir) else { return None; };
        
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.starts_with('.') || name == "venv" || name == "env" || name == "site-packages" || name == "__pycache__" {
                    continue;
                }
                if let Some(res) = search_dir(&path, targets, depth + 1) {
                    return Some(res);
                }
            } else if path.extension().map_or(false, |ext| ext == "py") {
                if let Ok(content) = fs::read_to_string(&path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if targets.iter().any(|t| trimmed.starts_with(*t)) {
                            if let Some(offset) = content.find(line) {
                                return Some((path.to_string_lossy().to_string(), content.clone(), offset, line.len()));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    search_dir(dir, &[&t1, &t2], 0)
}

/// Build a miette diagnostic for a specific vulnerability, highlighting the
/// line in the source file where the dependency is declared.
///
/// Returns `None` if the dependency name cannot be found in the source content.
pub fn build_diagnostic(
    vuln: &Vuln,
    source_file: &str,
    source_content: &str,
    dep_name: &str,
    fixed_version: &str,
) -> Option<Report> {
    // 1. Try to find where the user actually imports it in their code
    let mut project_dir = Path::new(source_file).parent().unwrap_or_else(|| Path::new("."));
    if project_dir.as_os_str().is_empty() {
        project_dir = Path::new(".");
    }
    
    let (final_file, final_content, offset, span_len, label_text) = 
        if let Some((f, c, o, l)) = find_import_source(dep_name, project_dir) {
            (f, c, o, l, "vulnerable dependency imported here".to_string())
        } else {
            // Fallback: point to the manifest file declaration
            let lower_content = source_content.to_lowercase();
            let lower_name = dep_name.to_lowercase();
            if let Some(offset) = lower_content.find(&lower_name) {
                let line_end = source_content[offset..]
                    .find('\n')
                    .map(|i| offset + i)
                    .unwrap_or(source_content.len());
                (
                    source_file.to_string(), 
                    source_content.to_string(), 
                    offset, 
                    line_end - offset,
                    "vulnerable dependency declared here".to_string()
                )
            } else {
                return None;
            }
        };

    let diag = VulnDiagnostic {
        vuln_id: vuln.id.clone(),
        summary: summarize(&vuln.details, 150),
        suggestion: format!("Update '{}' to {}", dep_name, fixed_version),
        source_code: NamedSource::new(final_file, final_content),
        span: (offset, span_len).into(),
        label_text,
    };

    Some(Report::new(diag))
}

/// Extract the fixed version from a vulnerability's range events.
///
/// Checks `affected[].ranges[].events[].fixed` first (most precise),
/// then falls back to the last entry in `affected[].versions`.
pub fn extract_fixed_version(vuln: &Vuln) -> String {
    for affected in &vuln.affected {
        // Try range events first — gives us the exact fix version
        if let Some(ranges) = &affected.ranges {
            for range in ranges {
                for event in &range.events {
                    if let Some(fixed) = &event.fixed {
                        return format!(">= {}", fixed);
                    }
                }
            }
        }

        // Fallback: use last known affected version
        if let Some(versions) = &affected.versions {
            if let Some(last) = versions.last() {
                return format!("> {}", last);
            }
        }
    }

    "No fix available yet".to_string()
}

/// Extract a meaningful summary from vulnerability details text.
///
/// OSV/GHSA details often start with boilerplate like:
/// - "An issue was discovered in X before Y."
/// - "X is a library for Y."
/// - "In X before Y, there is a vulnerability..."
///
/// This function skips the first sentence and uses the remainder as the
/// actual description. If only one sentence exists, it falls back to
/// the full text (truncated).
fn summarize(details: &str, max: usize) -> String {
    let trimmed = details.trim();

    if trimmed.is_empty() {
        return "No details available".to_string();
    }

    // Try to find the end of the first sentence.
    // Look for ". " (period+space) or ".\n" (period+newline) patterns
    // that indicate a sentence boundary.
    let useful_text = find_substance(trimmed);

    truncate_at_boundary(useful_text.trim(), max)
}

/// Skip leading boilerplate sentences and return the substantive text.
///
/// Detects common boilerplate patterns:
/// - Sentences starting with articles + generic verbs ("An issue was...", "A vulnerability in...")
/// - Sentences that are just naming the package ("X is a library for...")
fn find_substance(text: &str) -> &str {
    // Common boilerplate starters (case-insensitive check)
    let boilerplate_prefixes: &[&str] = &[
        "an issue ",
        "a vulnerability ",
        "a flaw ",
        "a bug ",
        "a security ",
        "there is ",
        "there was ",
        "it was ",
        "this advisory ",
        "this cve ",
    ];

    let lower = text.to_lowercase();

    // Check if the text starts with boilerplate
    let starts_with_boilerplate = boilerplate_prefixes
        .iter()
        .any(|prefix| lower.starts_with(prefix));

    if !starts_with_boilerplate {
        // Also check for the pattern "PackageName is a ..." (naming sentence)
        // Heuristic: if first sentence contains " is a " or " is an " early on
        if let Some(first_end) = find_sentence_end(text) {
            let first_sentence = &text[..first_end];
            let first_lower = first_sentence.to_lowercase();
            if first_lower.contains(" is a ") || first_lower.contains(" is an ") {
                let rest = text[first_end..].trim_start_matches(|c: char| c == '.' || c.is_whitespace());
                if !rest.is_empty() {
                    return rest;
                }
            }
        }
        return text;
    }

    // Skip the first sentence
    if let Some(end) = find_sentence_end(text) {
        let rest = text[end..].trim_start_matches(|c: char| c == '.' || c.is_whitespace());
        if !rest.is_empty() {
            return rest;
        }
    }

    // Fallback: use the whole text if we can't split
    text
}

/// Find the byte offset of the end of the first sentence.
/// Looks for ". " or ".\n" patterns, ignoring decimal numbers (e.g., "2.31.0").
fn find_sentence_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let len = bytes.len();

    for i in 0..len.saturating_sub(1) {
        if bytes[i] == b'.' {
            let next = bytes[i + 1];
            // Period followed by space or newline = sentence boundary
            if next == b' ' || next == b'\n' || next == b'\r' {
                // But NOT if the char before the period is a digit and after the space
                // is also a digit (like "version 2.31.0 has...")
                let prev_is_digit = i > 0 && bytes[i - 1].is_ascii_digit();
                let after_space_is_digit = i + 2 < len && bytes[i + 2].is_ascii_digit();

                if prev_is_digit && after_space_is_digit {
                    continue; // Skip — this is a version number, not a sentence end
                }

                return Some(i + 1);
            }
        }
    }

    None
}

/// Truncate text at a char boundary, appending "..." if needed.
fn truncate_at_boundary(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        // Try to break at the last space for cleaner output
        if let Some(last_space) = s[..end].rfind(' ') {
            if last_space > max / 2 {
                return format!("{}...", &s[..last_space]);
            }
        }
        format!("{}...", &s[..end])
    }
}
