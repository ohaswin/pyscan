use comfy_table::{Table, ContentArrangement, Color, Attribute, Cell, presets};
use crate::parser::structs::ScannedDependency;
use super::theme::{classify_severity, severity_color, severity_icon, is_tty, SeverityLevel};
use super::diagnostic::extract_fixed_version;

/// A flattened, sortable row for the results table.
struct VulnRow<'a> {
    severity: SeverityLevel,
    dep_name: &'a str,
    dep_version: &'a str,
    fixed_version: String,
    vuln_id: &'a str,
}

/// Build the main results table containing both vulnerable and safe dependencies.
///
/// Vulnerable rows are **sorted by severity** (Critical → High → Med → Low → Unknown)
/// and **grouped by dependency name** — the dep name is shown on the first row of
/// each group, and subsequent vulns for the same dep show `↳` (or `>` in non-TTY).
///
/// In TTY mode: full UTF-8 table with borders, colors, and icons.
/// In piped mode: borderless, no ANSI, plain-text severity labels.
pub fn build_results_table(
    vulnerable: &[ScannedDependency],
) -> Table {
    let mut table = Table::new();

    if is_tty() {
        table.load_preset(presets::UTF8_FULL)
             .set_content_arrangement(ContentArrangement::Dynamic);
    } else {
        table.load_preset(presets::NOTHING)
             .set_content_arrangement(ContentArrangement::Disabled);
    }

    table.set_header(vec![
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("Dependency").add_attribute(Attribute::Bold),
        Cell::new("Installed").add_attribute(Attribute::Bold),
        Cell::new("Fixed In").add_attribute(Attribute::Bold),
        Cell::new("Vuln ID").add_attribute(Attribute::Bold),
    ]);

    // --- Flatten all vulns into sortable rows ---
    let mut rows: Vec<VulnRow> = Vec::new();
    for dep in vulnerable {
        for vuln in &dep.vuln.vulns {
            rows.push(VulnRow {
                severity: classify_severity(vuln),
                dep_name: &dep.name,
                dep_version: &dep.version,
                fixed_version: extract_fixed_version(vuln),
                vuln_id: &vuln.id,
            });
        }
    }

    // Sort: primary = severity (Critical first), secondary = dep name (alphabetical)
    rows.sort_by(|a, b| {
        a.severity.cmp(&b.severity)
            .then_with(|| a.dep_name.to_lowercase().cmp(&b.dep_name.to_lowercase()))
    });

    // --- Render rows, grouping by dep name ---
    let mut last_dep: Option<&str> = None;

    for row in &rows {
        let is_continuation = last_dep == Some(row.dep_name);

        let dep_cell = if is_continuation {
            // Same dep as previous row — show continuation marker
            Cell::new(if is_tty() { "  ↳" } else { ">" })
                .add_attribute(Attribute::Dim)
        } else {
            Cell::new(row.dep_name)
        };

        let version_cell = if is_continuation {
            Cell::new("") // Don't repeat version for grouped rows
        } else {
            Cell::new(row.dep_version).add_attribute(Attribute::Dim)
        };

        table.add_row(vec![
            Cell::new(format!("{} {}", severity_icon(&row.severity), row.severity.label()))
                .fg(severity_color(&row.severity))
                .add_attribute(Attribute::Bold),
            dep_cell,
            version_cell,
            Cell::new(&row.fixed_version).fg(Color::Green),
            Cell::new(row.vuln_id).fg(Color::Yellow),
        ]);

        last_dep = Some(row.dep_name);
    }

    table
}

/// Build a sorted list of (severity, dep_index, vuln_index) tuples for
/// rendering diagnostics in the same order as the table.
pub fn sorted_vuln_indices(collected: &[ScannedDependency]) -> Vec<(SeverityLevel, usize, usize)> {
    let mut indices: Vec<(SeverityLevel, usize, usize)> = Vec::new();
    for (di, dep) in collected.iter().enumerate() {
        for (vi, vuln) in dep.vuln.vulns.iter().enumerate() {
            indices.push((classify_severity(vuln), di, vi));
        }
    }
    indices.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| collected[a.1].name.to_lowercase().cmp(&collected[b.1].name.to_lowercase()))
    });
    indices
}
