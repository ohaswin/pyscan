/// for the parser module, extractor.rs is the backbone of all parsing
/// it takes a String and a mutable reference to a Vec<Dependency>.
/// String is the contents of a source file, while the mut ref vector will
/// be used to collect the dependencies that we have extracted from the contents.
use super::structs::{Dependency, VersionSource};

use pep_508::{self, Spec};
use regex::Regex;
use std::sync::LazyLock;

use crate::error::PyscanError;
use crate::ARGS;
use toml::{de::Error, Table, Value};

static IMPORT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:from|import)\s+(\w+(?:\s*,\s*\w+)*)").unwrap());

pub fn extract_imports_python(text: &str, imp: &mut Vec<Dependency>) {
    for x in IMPORT_REGEX.find_iter(text) {
        let mat = x.as_str().to_string();
        let mat = mat.replacen("import", "", 1).trim().to_string();

        imp.push(Dependency {
            name: mat,
            version: None,
            comparator: None,
            version_source: VersionSource::Code,
        })
    }
}

pub fn extract_imports_reqs(content: &str, imp: &mut Vec<Dependency>) -> Result<(), PyscanError> {
    // Pass 1: Line joining (backslash handling)
    let mut current_line = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with('\\') {
            current_line.push_str(trimmed[..trimmed.len() - 1].trim_end());
        } else {
            current_line.push_str(&line);
            extract_import_reqs_from_line(&mut current_line, imp);
            current_line.clear();
        }
    }
    Ok(())
}

fn extract_import_reqs_from_line(line: &mut String, imp: &mut Vec<Dependency>) {
    // 1. Skip empty lines or pure comment lines
    if line.is_empty() || line.starts_with('#') {
        return;
    }

    // 2. Skip pip options lines (e.g. -r, -c, --index-url)
    if line.starts_with('-') {
        return;
    }

    // 3. Strip inline comments (quoted-string-aware scan for '#')
    // Heuristic: find the first '#' preceded by whitespace NOT inside a quoted string.
    let mut comment_start = None;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let chars: Vec<char> = line.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '#' if !in_single_quote && !in_double_quote => {
                // Only treat # as a comment start if it is preceded by whitespace
                // (pip itself uses this heuristic to avoid breaking URLs with fragments)
                if i == 0 || chars[i - 1].is_whitespace() {
                    comment_start = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    if let Some(idx) = comment_start {
        line.truncate(idx);
    }

    // 4. Strip trailing pip options (scan for ' --')
    if let Some(idx) = line.find(" --") {
        line.truncate(idx);
    }

    // 5. Final strip and discard if empty
    let line = line.trim();
    if line.is_empty() {
        return;
    }

    // 6. What remains is a PEP 508 specifier
    let parsed = pep_508::parse(line);

    if let Ok(ref dep) = parsed {
        let dname = dep.name.to_string();
        if let Some(ver) = &dep.spec {
            if let Spec::Version(verspec) = ver {
                if let Some(v) = verspec.iter().next() {
                    let version = v.version.to_string();
                    let comparator = v.comparator;
                    imp.push(Dependency {
                        name: dname,
                        version: Some(version),
                        comparator: Some(comparator),
                        version_source: VersionSource::Code,
                    });
                }
            }
        } else {
            imp.push(Dependency {
                name: dname,
                version: None,
                comparator: None,
                version_source: VersionSource::None,
            });
        }
    } else if let Err(e) = parsed {
        // Silently fail or log for requirements fragments that aren't PEP 508
        // (e.g. local paths, which are common but not vulnerabilities)
        if ARGS.get().map(|a| a.pedantic).unwrap_or(false) {
            eprintln!("Failed to parse requirement '{}': {:?}", line, e);
        }
    }
}

pub fn extract_imports_setup_py(setup_py_content: &str, imp: &mut Vec<Dependency>) {
    let mut deps = Vec::new();

    // regex for install_requires section
    let re = Regex::new(r"install_requires\s*=\s*\[([^\]]+)\]").expect("Invalid regex pattern");

    for cap in re.captures_iter(setup_py_content) {
        if let Some(matched) = cap.get(1) {
            deps.extend(
                matched
                    .as_str()
                    .split(',')
                    .map(|dep| dep.trim().replace("\"", "").replace("\\", "").to_string()),
            );
        }
    }

    for d in deps {
        let d = d.as_str();
        let parsed = pep_508::parse(d);
        if let Ok(dep) = parsed {
            let dname = dep.name.to_string();
            if let Some(ver) = dep.spec {
                if let Spec::Version(verspec) = ver {
                    if let Some(v) = verspec.first() {
                        let version = v.version.to_string();
                        let comparator = v.comparator;
                        imp.push(Dependency {
                            name: dname,
                            version: Some(version),
                            comparator: Some(comparator),
                            version_source: VersionSource::Code,
                        });
                    }
                }
            } else {
                imp.push(Dependency {
                    name: dname,
                    version: None,
                    comparator: None,
                    version_source: VersionSource::None,
                });
            }
        }
    }
}

pub fn extract_imports_pyproject(
    toml_value: Value,
    imp: &mut Vec<Dependency>,
) -> Result<(), Error> {
    // Helper function to extract dependency values (version strings) including nested tables
    fn extract_dependencies(
        table: &toml::value::Table,
        poetry: Option<bool>,
    ) -> Result<Vec<String>, Error> {
        let mut deps = Vec::new();

        let projectlevel: Vec<&str> = vec![
            "dependencies",
            "optional-dependencies.docs",
            "optional-dependencies",
        ];

        for (key, version) in table {
            if projectlevel.contains(&key.as_str()) {
                match version {
                    Value::String(version_str) => {
                        deps.push(version_str.to_string());
                    }
                    Value::Table(nested_table) => {
                        if "optional-dependencies" == key {
                            parse_opt_deps_pyproject(nested_table.clone(), &mut deps);
                        } else {
                            let nested_deps = extract_dependencies(nested_table, None)?;
                            deps.extend(nested_deps);
                        }
                    }
                    Value::Array(array) => {
                        for item in array {
                            if let Value::String(item_str) = item {
                                deps.push(item_str.to_string());
                            }
                        }
                    }
                    _ => eprintln!("ERR: Invalid dependency syntax found while TOML parsing"),
                }
            } else if poetry.unwrap_or(false) {
                match version {
                    Value::String(version_str) => {
                        let verstr = version_str.to_string();
                        if verstr.contains('^') {
                            let s = format!("{} >= {}", key, verstr.strip_prefix('^').unwrap());
                            deps.push(s);
                        } else if verstr == "*" {
                            deps.push(key.to_string());
                        }
                    }
                    Value::Table(nested_table) => {
                        let nested_deps = extract_dependencies(nested_table, None)?;
                        deps.extend(nested_deps);
                    }
                    Value::Array(array) => {
                        for item in array {
                            if let Value::String(item_str) = item {
                                deps.push(item_str.to_string());
                            }
                        }
                    }
                    _ => eprintln!("ERR: Invalid dependency syntax found while TOML parsing"),
                }
            }
        }
        Ok(deps)
    }

    // Extract dependencies from different sections
    let mut all_dependencies = Vec::new();

    let keys_to_check = vec!["project", "optional-dependencies", "tool"];

    for key in keys_to_check {
        if key.contains("tool") {
            if let Some(dependencies_table) = toml_value.get("tool") {
                if let Some(dependencies_table) = dependencies_table.get("poetry") {
                    let poetrylevel: Vec<&str> = vec!["dependencies", "dev-dependencies"];
                    for k in poetrylevel.into_iter() {
                        if let Some(dep) = dependencies_table.get(k) {
                            match dep {
                                Value::Table(table) => {
                                    all_dependencies
                                        .extend(extract_dependencies(table, Some(true))?);
                                }
                                // Poetry [tool.poetry.dependencies] can contain non-table
                                // values like `python = "^3.8"` — skip them silently
                                other => {
                                    eprintln!(
                                        "Skipping unexpected TOML value type in poetry dependencies: {:?}",
                                        other.type_str()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        // if its not poetry, check for [project] dependencies
        else if !key.contains("poetry") {
            if let Some(dependencies_table) = toml_value.get(key) {
                if let Some(dependencies) = dependencies_table.as_table() {
                    all_dependencies.extend(extract_dependencies(dependencies, None)?);
                }
            }
        } else {
            eprintln!(
                "The pyproject.toml seen here is unlike of a python project. Please check and make sure you are in the right directory, or check the toml file."
            );
            return Ok(());
        }
    }
    // Sort then dedup to correctly remove all duplicates (not just consecutive ones)
    all_dependencies.sort_unstable();
    all_dependencies.dedup();

    for d in all_dependencies {
        let d = d.as_str();
        let parsed = pep_508::parse(d);
        if let Ok(dep) = parsed {
            let dname = dep.name.to_string();
            if let Some(ver) = dep.spec {
                if let Spec::Version(verspec) = ver {
                    if let Some(v) = verspec.into_iter().next() {
                        let version = v.version.to_string();
                        let comparator = v.comparator;
                        imp.push(Dependency {
                            name: dname.clone(),
                            version: Some(version),
                            comparator: Some(comparator),
                            version_source: VersionSource::Code,
                        });
                    }
                }
            } else {
                imp.push(Dependency {
                    name: dname.clone(),
                    version: None,
                    comparator: None,
                    version_source: VersionSource::None,
                });
            }
        }
    }
    Ok(())
}

pub fn parse_opt_deps_pyproject(table: Table, deps: &mut Vec<String>) {
    for v in table.values() {
        match v {
            Value::Array(a) => {
                for d in a {
                    if let Value::String(dependency) = d {
                        deps.push(dependency.to_owned());
                    } else {
                        eprintln!(
                            "Skipping unexpected TOML value type in optional-dependencies array: {:?}",
                            d.type_str()
                        );
                    }
                }
            }
            other => {
                eprintln!(
                    "Skipping unexpected TOML value type in optional-dependencies: {:?}",
                    other.type_str()
                );
            }
        }
    }
}

/// Extracts dependencies from a uv.lock file.
///
/// uv.lock is a TOML-based lockfile generated by the `uv` package manager.
/// The root project is identified by `source = { virtual = "." }`.
/// Dependencies with specifiers are found in `[package.metadata].requires-dist`
/// and `[package.metadata.requires-dev]`. Resolved versions are available in
/// each `[[package]]` entry's `version` field.
pub fn extract_imports_uvlock(toml_value: Value, imp: &mut Vec<Dependency>) -> Result<(), Error> {
    // Build a lookup map of resolved package versions: name -> version
    let mut resolved_versions: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    if let Some(packages) = toml_value.get("package") {
        if let Some(packages_arr) = packages.as_array() {
            for pkg in packages_arr {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|v| v.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    resolved_versions.insert(name.to_string(), version.to_string());
                }
            }
        }
    }

    // Find the root project package (source = { virtual = "." })
    let root_package = if let Some(packages) = toml_value.get("package") {
        if let Some(packages_arr) = packages.as_array() {
            packages_arr.iter().find(|pkg| {
                if let Some(source) = pkg.get("source") {
                    if let Some(source_table) = source.as_table() {
                        return source_table
                            .get("virtual")
                            .and_then(|v| v.as_str())
                            .map_or(false, |v| v == ".");
                    }
                    if let Some(source_str) = source.as_str() {
                        return source_str.contains("virtual") && source_str.contains(".");
                    }
                }
                false
            })
        } else {
            None
        }
    } else {
        None
    };

    let root_package = match root_package {
        Some(pkg) => pkg,
        None => {
            eprintln!("Could not find the root project package in uv.lock (expected source = {{ virtual = \".\" }})");
            return Ok(());
        }
    };

    // Collect dependency specifiers from requires-dist and requires-dev
    let mut dep_specs: Vec<(String, Option<String>)> = Vec::new();

    // Parse [package.metadata].requires-dist
    if let Some(metadata) = root_package.get("metadata") {
        if let Some(requires_dist) = metadata.get("requires-dist") {
            if let Some(arr) = requires_dist.as_array() {
                for entry in arr {
                    if let Some(table) = entry.as_table() {
                        if let Some(name) = table.get("name").and_then(|v| v.as_str()) {
                            let specifier = table
                                .get("specifier")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            dep_specs.push((name.to_string(), specifier));
                        }
                    }
                }
            }
        }

        // Parse [package.metadata.requires-dev] — all groups
        if let Some(requires_dev) = metadata.get("requires-dev") {
            if let Some(dev_table) = requires_dev.as_table() {
                for (_group_name, group_deps) in dev_table {
                    if let Some(arr) = group_deps.as_array() {
                        for entry in arr {
                            if let Some(table) = entry.as_table() {
                                if let Some(name) = table.get("name").and_then(|v| v.as_str()) {
                                    let specifier = table
                                        .get("specifier")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    dep_specs.push((name.to_string(), specifier));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate by name (keep first occurrence)
    let mut seen = std::collections::HashSet::new();
    dep_specs.retain(|(name, _)| seen.insert(name.clone()));

    // Convert collected specs into Dependency structs
    for (name, specifier) in dep_specs {
        let (version, comparator) = if let Some(ref spec_str) = specifier {
            parse_uv_specifier(spec_str, &name, &resolved_versions)
        } else {
            let ver = resolved_versions.get(&name).cloned();
            (ver, None)
        };

        imp.push(Dependency {
            name,
            version_source: if version.is_some() {
                VersionSource::Code
            } else {
                VersionSource::None
            },
            version,
            comparator,
        });
    }

    Ok(())
}

/// Parses a uv.lock specifier string (e.g. "==5.2.8", ">=1.0.3") into
/// a (version, comparator) pair. Falls back to the resolved lockfile version
/// when the specifier is not a pinned `==`.
fn parse_uv_specifier(
    spec_str: &str,
    name: &str,
    resolved_versions: &std::collections::HashMap<String, String>,
) -> (Option<String>, Option<pep_508::Comparator>) {
    let spec_str = spec_str.trim();

    let (comparator, version_str) = if let Some(v) = spec_str.strip_prefix("==") {
        (Some(pep_508::Comparator::Eq), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix("~=") {
        (Some(pep_508::Comparator::Cp), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix(">=") {
        (Some(pep_508::Comparator::Ge), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix("<=") {
        (Some(pep_508::Comparator::Le), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix("!=") {
        (Some(pep_508::Comparator::Ne), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix('>') {
        (Some(pep_508::Comparator::Gt), Some(v.trim().to_string()))
    } else if let Some(v) = spec_str.strip_prefix('<') {
        (Some(pep_508::Comparator::Lt), Some(v.trim().to_string()))
    } else {
        (None, None)
    };

    match comparator {
        Some(pep_508::Comparator::Eq) => (version_str, comparator),
        Some(_) => {
            let resolved = resolved_versions.get(name).cloned().or(version_str);
            (resolved, comparator)
        }
        None => {
            let resolved = resolved_versions.get(name).cloned();
            (resolved, None)
        }
    }
}

pub fn extract_imports_cyclonedx(content: serde_json::Value, imp: &mut Vec<Dependency>) {
    if let Some(components) = content.get("components").and_then(|c| c.as_array()) {
        for comp in components {
            if let (Some(name), Some(version)) = (
                comp.get("name").and_then(|n| n.as_str()),
                comp.get("version").and_then(|v| v.as_str()),
            ) {
                imp.push(Dependency {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                    comparator: None,
                    version_source: VersionSource::Code,
                });
            }
        }
    }
}

pub fn extract_imports_spdx(content: serde_json::Value, imp: &mut Vec<Dependency>) {
    if let Some(packages) = content.get("packages").and_then(|c| c.as_array()) {
        for pkg in packages {
            if let (Some(name), Some(version)) = (
                pkg.get("name").and_then(|n| n.as_str()),
                pkg.get("versionInfo").and_then(|v| v.as_str()),
            ) {
                imp.push(Dependency {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                    comparator: None,
                    version_source: VersionSource::Code,
                });
            }
        }
    }
}
