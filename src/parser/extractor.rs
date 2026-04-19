/// for the parser module, extractor.rs is the backbone of all parsing
/// it takes a String and a mutable reference to a Vec<Dependency>.
/// String is the contents of a source file, while the mut ref vector will
/// be used to collect the dependencies that we have extracted from the contents.
use super::structs::{Dependency, VersionStatus};

use pep_508::{self, Spec};
use regex::Regex;
use std::sync::LazyLock;

use toml::{de::Error, Table, Value};

static IMPORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:from|import)\s+(\w+(?:\s*,\s*\w+)*)").unwrap()
});

pub fn extract_imports_python(text: String, imp: &mut Vec<Dependency>) {
    for x in IMPORT_REGEX.find_iter(&text) {
        let mat = x.as_str().to_string();
        let mat = mat.replacen("import", "", 1).trim().to_string();

        imp.push(Dependency {
            name: mat,
            version: None,
            comparator: None,
            version_status: VersionStatus {
                pypi: false,
                pip: false,
                source: false,
            },
        })
    }
}

pub fn extract_imports_reqs(text: String, imp: &mut Vec<Dependency>) {
    // requirements.txt uses a PEP 508 parser to parse dependencies accordingly

    let parsed = pep_508::parse(text.as_str());

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
                        version_status: VersionStatus {
                            pypi: false,
                            pip: false,
                            source: true,
                        },
                    });
                }
            }
        } else {
            imp.push(Dependency {
                name: dname,
                version: None,
                comparator: None,
                version_status: VersionStatus {
                    pypi: false,
                    pip: false,
                    source: false,
                },
            });
        }
    } else if let Err(e) = parsed {
        println!("{:#?}", e);
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
                            version_status: VersionStatus {
                                pypi: false,
                                pip: false,
                                source: true,
                            },
                        });
                    }
                }
            } else {
                imp.push(Dependency {
                    name: dname,
                    version: None,
                    comparator: None,
                    version_status: VersionStatus {
                        pypi: false,
                        pip: false,
                        source: false,
                    },
                });
            }
        }
    }
}

pub fn extract_imports_pyproject(
    toml_content: String,
    imp: &mut Vec<Dependency>,
) -> Result<(), Error> {
    let toml_value: Value = toml::from_str(toml_content.as_str())?;

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
                            version_status: VersionStatus {
                                pypi: false,
                                pip: false,
                                source: true,
                            },
                        });
                    }
                }
            } else {
                imp.push(Dependency {
                    name: dname.clone(),
                    version: None,
                    comparator: None,
                    version_status: VersionStatus {
                        pypi: false,
                        pip: false,
                        source: false,
                    },
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
pub fn extract_imports_uvlock(
    toml_content: String,
    imp: &mut Vec<Dependency>,
) -> Result<(), Error> {
    let toml_value: Value = toml::from_str(toml_content.as_str())?;

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

        let has_source = version.is_some();
        imp.push(Dependency {
            name,
            version,
            comparator,
            version_status: VersionStatus {
                pypi: false,
                pip: false,
                source: has_source,
            },
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

pub fn extract_imports_cyclonedx(content: String, imp: &mut Vec<Dependency>) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(components) = v.get("components").and_then(|c| c.as_array()) {
            for comp in components {
                if let (Some(name), Some(version)) = (
                    comp.get("name").and_then(|n| n.as_str()),
                    comp.get("version").and_then(|v| v.as_str()),
                ) {
                    imp.push(Dependency {
                        name: name.to_string(),
                        version: Some(version.to_string()),
                        comparator: None,
                        version_status: VersionStatus {
                            pypi: false,
                            pip: false,
                            source: true,
                        },
                    });
                }
            }
        }
    } else {
        eprintln!("Failed to parse CycloneDX SBOM JSON");
    }
}

pub fn extract_imports_spdx(content: String, imp: &mut Vec<Dependency>) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(packages) = v.get("packages").and_then(|c| c.as_array()) {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("versionInfo").and_then(|v| v.as_str()),
                ) {
                    imp.push(Dependency {
                        name: name.to_string(),
                        version: Some(version.to_string()),
                        comparator: None,
                        version_status: VersionStatus {
                            pypi: false,
                            pip: false,
                            source: true,
                        },
                    });
                }
            }
        }
    } else {
        eprintln!("Failed to parse SPDX SBOM JSON");
    }
}
