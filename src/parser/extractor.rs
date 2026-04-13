use std::process::exit;

/// for the parser module, extractor.rs is the backbone of all parsing
/// it takes a String and a mutable reference to a Vec<Dependency>.
/// String is the contents of a source file, while the mut ref vector will
/// be used to collect the dependencies that we have extracted from the contents.
use super::structs::{Dependency, VersionStatus};

use lazy_static::lazy_static;
use pep_508::{self, Spec};
use regex::Regex;

use toml::{de::Error, Table, Value};

pub fn extract_imports_python(text: String, imp: &mut Vec<Dependency>) {
    lazy_static! {
        static ref IMPORT_REGEX: Regex =
            Regex::new(r"^\s*(?:from|import)\s+(\w+(?:\s*,\s*\w+)*)").unwrap();
    }

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
    // you might think its just a text file, but I'm gonna decline reinventing the wheel
    // just to parse "requests >= 2.0.8"

    let parsed = pep_508::parse(text.as_str());

    if let Ok(ref dep) = parsed {
        let dname = dep.name.to_string();
        // println!("{:?}", parsed.clone());
        if let Some(ver) = &dep.spec {
            if let Spec::Version(verspec) = ver {
                if let Some(v) = verspec.iter().next() {
                    // pyscan only takes the first version spec found for the dependency
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

// pub fn extract_imports_pyproject(f: String, imp: &mut Vec<Dependency>) {
//     let parsed = f.parse::<Table>();
//     if let Ok(parsed) = parsed {
//         let project = &parsed["project"];
//         let deps = &project["dependencies"];
//         let deps = deps
//             .as_array()
//             .expect("Could not find the dependencies table in your pyproject.toml");
//         for d in deps {
//             let d = d.as_str().unwrap();
//             let parsed = pep_508::parse(d);
//             if let Ok(dep) = parsed {
//                 let dname = dep.name.to_string();
//                 // println!("{:?}", dep.clone());
//                 if let Some(ver) = dep.spec {
//                     if let Spec::Version(verspec) = ver {
//                         for v in verspec {
//                             // pyscan only takes the first version spec found for the dependency
//                             // for now.
//                             let version = v.version.to_string();
//                             let comparator = v.comparator;
//                             imp.push(Dependency {
//                                 name: dname,
//                                 version: Some(version),
//                                 comparator: Some(comparator),
//                                 version_status: VersionStatus {
//                                     pypi: false,
//                                     pip: false,
//                                     source: true,
//                                 },
//                             });
//                             break;
//                         }
//                     }
//                 } else {
//                     imp.push(Dependency {
//                         name: dname,
//                         version: None,
//                         comparator: None,
//                         version_status: VersionStatus {
//                             pypi: false,
//                             pip: false,
//                             source: false,
//                         },
//                     });
//                 }
//             }
//         }
//     }
// }

pub fn extract_imports_setup_py(setup_py_content: &str, imp: &mut Vec<Dependency>) {
    let mut deps = Vec::new();

    // regex for install_requires section
    let re = Regex::new(r"install_requires\s*=\s*\[([^\]]+)\]").expect("Invalid regex pattern");

    for cap in re.captures_iter(setup_py_content) {
        if let Some(matched) = cap.get(1) {
            // Split the matched text by ',' and trim whitespace
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
                        // pyscan only takes the first version spec found for the dependency
                        // for now.
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
    // Parse the toml content into a Value
    let toml_value: Value = toml::from_str(toml_content.as_str())?;
    // println!("{:#?}",toml_value);

    // Helper function to extract dependency values (version strings) including nested tables
    fn extract_dependencies(
        table: &toml::value::Table,
        poetry: Option<bool>,
    ) -> Result<Vec<String>, Error> {
        let mut deps = Vec::new();

        // for [project] in pyproject.toml, the insides require a different sort of parsing
        // for poetry you need both keys and values (as dependency name and version),
        // for [project] the values are just enough and the keys are in the vec below
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
                            // Recursively extract dependencies from nested tables
                            let nested_deps = extract_dependencies(nested_table, None)?;
                            deps.extend(nested_deps);
                        }
                    }
                    Value::Array(array) => {
                        // Extract dependencies from an array (if any)
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
                        // Recursively extract dependencies from nested tables
                        let nested_deps = extract_dependencies(nested_table, None)?;
                        deps.extend(nested_deps);
                    }
                    Value::Array(array) => {
                        // Extract dependencies from an array (if any)
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

    // Look for keys like "dependencies" and "optional-dependencies"
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
                                // its definitely gonna be a table anyway, so...
                                Value::String(_) => todo!(),
                                Value::Integer(_) => todo!(),
                                Value::Float(_) => todo!(),
                                Value::Boolean(_) => todo!(),
                                Value::Datetime(_) => todo!(),
                                Value::Array(_) => todo!(),
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
                "The pyproject.toml seen here is unlike of a python project. Please check and make
            sure you are in the right directory, or check the toml file."
            );
            exit(1)
        }
    }
    // the toml might contain repeated dependencies
    // for different tools, dev tests, etc.
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
                    match d {
                        Value::String(dependency) => {
                            deps.push(dependency.to_owned());
                        }
                        Value::Integer(_) => todo!(),
                        Value::Float(_) => todo!(),
                        Value::Boolean(_) => todo!(),
                        Value::Datetime(datetime) => todo!(),
                        Value::Array(vec) => todo!(),
                        Value::Table(map) => todo!(),
                    }
                }
            }
            Value::String(_) => todo!(),
            Value::Integer(_) => todo!(),
            Value::Float(_) => todo!(),
            Value::Boolean(_) => todo!(),
            Value::Datetime(datetime) => todo!(),
            Value::Table(map) => todo!(),
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
                    // Also handle inline table string representation
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
    let mut dep_specs: Vec<(String, Option<String>)> = Vec::new(); // (name, specifier)

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
            // No specifier — try resolved version from lockfile
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

    // Try to parse as PEP 508 comparator + version
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

    // For pinned versions (==), use the specifier version directly.
    // For range specifiers (>=, etc.), prefer the resolved lockfile version
    // because it represents the actual installed version.
    match comparator {
        Some(pep_508::Comparator::Eq) => (version_str, comparator),
        Some(_) => {
            // Use resolved version from lockfile if available, otherwise use specifier version
            let resolved = resolved_versions.get(name).cloned().or(version_str);
            (resolved, comparator)
        }
        None => {
            let resolved = resolved_versions.get(name).cloned();
            (resolved, None)
        }
    }
}
