use std::collections::HashMap;
use std::ffi::OsString;

use crate::{scanner::models::Query, utils, ARGS};

use super::scanner::models::Vulnerability;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum FileTypes {
    Python,
    Requirements,
    Pyproject,
    Constraints,
    SetupPy,
    UvLock,
    CycloneDx,
    Spdx,
}

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub name: OsString,
    pub filetype: FileTypes,
    pub path: OsString,
}

#[derive(Debug, Clone)]
pub struct FoundFileResult {
    /// provides overall info about the files found (useful for prioritising filetypes)
    pub files: Vec<FoundFile>,
    counts: HashMap<FileTypes, u64>,
}

impl FoundFileResult {
    pub fn new() -> FoundFileResult {
        FoundFileResult {
            files: Vec::new(),
            counts: HashMap::new(),
        }
    }

    pub fn add(&mut self, f: FoundFile) {
        *self.counts.entry(f.filetype.clone()).or_insert(0) += 1;
        self.files.push(f);
    }

    pub fn count(&self, ft: &FileTypes) -> u64 {
        self.counts.get(ft).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    #[allow(dead_code)]
    pub comparator: Option<pep_508::Comparator>,
    #[allow(dead_code)]
    pub version_source: VersionSource,
}

impl Dependency {
    pub fn to_query(&self) -> Query {
        Query::new(self.version.as_ref().unwrap().as_str(), self.name.as_str())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum VersionSource {
    Pypi,
    Pip,
    Code,
    None,
}

/// returns the chosen version (from args or fallback)
pub async fn choose(name: &str) -> String {
    if ARGS.get().unwrap().pip || !ARGS.get().unwrap().pypi {
        match utils::get_python_package_version(name) {
            Ok(v) => return v,
            Err(e) => {
                eprintln!("An error occurred while retrieving version info from pip.\n{e}");
                // fallthrough to pypi
            }
        }
    }
    match utils::get_package_version_pypi(name).await {
        Ok(v) => return v,
        Err(e) => {
            eprintln!("An error occurred while retrieving version info from pypi.org.\n{e}");
            // fallthrough
        }
    }
    eprintln!("A version could not be retrieved for \x1b[1;91m{}\x1b[0m. This should not happen as pyscan defaults pip or pypi.org, unless:\n1) Pip is not installed\n2) You don't have an internet connection\n3) You did not anticipate the consequences of not specifying a version for your dependency in the configuration files.\nReach out on github.com/ohaswin/pyscan/issues if the above cases did not take place.", name);
    String::new()
}

#[derive(Debug, Clone)]
pub struct ScannedDependency {
    pub name: String,
    pub version: String,
    pub vuln: Vulnerability,
}
