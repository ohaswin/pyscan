use console::style;
use std::{ffi::OsString, process::exit};

use crate::{scanner::models::Query, utils, ARGS};

use super::scanner::models::Vulnerability;

// struct Python;
// struct Requirements;
// struct Pyproject;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FileTypes {
    Python,
    Requirements,
    Pyproject,
    Constraints,
    SetupPy,
}

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub name: OsString,
    pub filetype: FileTypes,
    pub path: OsString,
}

impl FoundFile {
    pub fn is_python(&self) -> bool {
        self.filetype == FileTypes::Python
    }
    pub fn is_reqs(&self) -> bool {
        self.filetype == FileTypes::Requirements
    }
    pub fn is_pyproject(&self) -> bool {
        self.filetype == FileTypes::Pyproject
    }
    pub fn is_setuppy(&self) -> bool {
        self.filetype == FileTypes::SetupPy
    }
}

#[derive(Debug, Clone)]
pub struct FoundFileResult {
    /// provides overall info about the files found (useful for proritising filetypes)
    pub files: Vec<FoundFile>,
    pub py_found: u64, // no. of said files found
    pub reqs_found: u64,
    pub pyproject_found: u64,
    pub constraints_found: u64,
    pub setuppy_found: u64
}

impl FoundFileResult {
    pub fn new() -> FoundFileResult {
        FoundFileResult {
            files: Vec::new(),
            py_found: 0,
            reqs_found: 0,
            pyproject_found: 0,
            constraints_found: 0,
            setuppy_found: 0,
        }
    }
    pub fn add(&mut self, f: FoundFile) {
        self.files.push(f)
    }
    pub fn python(&mut self) {
        self.py_found += 1
    }
    pub fn reqs(&mut self) {
        self.reqs_found += 1
    }
    pub fn pyproject(&mut self) {
        self.pyproject_found += 1
    }
    pub fn constraints(&mut self) {
        self.constraints_found += 1
    }
    pub fn setuppy(&mut self) {
        self.setuppy_found += 1
    }
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    pub comparator: Option<pep_508::Comparator>,
    pub version_status: VersionStatus,
}

impl Dependency {
    pub fn to_query(&self) -> Query {
        Query::new(self.version.as_ref().unwrap().as_str(), self.name.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct VersionStatus {
    // pyscan may get version info from a lot of places. This keeps it in check.
    pub pypi: bool,
    pub pip: bool,
    pub source: bool,
}

/// implementation for VersionStatus which can get return versions while updating the status, also pick the one decided via arguments, a nice abstraction really.
impl VersionStatus {
    /// retreives versions from pip and pypi.org in (pip, pypi) format.
    pub async fn _full_check(&mut self, name: &str) -> (String, String) {
        let pip = utils::get_python_package_version(name);
        let pip_v = if let Err(e) = pip {
            println!("An error occurred while retrieving version info from pip.\n{e}");
            exit(1)
        } else {
            pip.unwrap()
        };

        let pypi = utils::get_package_version_pypi(name).await;
        let pypi_v = if let Err(e) = pypi {
            println!("An error occurred while retrieving version info from pypi.org.\n{e}");
            exit(1)
        } else {
            *pypi.unwrap()
        };

        self.pip = true;
        self.pypi = true;

        (pip_v, pypi_v)
    }

    pub fn pip(name: &str) -> String {
        let pip = utils::get_python_package_version(name);

        if let Err(e) = pip {
            println!("An error occurred while retrieving version info from pip.\n{e}");
            exit(1)
        } else {
            pip.unwrap()
        }
    }

    pub async fn pypi(name: &str) -> String {
        let pypi = utils::get_package_version_pypi(name).await;

        if let Err(e) = pypi {
            println!("An error occurred while retrieving version info from pypi.org.\n{e}");
            exit(1)
        } else {
            *pypi.unwrap()
        }
    }

    /// returns the chosen version (from args or fallback)
    pub async fn choose(name: &str, dversion: &Option<String>) -> String {
        if ARGS.get().unwrap().pip {
            VersionStatus::pip(name)
        } else if ARGS.get().unwrap().pypi {
            VersionStatus::pypi(name).await
        } else {
            // fallback begins here once made sure no arguments are provided
            let d_version = if let Some(provided) = dversion {
                Some(provided.to_string())
            } else if let Ok(v) = utils::get_python_package_version(name) {
                println!("{} : {}",style(name).yellow().dim(), style("A version could not be detected in the source file, so retrieving version from pip instead.").dim());
                Some(v)
            } else if let Ok(v) = utils::get_package_version_pypi(name).await {
                println!("{} : {}",style(name).red().dim(), style("A version could not be detected through source or pip, so retrieving latest version from pypi.org instead.").dim());
                Some(v.to_string())
            } else {
                eprintln!("A version could not be retrieved for {}. This should not happen as pyscan defaults pip or pypi.org, unless:\n1) Pip is not installed\n2) You don't have an internet connection\n3) You did not anticipate the consequences of not specifying a version for your dependency in the configuration files.\nReach out on github.com/ohaswin/pyscan/issues if the above cases did not take place.", style(name).bright().red());
                exit(1);
            };
            d_version.unwrap()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScannedDependency {
    pub name: String,
    pub version: String,
    pub vuln: Vulnerability,
}
