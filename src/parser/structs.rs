use std::path::PathBuf;

use crate::{scanner::models::Query, utils, ARGS};

use super::scanner::models::Vulnerability;

// added partialord/ord to be used for sorting
// order matters
#[derive(Debug, PartialEq, Eq, Clone, Hash, Ord, PartialOrd)]
pub enum FileTypes {
    Requirements, // high, 0
    Constraints,
    UvLock,
    CycloneDx,
    Spdx,
    Pyproject,
    SetupPy,
    Python, // low, 7
}

impl FileTypes {
    pub fn file_name_to_type(file_name: &str) -> Option<FileTypes> {
        let f = match file_name {
            "setup.py" => FileTypes::SetupPy,
            "requirements.txt" => FileTypes::Requirements,
            "constraints.txt" => FileTypes::Constraints,
            "pyproject.toml" => FileTypes::Pyproject,
            "uv.lock" => FileTypes::UvLock,
            "bom.json" | "cyclonedx.json" => FileTypes::CycloneDx,
            "spdx.json" | "bom.spdx.json" => FileTypes::Spdx,
            x if x.ends_with(".py") => FileTypes::Python,
            _ => return None,
        };
        Some(f)
    }
}

#[derive(Debug, Clone)]
pub struct FoundFile {
    pub name: String,
    pub filetype: FileTypes,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FoundFileResult {
    /// provides overall info about the files found (useful for prioritising filetypes)
    pub files: Vec<FoundFile>,
    pub priority_file_type: Option<FileTypes>,
}

impl FoundFileResult {
    pub fn new() -> FoundFileResult {
        FoundFileResult {
            files: Vec::new(),
            priority_file_type: None,
        }
    }

    pub fn add(&mut self, f: FoundFile) {
        if self.priority_file_type.is_none()
            || &f.filetype < self.priority_file_type.as_ref().unwrap()
        // prirotiy file not set or priority of current filetype is less than new filetype
        {
            self.priority_file_type = Some(f.filetype.clone());
            self.files.clear();
        }
        if &f.filetype == self.priority_file_type.as_ref().unwrap() {
            self.files.push(f);
        }
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

/// implementation for VersionStatus which can get return versions while updating the status, also pick the one decided via arguments, a nice abstraction really.
impl VersionStatus {
    /// retrieves versions from pip and pypi.org in (pip, pypi) format.
    pub async fn _full_check(&mut self, name: &str) -> crate::error::Result<(String, String)> {
        let pip_v = utils::get_python_package_version(name)?;
        let pypi_v = utils::get_package_version_pypi(name).await?;
        self.pip = true;
        self.pypi = true;
        Ok((pip_v, pypi_v))
    }

    pub fn pip(name: &str) -> crate::error::Result<String> {
        utils::get_python_package_version(name)
    }

    pub async fn pypi(name: &str) -> crate::error::Result<String> {
        utils::get_package_version_pypi(name).await
    }

    /// returns the chosen version (from args or fallback)
    pub async fn choose(name: &str, dversion: &Option<String>) -> String {
        if ARGS.get().unwrap().pip {
            match VersionStatus::pip(name) {
                Ok(v) => return v,
                Err(e) => {
                    eprintln!("An error occurred while retrieving version info from pip.\n{e}");
                    // fallthrough to pypi
                }
            }
        } else if ARGS.get().unwrap().pypi {
            match VersionStatus::pypi(name).await {
                Ok(v) => return v,
                Err(e) => {
                    eprintln!(
                        "An error occurred while retrieving version info from pypi.org.\n{e}"
                    );
                    // fallthrough
                }
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

#[cfg(test)]
mod tests {
    use super::{FileTypes, FoundFile, FoundFileResult};
    use std::path::PathBuf;

    #[test]
    fn add_keeps_files_with_same_priority_type() {
        let mut result = FoundFileResult::new();

        result.add(FoundFile {
            name: "requirements.txt".to_string(),
            filetype: FileTypes::Requirements,
            path: PathBuf::from("requirements.txt"),
        });
        result.add(FoundFile {
            name: "dev-requirements.txt".to_string(),
            filetype: FileTypes::Requirements,
            path: PathBuf::from("dev-requirements.txt"),
        });

        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[0].name, "requirements.txt");
        assert_eq!(result.files[1].name, "dev-requirements.txt");
    }

    #[test]
    fn add_ignores_lower_priority_file_types() {
        let mut result = FoundFileResult::new();

        result.add(FoundFile {
            name: "requirements.txt".to_string(),
            filetype: FileTypes::Requirements,
            path: PathBuf::from("requirements.txt"),
        });
        result.add(FoundFile {
            name: "setup.py".to_string(),
            filetype: FileTypes::SetupPy,
            path: PathBuf::from("setup.py"),
        });

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].name, "requirements.txt");
        assert_eq!(result.files[0].filetype, FileTypes::Requirements);
    }

    #[test]
    fn add_replaces_files_when_higher_priority_type_is_seen() {
        let mut result = FoundFileResult::new();

        result.add(FoundFile {
            name: "main.py".to_string(),
            filetype: FileTypes::Python,
            path: PathBuf::from("main.py"),
        });
        result.add(FoundFile {
            name: "requirements.txt".to_string(),
            filetype: FileTypes::Requirements,
            path: PathBuf::from("requirements.txt"),
        });

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].name, "requirements.txt");
        assert_eq!(result.files[0].filetype, FileTypes::Requirements);
    }
}
