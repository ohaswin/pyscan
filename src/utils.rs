use chrono::{Timelike, Utc};
use reqwest::{
    self,
    {Client, Response},
    Method,
};
use semver::Version;
use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    str::{self},
    time,
};
use dirs;

use crate::{parser::structs::Dependency, scanner::models::PypiResponse, error::PyscanError, PIPCACHE};

pub fn get_time() -> String {
    let now = Utc::now();
    let (is_pm, hour) = now.hour12();
    format!(
        "{:02}:{:02}:{:02} {}",
        hour,
        now.minute(),
        now.second(),
        if is_pm { "PM" } else { "AM" }
    )
}

pub fn get_version() -> String {
    "2.0.0".to_string()
}

pub fn get_vuln_ignores() -> Vec<String> {
    let mut ignores: Vec<String> = Vec::new();
    let current_dir = std::env::current_dir().unwrap();
    let current_path = current_dir.join(".pyscanignore");
    if current_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(current_path) {
            ignores.extend(contents.lines().map(|s| s.to_string()));
        } else {
            eprintln!("Could not read the .pyscanignore file in the current directory. Ignoring it.");
        }
    } else {
        let config_path = dirs::config_dir().unwrap().join("pyscan").join(".pyscanignore");
        if config_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(config_path) {
                ignores.extend(contents.lines().map(|s| s.to_string()));
            } else {
                eprintln!("Could not read the .pyscanignore file in the config directory. Ignoring it.");
            }
        } else {
            return ignores;
        }
    }

    ignores
}

pub async fn _reqwest_send(method: &str, url: String) -> crate::error::Result<Response> {
    let client = reqwest::Client::builder()
        .user_agent(format!("pyscan v{}", get_version()))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| PyscanError::Network { source: e })?;

    let method = match method {
        "get" => Method::GET,
        "post" => Method::POST,
        "put" => Method::PUT,
        "head" => Method::HEAD,
        "connect" => Method::CONNECT,
        "trace" => Method::TRACE,
        _ => {
            println!("Didn't recognize that method so defaulting to GET");
            Method::GET
        }
    };

    let response = client.request(method, url).send().await
        .map_err(|e| PyscanError::Network { source: e })?;

    Ok(response)
}

pub fn get_python_package_version(package: &str) -> Result<String, PyscanError> {
    // check cache first
    if PIPCACHE.cached {
        let version = PIPCACHE
            .lookup(package)
            .map_err(|e| PyscanError::Pip(e.to_string()))?;
        Ok(version)
    } else {
        let output = std::process::Command::new("pip")
            .arg("show")
            .arg(package)
            .output()
            .map_err(|e| PyscanError::Pip(e.to_string()))?;

        let output = String::from_utf8(output.stdout)
            .map_err(|e| PyscanError::Pip(e.to_string()))?;

        let version = output
            .lines()
            .find(|line| line.starts_with("Version: "))
            .map(|line| line[9..].to_string());

        version.ok_or_else(|| PyscanError::Pip(
            "could not retrieve package version from Pip".to_string(),
        ))
    }
}

pub async fn get_package_version_pypi(package: &str) -> Result<String, PyscanError> {
    let url = format!("https://pypi.org/pypi/{package}/json");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| PyscanError::Pypi(e.to_string()))?;

    let response = client.get(&url)
        .send().await
        .map_err(|e| PyscanError::Pypi(e.to_string()))?
        .error_for_status()
        .map_err(|e| PyscanError::Pypi(e.to_string()))?;

    let body = response.text().await
        .map_err(|e| PyscanError::Pypi(format!("Failed to read pypi.org response: {e}")))?;

    let pypi: PypiResponse = serde_json::from_str(body.trim())
        .map_err(|e| PyscanError::Pypi(format!("Failed to parse pypi.org response: {e}")))?;

    let strvers: Vec<String> = pypi.releases.into_keys().collect();
    let mut somever: Vec<Version> = semver_parse(&strvers);
    somever.sort();

    somever.last()
        .map(|v| v.to_string())
        .ok_or_else(|| PyscanError::Pypi(format!("No versions found for {package}")))
}

pub fn pip_list() -> io::Result<HashMap<String, String>> {
    let output = std::process::Command::new("pip")
        .arg("list")
        .output()
        .map_err(|_| io::Error::new(ErrorKind::Other, "Failed to execute 'pip list' command. pyscan caches the dependencies from pip with versions to be faster and it could not run 'pip list'. You can turn this off via just using --cache-off [note: theres a chance pyscan might still fallback to using pip]"))?;

    let output_str = str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Output from 'pip list' was not valid UTF-8. pyscan caches the dependencies from pip with versions to be faster and the output it recieved was not valid UTF-8. You can turn this off via just using --cache-off [note: theres a chance pyscan might still fallback to using pip]"))?;

    let mut pip_list: HashMap<String, String> = HashMap::new();

    for line in output_str.lines().skip(2) {
        let split: Vec<&str> = line.split_whitespace().collect();
        if split.len() >= 2 {
            pip_list.insert(split[0].to_string(), split[1].to_string());
        }
    }

    Ok(pip_list)
}

pub fn semver_parse(versions: &[String]) -> Vec<Version> {
    versions.iter()
        .filter_map(|v| lenient_semver::Version::parse(v).ok())
        .map(Version::from)
        .collect()
}

/// returns a hashmap<string, string> of (dependency name, version)
pub fn vecdep_to_hashmap(v: &[Dependency]) -> HashMap<String, String> {
    let mut importmap: HashMap<String, String> = HashMap::new();

    v.iter().for_each(|d| {
        importmap.insert(d.name.clone(), d.version.as_ref().unwrap().clone());
    });

    importmap
}

/// caches package name, version data from 'pip list' in a hashmap for efficient lookup later.
pub struct PipCache {
    cache: HashMap<String, String>,
    pub cached: bool,
}

impl PipCache {
    pub fn init() -> PipCache {
        match pip_list() {
            Ok(pl) => PipCache {
                cache: pl,
                cached: true,
            },
            Err(e) => {
                eprintln!("{e}");
                PipCache {
                    cache: HashMap::new(),
                    cached: false,
                }
            }
        }
    }

    pub fn _clear_cache(&mut self) {
        if self.cached {
            self.cache.clear()
        }
    }

    pub fn lookup(&self, package_name: &str) -> io::Result<String> {
        match self.cache.get(package_name) {
            Some(version) => Ok(version.to_string()),
            None => Err(Error::new(ErrorKind::NotFound, "Package not found in pip")),
        }
    }
}

pub struct SysInfo {
    pub pip_found: bool,
    pub pypi_found: bool,
}

impl SysInfo {
    pub async fn new() -> SysInfo {
        let pip_found: bool = pip_list().is_ok();
        let pypi_found: bool = check_pypi_status().await;

        SysInfo {
            pip_found,
            pypi_found,
        }
    }
}

pub async fn check_pypi_status() -> bool {
    match _reqwest_send("get", "https://pypi.org".to_string()).await {
        Ok(res) => res.status().is_success(),
        Err(_) => false,
    }
}