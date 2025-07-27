use chrono::{Timelike, Utc};
use reqwest::{
    self,
    {Client, Response},
    Method,
};
use semver::Version;
use std::{
    boxed::Box,
    collections::HashMap,
    io::{self, Error, ErrorKind},
    str::{self},
};
use dirs;

pub fn get_time() -> String {
    // get the current time in a stting format i like.
    let now = Utc::now();
    let (is_pm, hour) = now.hour12();
    {
        let time = format!(
            "{:02}:{:02}:{:02} {}",
            hour,
            now.minute(),
            now.second(),
            if is_pm { "PM" } else { "AM" }
        );

        time
    }
}

pub fn get_version() -> String {
    "0.1.8".to_string()
}

pub fn get_vuln_ignores() -> Vec<String> {
    // returns a vector of vuln IDs to ignore from the .pyscanignore file either in the current directory or the config directory.
    // this is used to ignore vulns that are not relevant to the project.
    // check if the file exists in the current directory first, then check the config directory.
    // if the file exists, read the file and return a vector of strings.
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

pub async fn _reqwest_send(method: &str, url: String) -> Option<Response> {
    // for easily sending web requests

    let client = reqwest::Client::builder()
        .user_agent(format!("pyscan v{}", get_version()))
        .build();

    if let Ok(client) = client {
        let method = match method {
            "get" => Method::GET,
            "post" => Method::POST,
            "put" => Method::PUT,
            "head" => Method::HEAD,
            "connect" => Method::CONNECT,
            "trace" => Method::TRACE,
            &_ => {
                println!("Didn't recognize that method so defaulting to GET");
                Method::GET
            }
        };
        let res = client.request(method, url).send().await;

        if let Ok(success) = res {
            Some(success)
        } else {
            eprintln!(
                "Could not establish an internet connection. Check your internet or try again."
            );  exit(1)
        }
    } else {
        eprintln!("Could not build the network client. Report this at https://github.com/ohaswin/pyscan/issues");
        None
    }
}

use std::process::{exit, Command};

use crate::{parser::structs::Dependency, scanner::models::PypiResponse, PIPCACHE};
// Define a custom error type that wraps a String message
#[derive(Debug)]
pub struct PipError(String);

// Implement the std::error::Error trait for DockerError
impl std::error::Error for PipError {}

// Implement the std::fmt::Display trait for DockerError
impl std::fmt::Display for PipError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Pip error: {}", self.0)
    }
}

pub fn get_python_package_version(package: &str) -> Result<String, PipError> {
    // gets the version of a package from pip.

    // check cache first
    if PIPCACHE.cached {
        let version = PIPCACHE
            .lookup(package)
            .map_err(|e| PipError(e.to_string()))?;
        Ok(version)
    } else {
        let output = Command::new("pip")
            .arg("show")
            .arg(package)
            .output()
            .map_err(|e| PipError(e.to_string()))?;

        let output = output.stdout;
        let output = String::from_utf8(output).map_err(|e| PipError(e.to_string()))?;

        let version = output
            .lines()
            .find(|line| line.starts_with("Version: "))
            .map(|line| line[9..].to_string());

        if let Some(v) = version {
            Ok(v)
        } else {
            Err(PipError(
                "could not retrive package version from Pip".to_string(),
            ))
        }
    }
}

#[derive(Debug)]
pub struct PypiError(String);

// Implement the std::error::Error trait for PypiError
impl std::error::Error for PypiError {}

// Implement the std::fmt::Display trait for PypiError
impl std::fmt::Display for PypiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pypi.org error: {}\n\n(note: this might usually happen when the dependency does not exist on pypi [check spelling, typos, etc] or when there's problems accessing the website.)", self.0)
    }
}

impl From<reqwest::Error> for PypiError {
    fn from(item: reqwest::Error) -> Self {
        PypiError(item.to_string())
    }
}

pub async fn get_package_version_pypi<'a>(package: &str) -> Result<Box<String>, PypiError> {
    let url = format!("https://pypi.org/pypi/{package}/json");

    let client = Client::new();
    let res = client.get(url).send().await?.error_for_status();

    let version = if let Err(e) = res {
        eprintln!("Failed to make a request to pypi.org:\n{}", e);
        Err(PypiError(e.to_string()))
    } else if let Ok(r) = res {
        let restext = r.text().await;
        let restext = if let Ok(r) = restext {
            r
        } else {
            return Err(PypiError("Failed to connect to pypi.org".to_string()));
        };
        // println!("{:#?}", restext.clone());

        let parsed: Result<PypiResponse, serde_json::Error> = serde_json::from_str(restext.trim());

        let version = if let Err(e) = parsed {
            eprintln!("Failed to parse reponse from pypi.org:\n{}", e);
            Err(PypiError(e.to_string()))
        } else if let Ok(pypi) = parsed {
            let strvers: Vec<String> = pypi.releases.into_keys().collect(); // versions in string
            let mut somever: Vec<Version> = semver_parse(strvers);
            somever.sort();
            Ok(somever.last().unwrap().to_owned())
        } else {
            Err(PypiError("pypi.org response error".to_string()))
        };
        version
    } else if res.is_err() {
        let _ = res.map_err(|e| PypiError(e.to_string()));
        exit(1)
    } else {
        exit(1)
    };

    Ok(Box::new(if let Err(e) = version {
        eprintln!("{e}");
        exit(1)
    } else {
        version.unwrap().to_string()
    }))
}

// creates a hashmap of package name,version from pip list.
pub fn pip_list() -> io::Result<HashMap<String, String>> {
    let output = Command::new("pip")
        .arg("list")
        .output()
        .map_err(|_| io::Error::new(ErrorKind::Other, "Failed to execute 'pip list' command. pyscan caches the dependencies from pip with versions to be faster and it could not run 'pip list'. You can turn this off via just using --cache-off [note: theres a chance pyscan might still fallback to using pip]"))?;

    let output_str = str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Output from 'pip list' was not valid UTF-8. pyscan caches the dependencies from pip with versions to be faster and the output it recieved was not valid UTF-8. You can turn this off via just using --cache-off [note: theres a chance pyscan might still fallback to using pip]"))?;

    let mut pip_list: HashMap<String, String> = HashMap::new();

    for line in output_str.lines().skip(2) {
        // Skip the first two lines
        let split: Vec<&str> = line.split_whitespace().collect();
        if split.len() >= 2 {
            pip_list.insert(split[0].to_string(), split[1].to_string());
        }
    }

    Ok(pip_list)
}

pub fn semver_parse(v: Vec<String>) -> Vec<Version> {
    let mut cache: Vec<Version> = Vec::new();
    for x in v {
        let version = lenient_semver::Version::parse(x.as_str()).unwrap();
        let b = Version::from(version);
        cache.push(b)
    }
    cache
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
    cached: bool,
}

impl PipCache {
    // initializes the cache, caches and returns itself.
    pub fn init() -> PipCache {
        let pip_list = pip_list();
        if let Ok(pl) = pip_list {
            PipCache {
                cache: pl,
                cached: true,
            }
        } else if let Err(e) = pip_list {
            eprintln!("{e}");
            exit(1)
        } else {
            exit(1)
        }
    }

    // clears if cached, otherwise does nothing
    pub fn _clear_cache(&mut self) {
        if !self.cached {
        } else {
            self.cache.clear()
        }
    }

    // Function to look up a package by name in cache
    pub fn lookup(&self, package_name: &str) -> io::Result<String> {
        match self.cache.get(package_name) {
            Some(version) => Ok(version.to_string()),
            None => Err(Error::new(ErrorKind::NotFound, "Package not found in pip")),
        }
    }
}

// useful info to have during the entire execution of the program.
pub struct SysInfo {
    pub pip_found: bool,
    pub pypi_found: bool,
}

impl SysInfo {
    pub async fn new() -> SysInfo {
        let pip_found: bool = pip_list().is_ok();
        let pypi_found: bool =  check_pypi_status().await;

        SysInfo {
            pip_found,
            pypi_found,
        }
    }
}

pub async fn check_pypi_status() ->  bool {
    let r = _reqwest_send("get", "https://pypi.org".to_string()).await.ok_or(());
    if let Ok(res) = r {
        res.status().is_success()
    }
    else {
        false
    }
}