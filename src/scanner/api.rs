use crate::{display, ARGS, VULN_IGNORE};
/// provides the functions needed to connect to various advisory sources.
use crate::{parser::structs::Dependency, scanner::models::Vulnerability};
use crate::{
    parser::structs::{ScannedDependency, VersionStatus},
    scanner::models::Vuln,
    error::PyscanError,
};
use reqwest::{self, Client, Method};
use futures::future;
use std::{fs, env, time::Instant};
use super::{
    super::utils,
    models::{Query, QueryBatched, QueryResponse},
};
use display::SourceContext;

/// OSV provides a distributed database for vulns, with a free API
#[derive(Debug)]
pub struct Osv {
    /// check if the host is online
    pub online: bool,
    /// time of last query
    pub last_queried: String,
    /// the Client which handles the API.
    client: Client,
}

impl Osv {
    pub async fn new() -> crate::error::Result<Osv> {
        let version = utils::get_version();
        let pyscan_version = format!("pyscan {}", version);
        let client = reqwest::Client::builder()
            .user_agent(pyscan_version)
            .build()
            .map_err(|e| PyscanError::Osv(format!("Could not build the network client: {e}")))?;

        client.get("https://osv.dev").send().await
            .map_err(|e| PyscanError::Osv(format!("Could not connect to the OSV website. Check your internet or try again: {e}")))?;

        Ok(Osv {
            online: true,
            last_queried: utils::get_time(),
            client,
        })
    }

    pub async fn _query(&self, d: Dependency) -> crate::error::Result<Option<Vulnerability>> {
        let version = match d.version {
            Some(v) => v,
            None => {
                utils::get_package_version_pypi(d.name.as_str()).await?
            }
        };

        Ok(self._get_json(d.name.as_str(), &version).await)
    }

    pub async fn query_batched(&self, mut deps: Vec<Dependency>, source: Option<SourceContext>) -> crate::error::Result<Vec<ScannedDependency>> {
        // Resolve missing versions in parallel
        let _ = future::join_all(deps
            .iter_mut()
            .map(|d| async {
                d.version = if d.version.is_none() {
                    Some(VersionStatus::choose(d.name.as_str(), &d.version).await)
                } else {
                    d.version.clone()
                }
            })).await;

        let bar = display::create_scan_progress(deps.len());
        let scan_start = Instant::now();

        let imports_info = utils::vecdep_to_hashmap(&deps);

        let url = "https://api.osv.dev/v1/querybatch";

        let queries: Vec<Query> = deps.iter().map(|d| d.to_query()).collect();
        let batched = QueryBatched::new(queries);

        let body = serde_json::to_string(&batched)
            .map_err(|e| PyscanError::Json { source: e })?;

        let response = self.client.request(Method::POST, url).body(body).send().await
            .map_err(|e| PyscanError::Osv(format!("Could not fetch a response from osv.dev: {e}")))?;

        if response.status().is_client_error() {
            return Err(PyscanError::Osv("Failed connecting to OSV. [Client error]".to_string()));
        } else if response.status().is_server_error() {
            return Err(PyscanError::Osv("Failed connecting to OSV. [Server error]".to_string()));
        }

        let restext = response.text().await
            .map_err(|e| PyscanError::Osv(format!("Failed to read OSV response: {e}")))?;

        let mut scanneddeps: Vec<ScannedDependency> = Vec::new();

        // Handle --output flag for JSON export
        if ARGS.get().unwrap().output.is_some() {
            let filename = ARGS.get().unwrap().output.as_ref().unwrap();
            if filename.ends_with(".json") {
                if let Ok(dir) = env::current_dir() {
                    fs::write(dir.join(filename), &restext)
                        .map_err(|e| PyscanError::Io { source: e })?;
                    return Ok(scanneddeps);
                }
            }
        }

        let parsed: QueryResponse = serde_json::from_str(&restext)
            .map_err(|e| PyscanError::Osv(format!(
                "Invalid parse of API response at scanner/api::query_batched\nThis is usually due to an unforeseen API response or a malformed source file.\n{e}"
            )))?;

        let mut imports_info = imports_info;

        for vres in parsed.results {
            if let Some(vulns) = vres.vulns {
                // Filter vuln IDs to fetch
                let ids_to_fetch: Vec<&str> = vulns.iter()
                    .filter(|qv| {
                        !(VULN_IGNORE.contains(&qv.id) || ARGS.get().unwrap().ignorevulns.contains(&qv.id))
                            || ARGS.get().unwrap().pedantic
                    })
                    .map(|qv| qv.id.as_str())
                    .collect();

                // Log ignored vulns
                for qv in vulns.iter() {
                    if (VULN_IGNORE.contains(&qv.id) || ARGS.get().unwrap().ignorevulns.contains(&qv.id))
                        && !ARGS.get().unwrap().pedantic
                    {
                        println!("Ignoring vuln with ID: {}", qv.id);
                    }
                }

                // Fetch vuln details in parallel
                let vecvulns: Vec<Vuln> = future::join_all(
                    ids_to_fetch.iter().map(|id| self.vuln_id(id))
                ).await
                .into_iter()
                .filter_map(|r| r.ok())
                .collect();

                let structvuln = Vulnerability { vulns: vecvulns };
                if let Some(ref b) = bar { b.inc(1); }

                if structvuln.vulns.is_empty() {
                    continue;
                }
                scanneddeps.push(structvuln.to_scanned_dependency(&imports_info));
            }
        }

        display::finish_progress(bar, scanneddeps.len());

        let scan_duration = scan_start.elapsed();

        // --- passing to display module starts here ---
        display::display_results(
            &scanneddeps,
            &mut imports_info,
            source.as_ref(),
            scan_duration,
        );
        Ok(scanneddeps)
    }

    /// get a Vuln from a vuln ID from OSV
    pub async fn vuln_id(&self, id: &str) -> crate::error::Result<Vuln> {
        let url = format!("https://api.osv.dev/v1/vulns/{id}");

        let response = self.client.request(Method::GET, url).send().await
            .map_err(|e| PyscanError::Osv(format!("Could not fetch a response from osv.dev [vuln_id]: {e}")))?;

        if response.status().is_client_error() {
            eprintln!("Failed connecting to OSV. [Client error]")
        } else if response.status().is_server_error() {
            eprintln!("Failed connecting to OSV. [Server error]")
        }

        let restext = response.text().await
            .map_err(|e| PyscanError::Osv(format!("Failed to read OSV vuln response: {e}")))?;

        let parsed: Vuln = serde_json::from_str(&restext)
            .map_err(|e| PyscanError::Osv(format!("Invalid parse of API response at scanner/api::vuln_id\n{e}")))?;

        Ok(parsed)
    }

    pub async fn _get_json(&self, name: &str, version: &str) -> Option<Vulnerability> {
        let url = r"https://api.osv.dev/v1/query";

        let body = Query::new(version, name);
        let body = serde_json::to_string(&body).unwrap();

        let res = self.client.request(Method::POST, url).body(body).send().await;

        if let Ok(response) = res {
            if response.status().is_client_error() {
                eprintln!("Failed connecting to OSV. [Client error]")
            } else if response.status().is_server_error() {
                eprintln!("Failed connecting to OSV. [Server error]")
            }
            let restext = response.text().await.unwrap();
            if restext.len() >= 3 {
                serde_json::from_str(&restext).ok()
            } else {
                None
            }
        } else {
            eprintln!("Could not fetch a response from osv.dev");
            None
        }
    }
}
