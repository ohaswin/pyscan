use crate::{display, ARGS, VULN_IGNORE};
/// provides the functions needed to connect to various advisory sources.
use crate::{parser::structs::Dependency, scanner::models::Vulnerability};
use crate::{
    parser::structs::{ScannedDependency, VersionStatus},
    scanner::models::Vuln,
};
use reqwest::{self, Client, Method};
use futures::future;
use std::{fs, env};
use std::process::exit;
use super::{
    super::utils,
    models::{Query, QueryBatched, QueryResponse},
};

/// OSV provides a distrubuted database for vulns, with a free API
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
    pub async fn new() -> Result<Osv, ()> {
        let version = utils::get_version();
        let pyscan_version = format!("pyscan {}", version);
        let client = reqwest::Client::builder()
            .user_agent(pyscan_version)
            .build();

        if let Ok(client) = client {
            let res = client.get("https://osv.dev").send().await;

            if let Ok(_success) = res {
                Ok(Osv {
                    online: true,
                    last_queried: { utils::get_time() },
                    client,
                })
            } else {
                eprintln!(
                    "Could not connect to the OSV website. Check your internet or try again."
                ); exit(1)
            }
        } else {
            eprintln!(
                "Could not build the network client to connect to OSV. Report this at github.com/ohaswin/pyscan/issues"
            ); exit(1)
        }
    }

    pub async fn _query(&self, d: Dependency) -> Option<Vulnerability> {
        // returns None if no vulns found
        // else Some(Vulnerability)

        let version = if d.version.is_some() {
            d.version
        } else {
            let res = utils::get_package_version_pypi(d.name.as_str()).await;
            if let Err(e) = res {
                eprintln!("PypiError:\n{}", e);
                exit(1);
            } else if let Ok(res) = res {
                Some(res.to_string())
            } else {
                eprintln!("A very unexpected error occurred while retrieving version info from Pypi. Please report this on https://github.com/ohaswin/pyscan/issues");
                exit(1);
            }
        };
        // println!("{:?}", self.get_latest_package_version(d.name.clone()));

        
        // println!("{:?}", res);

        self._get_json(d.name.as_str(), &version.unwrap()).await
    }

    pub async fn query_batched(&self, mut deps: Vec<Dependency>) -> Vec<ScannedDependency> {
        // runs the batch API. Each dep is converted into JSON format here, POSTed, and the response of vuln IDs -> queried into Vec<Vulnerability> -> returned as Vec<ScannedDependency>
        // The dep version conflicts are also solved over here.
        let _ = future::join_all(deps
            .iter_mut()
            .map(|d| async {
                d.version = if d.version.is_none() {
                    Some(VersionStatus::choose(d.name.as_str(), &d.version).await)
                } else {
                    d.version.clone()
                }
            })).await;
            
            // .collect::<Vec<_>>();
        let mut progress = display::Progress::new();

        let mut imports_info = utils::vecdep_to_hashmap(&deps);

        let url = "https://api.osv.dev/v1/querybatch";

        let queries: Vec<Query> = deps.iter().map(|d| d.to_query()).collect();
        let batched = QueryBatched::new(queries);

        let body = serde_json::to_string(&batched).unwrap();

        let res = self.client.request(Method::POST, url).body(body).send().await;
        if let Ok(response) = res {
            if response.status().is_client_error() {
                eprintln!("Failed connecting to OSV. [Client error]");
                exit(1)
            } else if response.status().is_server_error() {
                eprintln!("Failed connecting to OSV. [Server error]");
                exit(1)
            }

            let restext = response.text().await.unwrap();

            let parsed: Result<QueryResponse, serde_json::Error> = serde_json::from_str(&restext);
            let mut scanneddeps: Vec<ScannedDependency> = Vec::new();
            if ARGS.get().unwrap().output.is_some() {
                // txt or json extention inference, custom output filename
                let filename = ARGS.get().unwrap().output.as_ref().unwrap();
                if ".json" == &filename[{ filename.len() - 5 }..] {
                    if let Ok(dir) = env::current_dir() {
                        let r = fs::write(dir.join(filename), restext);
                        if let Err(er) = r {
                            eprintln!("Could not write output to file: {}", er.to_string());
                            exit(1)
                        }
                        else {
                            exit(0)
                        }
                    }
                }
            }
            if let Ok(p) = parsed {
                for vres in p.results {
                    if let Some(vulns) = vres.vulns {

                        
                        let mut vecvulns: Vec<Vuln> = Vec::new();
                        for qv in vulns.iter() {
                            // println!("{:#?}", vulns);

                            if ( VULN_IGNORE.contains(&qv.id) || ARGS.get().unwrap().ignorevulns.contains(&qv.id) ) && !ARGS.get().unwrap().pedantic {
                                // if the vuln ID is in the ignore list, skip it
                                println!("Ignoring vuln with ID: {}", qv.id);
                                continue;
                            }
                            vecvulns.push(self.vuln_id(qv.id.as_str()).await) // retrives vuln info from API with a vuln ID
                        }

                        // has to be turned to a Vulnerability before becoming a scanned dependency
                        let structvuln = Vulnerability {vulns: vecvulns};
                        // println!("[VECVULNS] \n {:#?}", structvuln);
                        progress.count_one(); progress.display(); // increment progress
                        if structvuln.vulns.is_empty() {
                            // if no vulns found, skip this dep
                            continue;
                        }
                        scanneddeps.push(structvuln.to_scanned_dependency(&imports_info));

                    }
                    else {continue;}
                } 
                if progress.count > 0 {progress.end()} // clear progress line

                // --- passing to display module starts here ---
                display::display_queried(&scanneddeps, &mut imports_info);
                scanneddeps
            } else {
                eprintln!("Invalid parse of API reponse at src/scanner/api.rs::query_batched\nThis is usually due to a unforeseen API response or a malformed source file.");
                exit(1);
            }
        } else {
            eprintln!("Could not fetch a response from osv.dev [scanner/api/query_batched]");
            exit(1);
        }
    }

    /// get a Vuln from a vuln ID from OSV
    pub async fn vuln_id(&self, id: &str) -> Vuln {
        let url = format!("https://api.osv.dev/v1/vulns/{id}");

        let res = self.client.request(Method::GET, url).send().await;

        // println!("{:?}", res);

        if let Ok(response) = res {
            if response.status().is_client_error() {
                eprintln!("Failed connecting to OSV. [Client error]")
            } else if response.status().is_server_error() {
                eprintln!("Failed connecting to OSV. [Server error]")
            }
            let restext = response.text().await.unwrap();
            // println!("{:#?}", restext.clone());
            let parsed: Result<Vuln, serde_json::Error> = serde_json::from_str(&restext);
            if let Ok(p) = parsed {
                p
            } else if let Err(e) = parsed {
                eprintln!("Invalid parse of API reponse at src/scanner/api.rs::vuln_id\n{}", e);
                exit(1);
            }
            else {
                eprintln!("Invalid parse of API reponse at src/scanner/api.rs(vuln_id)");
                exit(1);
            }
        } else {
            eprintln!("Could not fetch a response from osv.dev [scanner/api/vuln_id]");
            exit(1);
        }
    }

    pub async fn _get_json(&self, name: &str, version: &str) -> Option<Vulnerability> {
        let url = r"https://api.osv.dev/v1/query";

        let body = Query::new(version, name); // struct implementation of query sent to OSV API.
        let body = serde_json::to_string(&body).unwrap();

        // println!("{}", body.clone());

        let res = self.client.request(Method::POST, url).body(body).send().await;

        // println!("{:?}", res);

        if let Ok(response) = res {
            if response.status().is_client_error() {
                eprintln!("Failed connecting to OSV. [Client error]")
            } else if response.status().is_server_error() {
                eprintln!("Failed connecting to OSV. [Server error]")
            }
            let restext = response.text().await.unwrap();
            if !restext.len() < 3 {
                // check if vulns exist by char len of json
                // api returns '{}' if none found so this is easy

                let parsed: Result<Vulnerability, serde_json::Error> =
                    serde_json::from_str(&restext);
                // println!("{:?}", parsed);
                if let Ok(v) = parsed {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            eprintln!("Could not fetch a response from osv.dev");
            exit(1);
        }
    }
}
