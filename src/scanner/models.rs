// automatically generated. do not change.

use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::parser::structs::ScannedDependency;



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(rename = "vulns")]
    pub vulns: Vec<Vuln>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vuln {
    #[serde(rename = "id")]
    pub id: String,

    // #[serde(rename = "summary")]
    // pub summary: Option<String>,

    #[serde(rename = "details")]
    pub details: String,

    // #[serde(rename = "aliases")]
    // pub aliases: Vec<String>,

    // #[serde(rename = "modified")]
    // pub modified: String,

    // #[serde(rename = "published")]
    // pub published: String,

    // #[serde(rename = "database_specific")]
    // pub database_specific: Option<VulnDatabaseSpecific>,

    // #[serde(rename = "references")]
    // pub references: Vec<Reference>,

    #[serde(rename = "affected")]
    pub affected: Vec<Affected>,

    // #[serde(rename = "schema_version")]
    // pub schema_version: String,

    // #[serde(rename = "severity")]
    // pub severity: Option<Vec<Severity>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    #[serde(rename = "package")]
    pub package: Package,

    // #[serde(rename = "ranges")]
    // pub ranges: Vec<Range>,

    #[serde(rename = "versions")]
    pub versions: Option<Vec<String>>,

    // #[serde(rename = "database_specific")]
    // pub database_specific: AffectedDatabaseSpecific,

    // #[serde(rename = "ecosystem_specific")]
    // pub ecosystem_specific: Option<EcosystemSpecific>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedDatabaseSpecific {
    #[serde(rename = "source")]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemSpecific {
    #[serde(rename = "affected_functions")]
    pub affected_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "ecosystem")]
    pub ecosystem: String,

    #[serde(rename = "purl")]
    pub purl: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub range_type: String,

    #[serde(rename = "events")]
    pub events: Vec<Event>,

    #[serde(rename = "repo")]
    pub repo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "introduced")]
    pub introduced: Option<String>,

    #[serde(rename = "fixed")]
    pub fixed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDatabaseSpecific {
    #[serde(rename = "cwe_ids")]
    pub cwe_ids: Vec<String>,

    #[serde(rename = "github_reviewed")]
    pub github_reviewed: bool,

    #[serde(rename = "severity")]
    pub severity: String,

    #[serde(rename = "github_reviewed_at")]
    pub github_reviewed_at: String,

    #[serde(rename = "nvd_published_at")]
    pub nvd_published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub reference_type: String,

    #[serde(rename = "url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub severity_type: String,

    #[serde(rename = "score")]
    pub score: String,
}

// --- pypi.org/pypi/<package>/json JSON repsonse ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiResponse {
    // #[serde(rename = "info")]
    // pub info: Info,

    // #[serde(rename = "last_serial")]
    // pub last_serial: i64,

    #[serde(rename = "releases")]
    pub releases: HashMap<String, Option<Vec<Url>>>,

    // #[serde(rename = "urls")]
    // pub urls: Vec<Url>,

    // #[serde(rename = "vulnerabilities")]
    // pub vulnerabilities: Vec<Option<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    #[serde(rename = "author")]
    pub author: String,

    #[serde(rename = "author_email")]
    pub author_email: String,

    #[serde(rename = "bugtrack_url")]
    pub bugtrack_url: Option<serde_json::Value>,

    #[serde(rename = "classifiers")]
    pub classifiers: Vec<String>,

    #[serde(rename = "description")]
    pub description: String,

    #[serde(rename = "description_content_type")]
    pub description_content_type: String,

    #[serde(rename = "docs_url")]
    pub docs_url: Option<serde_json::Value>,

    #[serde(rename = "download_url")]
    pub download_url: Option<serde_json::Value>,

    #[serde(rename = "downloads")]
    pub downloads: Downloads,

    #[serde(rename = "home_page")]
    pub home_page: String,

    #[serde(rename = "keywords")]
    pub keywords: String,

    #[serde(rename = "license")]
    pub license: String,

    #[serde(rename = "maintainer")]
    pub maintainer: Option<serde_json::Value>,

    #[serde(rename = "maintainer_email")]
    pub maintainer_email: Option<serde_json::Value>,

    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "package_url")]
    pub package_url: String,

    #[serde(rename = "platform")]
    pub platform: Option<serde_json::Value>,

    #[serde(rename = "project_url")]
    pub project_url: String,

    #[serde(rename = "project_urls")]
    pub project_urls: ProjectUrls,

    #[serde(rename = "release_url")]
    pub release_url: String,

    #[serde(rename = "requires_dist")]
    pub requires_dist: Option<serde_json::Value>,

    #[serde(rename = "requires_python")]
    pub requires_python: String,

    #[serde(rename = "summary")]
    pub summary: String,

    #[serde(rename = "version")]
    pub version: String,

    #[serde(rename = "yanked")]
    pub yanked: bool,

    #[serde(rename = "yanked_reason")]
    pub yanked_reason: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Downloads {
    #[serde(rename = "last_day")]
    pub last_day: i64,

    #[serde(rename = "last_month")]
    pub last_month: i64,

    #[serde(rename = "last_week")]
    pub last_week: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectUrls {
    #[serde(rename = "Homepage")]
    pub homepage: String,

    #[serde(rename = "Source Code")]
    pub source_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Url {
    // #[serde(rename = "comment_text")]
    // pub comment_text: Option<serde_json::Value>,

    #[serde(rename = "digests")]
    pub digests: Option<Digests>,

    #[serde(rename = "downloads")]
    pub downloads: Option<i64>,

    #[serde(rename = "filename")]
    pub filename: Option<String>,

    #[serde(rename = "has_sig")]
    pub has_sig: Option<bool>,

    #[serde(rename = "md5_digest")]
    pub md5_digest: Option<String>,

    #[serde(rename = "packagetype")]
    pub packagetype: Option<String>,

    #[serde(rename = "python_version")]
    pub python_version: Option<String>,

    #[serde(rename = "requires_python")]
    pub requires_python: Option<String>,

    #[serde(rename = "size")]
    pub size: Option<i64>,

    #[serde(rename = "upload_time")]
    pub upload_time: Option<String>,

    #[serde(rename = "upload_time_iso_8601")]
    pub upload_time_iso_8601: Option<String>,

    #[serde(rename = "url")]
    pub url: Option<String>,

    #[serde(rename = "yanked")]
    pub yanked: Option<bool>,

    // #[serde(rename = "yanked_reason")]
    // pub yanked_reason: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digests {
    #[serde(rename = "blake2b_256")]
    pub blake2_b_256: String,

    #[serde(rename = "md5")]
    pub md5: String,

    #[serde(rename = "sha256")]
    pub sha256: String,
}


// BATCHED QUERY MODELS

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryBatched {
    queries: Vec<Query>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {

    pub version: String,

    pub package: QueryPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPackage {
    pub name: String,

    pub ecosystem: String
}

// REPONSE FROM QUERY_BATCHED

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct QueryResponse {
//     pub results: Vec<QueryResponseVulns>
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct QueryResponseVulns {
//     pub vulns: Vec<Option<QueryVulnInfo>> // each vec represents individual dependencies, which may or may not have vuln(s) present, therefore optioned.
// }

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct QueryVulnInfo {
//     pub id: String,
//     pub modified: String
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub results: Vec<QueryResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub vulns: Option<Vec<QueryVuln>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryVuln {
    pub id: String,

    pub modified: String,
}


impl Query {
    pub fn new(version: &str, name: &str) -> Query {
        Query {
            version: version.to_string(),
            package: QueryPackage { name: name.to_string(), ecosystem: "PyPI".to_string() }
        }
    }
}

impl QueryBatched {
    pub fn new(q: Vec<Query>) -> QueryBatched {
        QueryBatched { queries: q }
    }
}

impl Vulnerability {
    pub fn to_scanned_dependency(&self, imports_info: &HashMap<String, String>) -> ScannedDependency {
        // println!("{:#?}", imports_info);
        let name_from_v = if let Some(n) = self.vulns.first() {
            if !n.affected.is_empty() {n.affected.first().unwrap().package.name.clone()}

            else {"Name in Context".to_string()}
        }
        else {"Name In Context".to_string()};

        let version_from_map = if let Some(v) = imports_info.get(&name_from_v) {
            v
        } else {
            &"parent package related to one of your dependencies".to_string()
            // this happens rarely but every once in a while a vulnerability
            // gets assigned to a different (usually) parent package so trying to
            // get the version from our map fails unfortunately.
        };

        ScannedDependency { name: name_from_v, version: version_from_map.to_owned(), vuln: self.clone() }

    }
}
