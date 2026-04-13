use thiserror::Error;

#[derive(Error, Debug)]
pub enum PyscanError {
    #[error("pip error: {0}")]
    Pip(String),

    #[error("pypi.org error: {0}\n\n(note: this might usually happen when the dependency does not exist on pypi [check spelling, typos, etc] or when there's problems accessing the website.)")]
    Pypi(String),

    #[error("Docker error: {0}")]
    Docker(String),

    #[error("OSV API error: {0}")]
    Osv(String),

    #[error("Parser error: {0}")]
    Parser(String),

    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[error("Network error: {source}")]
    Network {
        #[from]
        source: reqwest::Error,
    },

    #[error("JSON error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    #[error("TOML error: {source}")]
    Toml {
        #[from]
        source: toml::de::Error,
    },
}

pub type Result<T> = std::result::Result<T, PyscanError>;
