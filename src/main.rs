use clap::{Parser, Subcommand};
use console::style;
use once_cell::sync::Lazy;
use std::sync::OnceLock;
use std::{path::PathBuf, process::exit};
use utils::{PipCache, SysInfo};
mod display;
mod docker;
mod parser;
mod scanner;
mod utils;
use crate::{
    parser::structs::{Dependency, VersionStatus},
    utils::get_version,
};
use std::env;
use tokio::task;

#[derive(Parser, Debug)]
#[command(
    author = "ohaswin",
    version = "0.1.8",
    about = "python dependency vulnerability scanner.\n\ndo 'pyscan [subcommand] --help' for specific help."
)]
struct Cli {
    /// path to source. (default: current directory)
    #[arg(long,short,default_value=None,value_name="DIRECTORY")]
    dir: Option<PathBuf>,

    /// export the result to a desired format. [json]
    #[arg(long, short, required = false, value_name = "FILENAME")]
    output: Option<String>,

    /// search for a single package.
    #[command(subcommand)]
    subcommand: Option<SubCommand>,

    /// skip: skip the given databases
    /// ex. pyscan -s osv snyk
    /// hidden due to only having one database for now.
    #[arg(
        short,
        long,
        value_delimiter = ' ',
        value_name = "VAL1 VAL2 VAL3...",
        hide = true
    )]
    skip: Vec<String>,

    /// show the version and information about a package from all available sources. (does not search for vulns, use 'package' subcommand for that).
    /// usage: pyscan show requests pyscan-rs lxml koda
    /// hidden due to unfinished
    #[arg(
        long,
        value_delimiter = ' ',
        value_name = "package1 package2 package3...",
        hide = true
    )]
    show: Vec<String>,

    /// Uses pip to retrieve versions. if not provided it will use the source, falling back on pip if not, pypi.org.
    #[arg(long, required=false, action=clap::ArgAction::SetTrue)]
    pip: bool,

    /// Same as --pip except uses pypi.org to retrieve the latest version for the packages.
    #[arg(long, required=false,action=clap::ArgAction::SetTrue)]
    pypi: bool,

    /// turns off the caching of pip packages at the starting of execution.
    #[arg(long="cache-off", required=false,action=clap::ArgAction::SetTrue)]
    cache_off: bool,

    /// ignores the given vuln IDs (from OSV) seperated by spaces
    #[arg(
        long,
        short = 'i',
        value_delimiter = ' ',
        value_name = "VULN_ID1 VULN_ID2 VULN_ID3...",
    )]
    ignorevulns: Vec<String>,

    /// ignore .pyscanignore file (anywhere), reports all vulnerabilities found.
    #[arg(long, short, action=clap::ArgAction::SetTrue, default_value_t = false)]
    pedantic: bool,

}

#[derive(Subcommand, Debug, Clone)]
enum SubCommand {
    /// query for a single python package
    Package {
        /// name of the package
        #[arg(long, short)]
        name: String,

        /// version of the package (defaults to latest if not provided)
        #[arg(long, short, default_value=None)]
        version: Option<String>,
    },

    /// scan inside a docker image
    Docker {
        /// name of the docker image
        #[arg(long, short)]
        name: String,

        /// path inside your docker container where requirements.txt is, or just the folder name where your Dockerfile (along with requirements.txt) is.
        #[arg(long, short, value_name = "DIRECTORY")]
        path: PathBuf,
    },
}

static ARGS: Lazy<OnceLock<Cli>> = Lazy::new(|| OnceLock::from(Cli::parse()));

// Why is the args a static variable? Some arguments need to be seen by other files in the codebase
// such as --pip or --pypi due to different use cases. Args only get wrote to once so it shouldn't pose a problem (Reason its OnceLock'ed).
// Why is it Lazy? Something about a non-const fn in a const world. Pretty surprised to see the compiler recommend an outside crate for this issue.

static PIPCACHE: Lazy<PipCache> = Lazy::new(|| utils::PipCache::init());
// is a hashmap of (package name, version) from 'pip list'
// because calling 'pip show' everytime might get expensive if there are a lot of dependencies to check.

static VULN_IGNORE: Lazy<Vec<String>> = Lazy::new(|| { utils::get_vuln_ignores() });
// vuln IDs

#[tokio::main]
async fn main() {
    match &ARGS.get().unwrap().subcommand {
        // subcommand package
        Some(SubCommand::Package { name, version }) => {
            // let osv = Osv::new().expect("Cannot access the API to get the latest package version.");
            let version = if let Some(v) = version {
                v.to_string()
            } else {
                utils::get_package_version_pypi(name.as_str())
                    .await
                    .expect("Error in retrieving stable version from API")
                    .to_string()
            };

            let dep = Dependency {
                name: name.to_string(),
                version: Some(version),
                comparator: None,
                version_status: VersionStatus {
                    pypi: false,
                    pip: false,
                    source: false,
                },
            };

            // start() from scanner only accepts Vec<Dependency> so
            let vdep = vec![dep];

            let _res = scanner::start(vdep).await;
            exit(0)
        }
        Some(SubCommand::Docker { name, path }) => {
            println!(
                "{} {}\n{} {}",
                style("Docker image:").yellow().blink(),
                style(name.clone()).bold().green(),
                style("Path inside container:").yellow().blink(),
                style(path.to_string_lossy()).bold().green()
            );
            println!("{}",
        style("--- Make sure you run the command with elevated permissions (sudo/administrator) as pyscan might have trouble accessing files inside docker containers ---").dim());
            docker::list_files_in_docker_image(name, path.to_path_buf())
                .await
                .expect("Error in scanning files from Docker image.");
            exit(0)
        }
        None => (),
    }

    println!(
        "pyscan v{} | by Aswin (https://github.com/ohaswin)",
        get_version()
    );

    let sys_info = SysInfo::new().await;
    // supposed to be a global static, cant atm because async closures are unstable.
    // has to be ran in diff thread due to underlying blocking functions, to be fixed soon.

    task::spawn(async move {
        // init pip cache, if cache-off is false or pip has been found
        if !&ARGS.get().unwrap().cache_off | sys_info.pip_found {
            let _ = PIPCACHE.lookup(" ");
            // since its in Lazy its first accesss would init the cache, the result is ignorable.
        }
        // has to be run on another thread to not block user functionality
        // it still blocks because i cant make pip_list() async or PIPCACHE would fail
        // as async closures aren't stable yet.
        // but it removes a 3s delay, for now.
    });

    // --- giving control to parser starts here ---

    // if a directory path is provided
    if let Some(dir) = &ARGS.get().unwrap().dir {
        parser::scan_dir(dir.as_path()).await
    }
    // if not, use cwd
    else if let Ok(dir) = env::current_dir() {
        parser::scan_dir(dir.as_path()).await
    } else {
        eprintln!("the given directory is empty.");
        exit(1)
    }; // err when dir is empty
}
