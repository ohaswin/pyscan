use clap::{Parser, Subcommand};
use std::sync::{LazyLock, OnceLock};
use std::{path::PathBuf, process::exit};
use utils::{PipCache, SysInfo};
mod display;
mod docker;
mod error;
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
    version = "2.1.0",
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
    #[arg(
        short,
        long,
        value_delimiter = ' ',
        value_name = "VAL1 VAL2 VAL3...",
        hide = true
    )]
    skip: Vec<String>,

    /// show the version and information about a package from all available sources.
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

    /// ignores the given vuln IDs (from OSV) separated by spaces
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

static ARGS: LazyLock<OnceLock<Cli>> = LazyLock::new(|| OnceLock::from(Cli::parse()));

static PIPCACHE: LazyLock<PipCache> = LazyLock::new(|| utils::PipCache::init());

static VULN_IGNORE: LazyLock<Vec<String>> = LazyLock::new(|| utils::get_vuln_ignores());

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        exit(1);
    }
}

async fn run() -> error::Result<()> {
    match &ARGS.get().unwrap().subcommand {
        Some(SubCommand::Package { name, version }) => {
            let version = match version {
                Some(v) => v.clone(),
                None => utils::get_package_version_pypi(name.as_str()).await?,
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

            let vdep = vec![dep];
            scanner::start(vdep, None).await?;
            return Ok(());
        }
        Some(SubCommand::Docker { name, path }) => {
            if display::theme::is_tty() {
                println!(
                    "  \x1b[33mDocker image:\x1b[0m \x1b[1;32m{}\x1b[0m",
                    name
                );
                println!(
                    "  \x1b[33mPath inside container:\x1b[0m \x1b[1;32m{}\x1b[0m",
                    path.to_string_lossy()
                );
                println!("\x1b[2m  --- Make sure you run the command with elevated permissions (sudo/administrator) as pyscan might have trouble accessing files inside docker containers ---\x1b[0m");
            } else {
                println!("Docker image: {}", name);
                println!("Path inside container: {}", path.to_string_lossy());
            }
            docker::list_files_in_docker_image(name, path.to_path_buf()).await?;
            return Ok(());
        }
        None => (),
    }

    if display::theme::is_tty() {
        println!(
            "\x1b[1m  pyscan\x1b[0m v{} \x1b[2m│\x1b[0m by Aswin (https://github.com/ohaswin)",
            get_version()
        );
        println!("  \x1b[2m─────────────────────────────────────────────────────\x1b[0m");
    } else {
        println!(
            "pyscan v{} | by Aswin (https://github.com/ohaswin)",
            get_version()
        );
    }

    let sys_info = SysInfo::new().await;

    task::spawn(async move {
        if !&ARGS.get().unwrap().cache_off | sys_info.pip_found {
            let _ = PIPCACHE.lookup(" ");
        }
    });

    // --- giving control to parser starts here ---
    if let Some(dir) = &ARGS.get().unwrap().dir {
        parser::scan_dir(dir.as_path()).await?;
    } else if let Ok(dir) = env::current_dir() {
        parser::scan_dir(dir.as_path()).await?;
    } else {
        return Err(error::PyscanError::Parser("the given directory is empty.".to_string()));
    }

    Ok(())
}
