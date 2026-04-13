use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::ffi::OsString;
use std::fs::File;
mod extractor;
pub mod structs;
use super::scanner;
use structs::{FileTypes, FoundFile, FoundFileResult};
use crate::error::PyscanError;

pub async fn scan_dir(dir: &Path) -> crate::error::Result<()> {
    let mut result = FoundFileResult::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name();
            let filext = if let Some(ext) = Path::new(&filename).extension() {
                ext.to_os_string()
            } else {
                "none".into()
            };

            // setup.py check comes first otherwise it might cause issues with .py checker
            if filename == "setup.py" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::SetupPy,
                    path: OsString::from(entry.path()),
                });
            }
            // check if .py
            else if filext == ".py" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Python,
                    path: OsString::from(entry.path()),
                });
            }
            // requirements.txt
            else if filename == "requirements.txt" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Requirements,
                    path: OsString::from(entry.path()),
                });
            }
            // constraints.txt
            else if filename == "constraints.txt" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Constraints,
                    path: OsString::from(entry.path()),
                });
            }
            // pyproject.toml
            else if filename == "pyproject.toml" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Pyproject,
                    path: OsString::from(entry.path()),
                });
            }
            // uv.lock
            else if filename == "uv.lock" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::UvLock,
                    path: OsString::from(entry.path()),
                });
            }
        }
    }

    find_import(result).await
}

/// A nice abstraction over different ways to find imports for different filetypes.
async fn find_import(res: FoundFileResult) -> crate::error::Result<()> {
    let files = &res.files;
    if res.count(&FileTypes::Requirements) > 0 {
        find_reqs_imports(files).await
    } else if res.count(&FileTypes::Constraints) > 0 {
        // since constraints and requirements have the same syntax, its okay to use the same parser.
        find_reqs_imports(files).await
    } else if res.count(&FileTypes::UvLock) > 0 {
        // uv.lock has resolved versions — prefer over pyproject.toml
        find_uvlock_imports(files).await
    } else if res.count(&FileTypes::Pyproject) > 0 {
        find_pyproject_imports(files).await
    } else if res.count(&FileTypes::SetupPy) > 0 {
        find_setuppy_imports(files).await
    } else if res.count(&FileTypes::Python) > 0 {
        find_python_imports(files).await
    } else {
        Err(PyscanError::Parser(
            "Could not find any requirements.txt, uv.lock, pyproject.toml or python files in this directory".to_string()
        ))
    }
}

async fn find_setuppy_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let cons = console::Term::stdout();
    cons.write_line("Using setup.py as source...")?;

    let mut imports = Vec::new();
    for file in f {
        if file.filetype == FileTypes::SetupPy {
            match fs::read_to_string(&file.path) {
                Ok(content) => extractor::extract_imports_setup_py(content.as_str(), &mut imports),
                Err(_) => eprintln!("There was a problem reading your setup.py"),
            }
        }
    }
    scanner::start(imports).await
}

async fn find_python_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let cons = console::Term::stdout();
    cons.write_line("Using python file as source...")?;

    let mut imports = Vec::new();
    for file in f {
        if file.filetype == FileTypes::Python {
            if let Ok(fhandle) = File::open(&file.path) {
                let reader = BufReader::new(fhandle);
                for line in reader.lines().flatten() {
                    extractor::extract_imports_python(line, &mut imports);
                }
            }
        }
    }
    scanner::start(imports).await
}

async fn find_reqs_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let cons = console::Term::stdout();
    cons.write_line("Using requirements.txt...")?;

    let mut imports = Vec::new();
    for file in f {
        if file.filetype == FileTypes::Requirements || file.filetype == FileTypes::Constraints {
            if let Ok(fhandle) = File::open(&file.path) {
                let reader = BufReader::new(fhandle);
                for line in reader.lines().flatten() {
                    // pep-508 does not parse --hash embeds in requirements.txt
                    extractor::extract_imports_reqs(line.trim().to_string(), &mut imports)
                }
            }
        }
    }
    scanner::start(imports).await
}

async fn find_pyproject_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let cons = console::Term::stdout();
    cons.write_line("Using pyproject.toml as source...")?;

    let mut imports = Vec::new();
    for file in f {
        if file.filetype == FileTypes::Pyproject {
            match fs::read_to_string(&file.path) {
                Ok(content) => { let _ = extractor::extract_imports_pyproject(content, &mut imports); },
                Err(_) => eprintln!("There was a problem reading your pyproject.toml"),
            }
        }
    }
    scanner::start(imports).await
}

async fn find_uvlock_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let cons = console::Term::stdout();
    cons.write_line("Using uv.lock as source...")?;

    let mut imports = Vec::new();
    for file in f {
        if file.filetype == FileTypes::UvLock {
            match fs::read_to_string(&file.path) {
                Ok(content) => { let _ = extractor::extract_imports_uvlock(content, &mut imports); },
                Err(_) => eprintln!("There was a problem reading your uv.lock"),
            }
        }
    }
    scanner::start(imports).await
}
