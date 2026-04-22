use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::ffi::OsString;
use std::fs::File;
mod extractor;
pub mod structs;
use super::scanner;
use super::display::{SourceContext, theme::is_tty};
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
            // cyclonedx
            else if filename == "bom.json" || filename == "cyclonedx.json" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::CycloneDx,
                    path: OsString::from(entry.path()),
                });
            }
            // spdx
            else if filename == "spdx.json" || filename == "bom.spdx.json" {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Spdx,
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
    } else if res.count(&FileTypes::CycloneDx) > 0 {
        find_cyclonedx_imports(files).await
    } else if res.count(&FileTypes::Spdx) > 0 {
        find_spdx_imports(files).await
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

/// Print a source info message (only in TTY mode).
fn print_source_info(source_name: &str) {
    if is_tty() {
        println!("  \x1b[2mℹ  Source: {}\x1b[0m", source_name);
    }
}

async fn find_setuppy_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("setup.py");

    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::SetupPy {
            match fs::read_to_string(&file.path) {
                Ok(content) => {
                    extractor::extract_imports_setup_py(content.as_str(), &mut imports);
                    source_ctx = Some(SourceContext {
                        file_path: file.path.to_string_lossy().to_string(),
                        content,
                    });
                }
                Err(_) => eprintln!("There was a problem reading your setup.py"),
            }
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_python_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("*.py files");

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
    // No meaningful source context for import-style scanning (multiple files, single lines)
    scanner::start(imports, None).await
}

async fn find_reqs_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::Requirements || file.filetype == FileTypes::Constraints {
            let file_name = file.name.to_string_lossy().to_string();
            print_source_info(&file_name);

            if let Ok(content) = fs::read_to_string(&file.path) {
                extractor::extract_imports_reqs(content.clone(), &mut imports);

                source_ctx = Some(SourceContext {
                    file_path: file_name,
                    content,
                });
            } else {
                eprintln!("There was a problem reading your {}", file.name.to_string_lossy());
            }
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_pyproject_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("pyproject.toml");

    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::Pyproject {
            match fs::read_to_string(&file.path) {
                Ok(content) => {
                    let _ = extractor::extract_imports_pyproject(content.clone(), &mut imports);
                    source_ctx = Some(SourceContext {
                        file_path: file.path.to_string_lossy().to_string(),
                        content,
                    });
                }
                Err(_) => eprintln!("There was a problem reading your pyproject.toml"),
            }
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_uvlock_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("uv.lock");

    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::UvLock {
            match fs::read_to_string(&file.path) {
                Ok(content) => {
                    let _ = extractor::extract_imports_uvlock(content.clone(), &mut imports);
                    source_ctx = Some(SourceContext {
                        file_path: file.path.to_string_lossy().to_string(),
                        content,
                    });
                }
                Err(_) => eprintln!("There was a problem reading your uv.lock"),
            }
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_cyclonedx_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("CycloneDX SBOM");

    let mut imports = Vec::new();
    let source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::CycloneDx {
            match fs::read_to_string(&file.path) {
                Ok(content) => {
                    extractor::extract_imports_cyclonedx(content.clone(), &mut imports);
                    // Do not provide source_ctx for SBOMs to avoid parsing/rendering massive JSON files in miette
                }
                Err(_) => eprintln!("There was a problem reading your CycloneDX SBOM"),
            }
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_spdx_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("SPDX SBOM");

    let mut imports = Vec::new();
    let source_ctx: Option<SourceContext> = None;

    for file in f {
        if file.filetype == FileTypes::Spdx {
            match fs::read_to_string(&file.path) {
                Ok(content) => {
                    extractor::extract_imports_spdx(content.clone(), &mut imports);
                    // Do not provide source_ctx for SBOMs
                }
                Err(_) => eprintln!("There was a problem reading your SPDX SBOM"),
            }
        }
    }
    scanner::start(imports, source_ctx).await
}
