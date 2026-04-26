use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
mod extractor;
pub mod structs;
use super::display::{theme::is_tty, SourceContext};
use super::scanner;
use crate::error::PyscanError;
use structs::{FileTypes, FoundFile, FoundFileResult};

pub async fn scan_dir(dir: &Path) -> crate::error::Result<()> {
    let mut result = FoundFileResult::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().as_os_str().to_string_lossy().to_string();
            if let Some(filetype) = FileTypes::file_name_to_type(&filename) {
                result.add(FoundFile {
                    name: filename,
                    filetype,
                    path: entry.path(),
                });
            }
        }
    }

    find_import(result).await
}

/// abstraction over different ways to find imports for different filetypes.
/// Only one type of file will be used to get the imported versions.
///
async fn find_import(res: FoundFileResult) -> crate::error::Result<()> {
    let files = &res.files;

    match res.priority_file_type {
        Some(FileTypes::Requirements | FileTypes::Constraints) => find_reqs_imports(files).await,
        Some(FileTypes::UvLock) => find_uvlock_imports(files).await,
        Some(FileTypes::CycloneDx) => find_cyclonedx_imports(files).await,
        Some(FileTypes::Spdx) => find_spdx_imports(files).await,
        Some(FileTypes::Pyproject) => find_pyproject_imports(files).await,
        Some(FileTypes::SetupPy) => find_setuppy_imports(files).await,
        Some(FileTypes::Python) => find_python_imports(files).await,
        None => Err(PyscanError::Parser(
            "Could not find any requirements.txt, constraints.txt, uv.lock, pyproject.toml, setup.py, SBOM, or python files in this directory".to_string(),
        )),
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
                    extractor::extract_imports_setup_py(&content, &mut imports);
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
        if let Ok(fhandle) = File::open(&file.path) {
            let mut line_buffer = String::new();
            let mut reader = BufReader::new(fhandle);
            while reader.read_line(&mut line_buffer)? > 0 {
                extractor::extract_imports_python(&line_buffer, &mut imports);
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
        let file_name = file.name.clone();
        print_source_info(&file_name);

        if let Ok(content) = fs::read_to_string(&file.path) {
            let _ = extractor::extract_imports_reqs(&content, &mut imports);

            source_ctx = Some(SourceContext {
                file_path: file_name,
                content,
            });
        } else {
            eprintln!("There was a problem reading your {}", file.name);
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_pyproject_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("pyproject.toml");

    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        match fs::read_to_string(&file.path) {
            Ok(content) => {
                let _ =
                    extractor::extract_imports_pyproject(toml::from_str(&content)?, &mut imports);
                source_ctx = Some(SourceContext {
                    file_path: file.path.to_string_lossy().to_string(),
                    content,
                });
            }
            Err(_) => eprintln!("There was a problem reading your pyproject.toml"),
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_uvlock_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("uv.lock");

    let mut imports = Vec::new();
    let mut source_ctx: Option<SourceContext> = None;

    for file in f {
        match fs::read_to_string(&file.path) {
            Ok(content) => {
                let _ = extractor::extract_imports_uvlock(toml::from_str(&content)?, &mut imports);
                source_ctx = Some(SourceContext {
                    file_path: file.path.to_string_lossy().to_string(),
                    content,
                });
            }
            Err(_) => eprintln!("There was a problem reading your uv.lock"),
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_cyclonedx_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("CycloneDX SBOM");

    let mut imports = Vec::new();
    let source_ctx: Option<SourceContext> = None;

    for file in f {
        if let Ok(fhandle) = File::open(&file.path) {
            match serde_json::from_reader(fhandle) {
                Ok(content) => {
                    extractor::extract_imports_cyclonedx(content, &mut imports);
                    // Do not provide source_ctx for SBOMs to avoid parsing/rendering massive JSON files in miette
                }
                Err(_) => eprintln!("Failed to parse CycloneDX SBOM JSON"),
            }
        } else {
            eprintln!("There was a problem reading your CycloneDX SBOM");
        }
    }
    scanner::start(imports, source_ctx).await
}

async fn find_spdx_imports(f: &[FoundFile]) -> crate::error::Result<()> {
    print_source_info("SPDX SBOM");

    let mut imports = Vec::new();
    let source_ctx: Option<SourceContext> = None;

    for file in f {
        if let Ok(fhandle) = File::open(&file.path) {
            match serde_json::from_reader(fhandle) {
                Ok(content) => {
                    extractor::extract_imports_spdx(content, &mut imports);
                    // Do not provide source_ctx for SBOMs
                }
                Err(_) => eprintln!("Failed to parse SPDX SBOM JSON"),
            }
        } else {
            eprintln!("There was a problem reading your SPDX SBOM");
        }
    }
    scanner::start(imports, source_ctx).await
}
