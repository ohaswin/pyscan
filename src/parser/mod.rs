use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::exit;
use std::{ffi::OsString, fs::File};
mod extractor;
pub mod structs;
use super::scanner;
use structs::{FileTypes, FoundFile, FoundFileResult};

pub async fn scan_dir(dir: &Path) {
    let mut result = FoundFileResult::new(); // contains found files

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name();
            let filext = if let Some(ext) = Path::new(&filename).extension() {
                ext.to_os_string()
            } else {"none".into()};


            // setup.py check comes first otherwise it might cause issues with .py checker
            if *"setup.py" == filename.clone() {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::SetupPy,
                    path: OsString::from(entry.path()),
                });
                result.setuppy();
            }
            // check if .py
            // checking file extension straight up from filename caused some bugs.
            else if ".py" == filext {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Python,
                    path: OsString::from(entry.path()),
                });
                result.python(); // internal count of the file found
            }
            // requirements.txt
            else if *"requirements.txt" == filename.clone() {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Requirements,
                    path: OsString::from(entry.path()),
                });
                result.reqs();
            }
            // constraints.txt
            else if *"constraints.txt" == filename.clone() {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Constraints,
                    path: OsString::from(entry.path()),
                });
                result.constraints();
            }
            // pyproject.toml
            else if *"pyproject.toml" == filename.clone() {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::Pyproject,
                    path: OsString::from(entry.path()),
                });
                result.pyproject();
            }
            // uv.lock
            else if *"uv.lock" == filename.clone() {
                result.add(FoundFile {
                    name: filename,
                    filetype: FileTypes::UvLock,
                    path: OsString::from(entry.path()),
                });
                result.uvlock();
            }
        }
    }
    // println!("{:?}", result.clone());

    // --- find_import takes the result ---

    find_import(result).await
}

/// A nice abstraction over different ways to find imports for different filetypes.
async fn find_import(res: FoundFileResult) {
    let files = res.files;
    if res.reqs_found > res.pyproject_found {
        // if theres a requirements.txt and pyproject.toml isnt there
        find_reqs_imports(&files).await
    } else if res.reqs_found != 0 {
        // if both reqs and pyproject is present, go for reqs first
        find_reqs_imports(&files).await
    } else if res.constraints_found != 0 {
        // since constraints and requirements have the same syntax, its okay to use the same parser.
        find_reqs_imports(&files).await
    } else if res.uvlock_found != 0 {
        // uv.lock has resolved versions — prefer over pyproject.toml
        find_uvlock_imports(&files).await
    } else if res.pyproject_found != 0 {
        // use pyproject instead (if it exists)
        find_pyproject_imports(&files).await
    } else if res.setuppy_found != 0 {
        find_setuppy_imports(&files).await
    } else if res.py_found != 0 {
        // make sure theres atleast one python file, then use that
        find_python_imports(&files).await
    } else {
        eprintln!(
            "Could not find any requirements.txt, uv.lock, pyproject.toml or python files in this directory"
        ); exit(1)
    }
}

async fn find_setuppy_imports(f: &Vec<FoundFile>) {
    let cons = console::Term::stdout();
    cons.write_line("Using setup.py as source...")
        .unwrap();

    let mut imports = Vec::new();
    for file in f {
        if file.is_setuppy() {
            let readf = fs::read_to_string(file.path.clone());
            if let Ok(f) = readf {
                extractor::extract_imports_setup_py(f.as_str(), &mut imports);
            } else {
                eprintln!("There was a problem reading your setup.py")
            }
        }
    }
    // println!("{:?}", imports.clone());
    // cons.clear_last_lines(1).unwrap();
    // --- pass the dependencies to the scanner/api ---
    scanner::start(imports).await.unwrap();
}
async fn find_python_imports(f: &Vec<FoundFile>) {
    let cons = console::Term::stdout();
    cons.write_line("Using python file as source...").unwrap();

    let mut imports = Vec::new(); // contains the Dependencies
    for file in f {
        if file.is_python() {
            if let Ok(fhandle) = File::open(file.path.clone()) {
                let reader = BufReader::new(fhandle);

                for line in reader.lines().flatten() {
                        extractor::extract_imports_python(line, &mut imports);
                }
            }
        }
    }
    // println!("{:?}", imports.clone());
    // cons.clear_last_lines(1).unwrap();
    // --- pass the dependencies to the scanner/api ---
    scanner::start(imports).await.unwrap(); // unwrapping is ok since the return value doesnt matter.
}

async fn find_reqs_imports(f: &Vec<FoundFile>) {
    let cons = console::Term::stdout();
    cons.write_line("Using requirements.txt...")
        .unwrap();

    let mut imports = Vec::new();
    for file in f {
        if file.is_reqs() {
            if let Ok(fhandle) = File::open(file.path.clone()) {
                let reader = BufReader::new(fhandle);

                for line in reader.lines().flatten() {
                    // pep-508 does not parse --hash embeds in requirements.txt
                    // see (https://github.com/figsoda/pep-508/issues/2)
                        extractor::extract_imports_reqs(line.trim().to_string(), &mut imports)
                }
            }
        }
    }
    // println!("{:?}", imports.clone());

    // --- pass the dependencies to the scanner/api ---
    scanner::start(imports).await.unwrap();
}

async fn find_pyproject_imports(f: &Vec<FoundFile>) {
    let cons = console::Term::stdout();
    cons.write_line("Using pyproject.toml as source...")
        .unwrap();

    let mut imports = Vec::new();
    for file in f {
        if file.is_pyproject() {
            let readf = fs::read_to_string(file.path.clone());
            if let Ok(f) = readf {
                let _ = extractor::extract_imports_pyproject(f, &mut imports);
            } else {
                eprintln!("There was a problem reading your pyproject.toml")
            }
        }
    }
    // println!("{:?}", imports.clone());
    // cons.clear_last_lines(1).unwrap();
    // --- pass the dependencies to the scanner/api ---
    scanner::start(imports).await.unwrap();
}

async fn find_uvlock_imports(f: &Vec<FoundFile>) {
    let cons = console::Term::stdout();
    cons.write_line("Using uv.lock as source...")
        .unwrap();

    let mut imports = Vec::new();
    for file in f {
        if file.is_uvlock() {
            let readf = fs::read_to_string(file.path.clone());
            if let Ok(content) = readf {
                let _ = extractor::extract_imports_uvlock(content, &mut imports);
            } else {
                eprintln!("There was a problem reading your uv.lock")
            }
        }
    }
    // --- pass the dependencies to the scanner/api ---
    scanner::start(imports).await.unwrap();
}
