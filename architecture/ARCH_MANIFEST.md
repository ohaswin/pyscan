# ARCH_MANIFEST.md — pyscan System Manifest

> **Version**: 2.1.2  
> **Generated**: 2026-04-13 (updated post-refactor)  
> **Scope**: Single-crate CLI application (`pyscan`) — a Python dependency vulnerability scanner written in Rust.

---

## 1. High-Level System Architecture

### 1.1 Conceptual Model

pyscan follows a **Pipeline / Staged-Procedural** architecture. Data flows linearly through four well-defined stages — there is no event bus, no actor system, and no hexagonal port/adapter abstraction. The top-level control flow is strictly procedural (`main → parser → scanner → display`), while each stage internally uses structs and enums in an OOP-adjacent style.

| Stage | Responsibility | Purity |
|---|---|---|
| **CLI** (`main.rs`) | Argument parsing, global static init, entry-point dispatch | Side-Effect (IO) |
| **Parser** (`parser/`) | Filesystem scanning, file-type detection, dependency extraction | Side-Effect (FS reads) |
| **Scanner** (`scanner/`) | Version resolution, OSV API queries, vulnerability correlation | Side-Effect (Network) |
| **Display** (`display/`) | Terminal output formatting and summary rendering | Side-Effect (IO) |
| **Utils** (`utils.rs`) | Shared helpers: HTTP client, pip/pypi version retrieval, caching | Side-Effect (Subprocess, Network) |
| **Docker** (`docker/`) | Container creation, file extraction, cleanup | Side-Effect (Subprocess, FS) |

> **There are no pure-logic modules.** Every module performs IO. The closest to pure logic is `parser::extractor`, which takes `String` input and produces `Vec<Dependency>` output — but it's not isolated behind a trait boundary.

### 1.2 Crate / Module Graph

```mermaid
graph TD
    CLI["main.rs<br/><i>CLI Entry Point</i><br/>⚡ Side-Effect"]
    ERROR["error.rs<br/><i>Unified Error Type</i><br/>🧮 Pure Definitions"]
    PARSER["parser/mod.rs<br/><i>File Discovery & Routing</i><br/>⚡ Side-Effect FS"]
    EXTRACTOR["parser/extractor.rs<br/><i>Dependency Extraction</i><br/>🧮 Near-Pure Logic"]
    STRUCTS["parser/structs.rs<br/><i>Core Data Types</i><br/>🧮 Pure Definitions"]
    SCANNER["scanner/mod.rs<br/><i>Scan Orchestrator</i><br/>⚡ Side-Effect Net"]
    API["scanner/api.rs<br/><i>OSV API Client</i><br/>⚡ Side-Effect Net"]
    MODELS["scanner/models.rs<br/><i>API Serde Models</i><br/>🧮 Pure Definitions"]
    DISPLAY["display/mod.rs<br/><i>Terminal Renderer</i><br/>⚡ Side-Effect IO"]
    UTILS["utils.rs<br/><i>HTTP, Pip, Pypi, Cache</i><br/>⚡ Side-Effect Net/Sub"]
    DOCKER["docker/mod.rs<br/><i>Docker Integration</i><br/>⚡ Side-Effect Async Sub/FS"]

    CLI -->|"run().await"| PARSER
    CLI -->|"SubCommand::Package"| SCANNER
    CLI -->|"SubCommand::Docker"| DOCKER
    PARSER -->|"extract_imports_*()"| EXTRACTOR
    PARSER -->|"scanner::start(deps)"| SCANNER
    EXTRACTOR -->|"push Dependency"| STRUCTS
    SCANNER -->|"Osv::query_batched()"| API
    API -->|"deserialize JSON"| MODELS
    API -->|"display::display_queried()"| DISPLAY
    SCANNER -.->|"VersionStatus::choose()"| UTILS
    API -.->|"vuln_id() parallel"| MODELS
    DOCKER -->|"scan_dir(tmp path)"| PARSER
    CLI -.->|"PipCache, SysInfo"| UTILS
    STRUCTS -.->|"to_query()"| MODELS
    ERROR -.->|"PyscanError"| CLI
    ERROR -.->|"PyscanError"| PARSER
    ERROR -.->|"PyscanError"| SCANNER
    ERROR -.->|"PyscanError"| UTILS
    ERROR -.->|"PyscanError"| DOCKER

    style CLI fill:#ff6b6b,color:#fff
    style ERROR fill:#69db7c,color:#fff
    style PARSER fill:#ffa94d,color:#fff
    style EXTRACTOR fill:#69db7c,color:#fff
    style STRUCTS fill:#69db7c,color:#fff
    style SCANNER fill:#5c7cfa,color:#fff
    style API fill:#5c7cfa,color:#fff
    style MODELS fill:#69db7c,color:#fff
    style DISPLAY fill:#cc5de8,color:#fff
    style UTILS fill:#868e96,color:#fff
    style DOCKER fill:#868e96,color:#fff
```

**Legend**: 🟥 Entry Point · 🟧 Parser Stage · 🟩 Pure / Near-Pure · 🟦 Scanner Stage · 🟪 Display · ⬜ Utilities

---

## 2. The Execution Lifecycle ("The Golden Thread")

### 2.1 Primary Flow: `pyscan` (no subcommand)

```
CLI args parsed (clap)
  │
  ├─ Global statics initialized:
  │    ARGS: LazyLock<OnceLock<Cli>>      ← parsed CLI args, write-once
  │    PIPCACHE: LazyLock<PipCache>       ← HashMap<pkg, ver> from `pip list`
  │    VULN_IGNORE: LazyLock<Vec<String>> ← IDs from .pyscanignore
  │
  ├─ run().await                          ← all logic wrapped in Result-returning fn
  │
  ├─ SysInfo::new().await                 ← checks pip/pypi reachability
  │
  ├─ tokio::task::spawn(cache init)       ← PIPCACHE warm-up on background thread
  │
  └─ parser::scan_dir(dir).await?
       │
       ├─ fs::read_dir(dir)               ← scan for known file types
       │    └─ builds FoundFileResult { files: Vec<FoundFile>, counts: HashMap<FileTypes, u64> }
       │
       ├─ find_import(result)          ← priority dispatch:
       │    │   requirements.txt > constraints.txt > uv.lock > pyproject.toml > setup.py > *.py
       │    │
       │    └─ find_reqs_imports() / find_pyproject_imports() / ...
       │         │
       │         ├─ Read file or stream handle
       │         ├─ Parse structured content (TOML/JSON) if applicable
       │         ├─ extractor::extract_imports_*()   ← PEP 508 / regex / traverse Value
       │         │    └─ pushes Dependency { name, version?, comparator? } into Vec
       │         │
       │         └─ scanner::start(imports: Vec<Dependency>)
       │              │
       │              ├─ Osv::new().await             ← build reqwest Client, verify osv.dev
       │              │
       │              ├─ Resolve missing versions (futures::future::join_all):
       │              │    └─ VersionStatus::choose()  ← source → pip → pypi fallback
       │              │
       │              ├─ Batch query: POST /v1/querybatch
       │              │    ├─ deps → Vec<Query> → QueryBatched → JSON body
       │              │    └─ response → QueryResponse { results: Vec<QueryResult> }
       │              │
       │              ├─ Extract unique vuln IDs from all results:
       │              │    └─ Filter against VULN_IGNORE + --ignorevulns (unless --pedantic)
       │              │
       │              ├─ futures::future::join_all(vuln_id(id)...)  ← GLOBAL PARALLEL fetch
       │              │    └─ GET /v1/vulns/{id} → Vuln struct (concurrent HTTP)
       │              │
       │              ├─ Map fetched vulns back to dependencies:
       │              │    └─ Collect into Vec<ScannedDependency>
       │              │
       │              ├─ display::display_queried(&scanneddeps, &mut imports_info)
       │              │    ├─ Print vulnerable deps (red)
       │              │    ├─ Print safe deps (green)
       │              │    └─ display_summary() — ID, details, affected versions
       │              │
       │              └─ exit(1) if vulns found, Ok(()) otherwise
```

### 2.2 Ownership Handoffs

| Handoff Point | Mechanism | Why |
|---|---|---|
| `ARGS`, `PIPCACHE`, `VULN_IGNORE` | `static LazyLock<..>` (write-once globals) | CLI args and pip cache are needed across modules. `OnceLock` guarantees single-write safety without `Mutex`. No `Arc<Mutex<T>>` anywhere. Uses `std::sync::LazyLock` (Rust 1.80+). |
| `Vec<Dependency>` from parser → scanner | **Move** (`scanner::start(imports)`) | The parser fully relinquishes the dependency vector. No shared ownership. |
| `&[FoundFile]` within parser | **Immutable borrow (slice)** | `find_*_imports(&files)` borrows the file list as a slice; ownership stays with `FoundFileResult`. |
| `&mut Vec<Dependency>` inside extractors | **Mutable borrow** | Extractors push into a caller-owned `Vec` rather than returning a new one. |
| `ScannedDependency` from scanner → display | **Immutable borrow** (`&[ScannedDependency]`) | Display reads but never owns the data. |
| `imports_info` HashMap | **Mutable borrow** (`&mut HashMap`) | Display mutably borrows to `.remove()` vulnerable deps, leaving safe ones for green-printing. |
| All errors | **`Result<T, PyscanError>`** propagated with `?` | All modules return `crate::error::Result<T>`. Single `exit(1)` in `main()`. |

> **Key finding**: There is **zero** use of `Arc`, `Mutex`, `RwLock`, or `RefCell` in this codebase. All concurrency is expressed through `tokio::spawn` with `move` closures over `Copy`/`Clone` data, or through `futures::future::join_all` on borrowed iterators.

### 2.3 Async Strategy

| Component | Model | Details |
|---|---|---|
| **Runtime** | `tokio` multi-threaded (`#[tokio::main]`) | Default Tokio scheduler with `rt-multi-thread` + `process` features. |
| **PipCache init** | `tokio::task::spawn` (fire-and-forget) | Runs `pip list` (blocking subprocess!) on a separate Tokio task. Known issue — author notes it "still blocks" because `pip_list()` is sync and async closures aren't stable yet. |
| **Version resolution** | `futures::future::join_all` | All missing dependency versions are resolved concurrently via async `VersionStatus::choose()` calls. |
| **OSV batch query** | Single `POST` await | The batch API reduces N queries to 1. |
| **Vuln detail fetching** | `futures::future::join_all` (global parallel) | All unique `vuln_id()` calls across all dependencies are dispatched concurrently in a single network wave. |
| **Docker subprocess calls** | `tokio::process::Command` (async) | Docker `create`, `cp`, `stop`, `rm` commands use async subprocess execution, freeing the Tokio thread pool. |
| **Pip subprocess calls** | `std::process::Command` (synchronous) | `pip show` and `pip list` remain blocking. `pip_list()` is called from `LazyLock` init (sync context). |

> [!NOTE]
> Docker commands were migrated from blocking `std::process::Command` to async `tokio::process::Command`. Pip commands remain synchronous because `pip_list()` runs from a `LazyLock` initializer (sync context). The remaining `pip show` calls in `get_python_package_version()` are only invoked as a version-resolution fallback.

---

## 3. The Trait & Interface Blueprint

### 3.1 Trait Inventory

**pyscan defines zero custom traits.** The codebase is entirely struct-and-function based. Polymorphism is achieved through:

1. **Enum dispatch** (`FileTypes`, `SubCommand`) rather than trait objects.
2. **Function routing** (`find_import()` dispatches based on `FoundFileResult` counters).
3. **Serde's `Serialize`/`Deserialize`** — the only traits derived/implemented are from external crates.

| Derived/Implemented Trait | On Type | Purpose |
|---|---|---|
| `clap::Parser` | `Cli` | CLI argument parsing |
| `clap::Subcommand` | `SubCommand` | Subcommand dispatch |
| `serde::Serialize + Deserialize` | `Query`, `QueryBatched`, `QueryResponse`, `Vulnerability`, `Vuln`, etc. | JSON serialization for OSV API |
| `thiserror::Error` | `PyscanError` | Unified error type with `#[from]` conversions for `io::Error`, `reqwest::Error`, `serde_json::Error`, `toml::de::Error` |
| `Debug, Clone` | Nearly all structs | Development ergonomics |
| `Hash` | `FileTypes` | Required for `HashMap<FileTypes, u64>` counting in `FoundFileResult` |

### 3.2 Implicit Interfaces (Function Signatures as Contracts)

Although there are no formal traits, there are **de facto contracts** that any new extractor or data source must follow:

#### Extractor Contract

```rust
/// Every extractor function MUST conform to one of these signatures:

// 1. For text-based or line-by-line parsing (requirements, setup.py, .py):
pub fn extract_imports_<source>(
    input: &str,              // reference to file content or line
    imp: &mut Vec<Dependency> // accumulator — push extracted deps here
)

// 2. For structured formats (TOML/JSON) where parsing happens in the parser stage:
pub fn extract_imports_<source>(
    input: toml::Value,       // or serde_json::Value
    imp: &mut Vec<Dependency> // accumulator
)
// Return: () or Result<(), Error> — errors are handled or propagated as needed.
```

#### Scanner Entry Contract

```rust
/// The scanner expects a fully populated Vec<Dependency>.
/// Versions may be None — the scanner will resolve them via VersionStatus::choose().
pub async fn start(imports: Vec<Dependency>) -> crate::error::Result<()>
```

### 3.3 New Module Template: Adding a New File-Type Parser

To add support for parsing a new Python dependency format (e.g., `Pipfile`), follow this template:

```rust
// In src/parser/extractor.rs — add:
pub fn extract_imports_pipfile(content: toml::Value, imp: &mut Vec<Dependency>) {
    // 1. Content is already a parsed toml::Value from the parser stage
    // 2. For each dependency found:
    imp.push(Dependency {
        name: "package_name".to_string(),
        version: Some("1.0.0".to_string()),  // or None if absent
        comparator: None,                      // or Some(pep_508::Comparator)
        version_status: VersionStatus {
            pypi: false,
            pip: false,
            source: true,  // true if version came from the file
        },
    });
}
```

```rust
// In src/parser/structs.rs — extend FileTypes enum:
pub enum FileTypes {
    // ... existing variants ...
    Pipfile,  // ← add this
}
```

```rust
// In src/parser/mod.rs — add detection + routing:
// 1. In scan_dir(): add filename match for "Pipfile"
// 2. In find_import(): add priority logic in the if/else chain
// 3. Add async fn find_pipfile_imports() following existing pattern
```

---

## 4. Invariants & Safety Constraints

### 4.1 Logical Invariants

| Invariant | Location | Enforcement |
|---|---|---|
| **`ARGS` is written exactly once** | `main.rs` | `OnceLock` inside `LazyLock` guarantees single initialization. Second write panics. |
| **`PIPCACHE` is immutable after init** | `utils.rs` | `LazyLock` initializes on first access. No `&mut self` methods are called post-init (only `lookup(&self)`). `_clear_cache(&mut self)` exists but is never invoked. Init gracefully falls back to empty cache on `pip list` failure. |
| **File-type priority is deterministic** | `parser/mod.rs` | `find_import()` enforces strict ordering: `requirements.txt` > `constraints.txt` > `uv.lock` > `pyproject.toml` > `setup.py` > `.py`. Encoded as if/else-if chain using `res.count(&FileTypes::X)`, not configurable. |
| **Every dependency reaching the scanner MUST have a version** | `scanner/api.rs` | `query_batched()` resolves all `None` versions via `VersionStatus::choose()` before building queries. `to_query()` calls `.unwrap()` on the version — **panics if None**. |
| **OSV must be reachable before scanning begins** | `scanner/api.rs` | `Osv::new()` performs a health check GET to `osv.dev`. Failure returns `Err(PyscanError::Osv(...))`, propagated to `main()`. |
| **Ignored vulns are union of file + CLI args** | `scanner/api.rs` | Both `.pyscanignore` contents and `--ignorevulns` are checked, bypassed if `--pedantic` is set. |
| **Errors propagate — single exit point** | `main.rs` | `run() -> Result<()>` propagates all errors. Only `main()` calls `exit(1)` on `Err`. Vulns found also triggers `exit(1)` from `scanner/mod.rs`. |

### 4.2 Error Propagation Map

```mermaid
graph TD
    subgraph "Unified Error Type: PyscanError"
        PIP["Pip(String)"]
        PYPI["Pypi(String)"]
        DOCKER["Docker(String)"]
        OSV["Osv(String)"]
        PARSER["Parser(String)"]
        IO["Io — #from std::io::Error"]
        NET["Network — #from reqwest::Error"]
        JSON["Json — #from serde_json::Error"]
        TOML["Toml — #from toml::de::Error"]
    end

    subgraph "Propagation"
        Q["? operator — propagates to caller"]
        RUN["run() -> Result in main.rs"]
        EXIT["exit 1 — single point in main()"]
    end

    PIP --> Q
    PYPI --> Q
    DOCKER --> Q
    OSV --> Q
    PARSER --> Q
    IO --> Q
    NET --> Q
    JSON --> Q
    TOML --> Q
    Q --> RUN
    RUN --> EXIT

    style EXIT fill:#ff6b6b,color:#fff
    style Q fill:#69db7c,color:#fff
    style RUN fill:#69db7c,color:#fff
```

**Pattern**: The codebase uses a **unified `PyscanError` enum** (defined in `src/error.rs`) with `thiserror::Error` derive. All error types flow through a single type:

1. **Propagated** via `?` operator throughout the call stack
2. **Printed** via a single `eprintln!("{e}")` in `main()`
3. **Terminated** via a single `std::process::exit(1)` in `main()`

The `#[from]` attribute on `Io`, `Network`, `Json`, and `Toml` variants generates `From` impls, enabling automatic conversion with `?`. Domain-specific variants (`Pip`, `Pypi`, `Docker`, `Osv`, `Parser`) wrap `String` messages created via `.map_err()`.

```rust
// src/error.rs
pub type Result<T> = std::result::Result<T, PyscanError>;
```

### 4.3 Safety: `unsafe` Audit

**There are exactly zero `unsafe` blocks in this codebase.** All code is safe Rust. The dependencies that may use `unsafe` internally include:

- `openssl` (vendored) — FFI bindings to libssl
- `reqwest` / `tokio` — runtime internals
- `regex` — SIMD optimizations

No raw pointer manipulation, no `transmute`, no manual memory management exists in the application code.

---

## 5. LLM Extension Points ("The Hooks")

### 5.1 Add a New Dependency Source Format

**Goal**: Support parsing `Pipfile`, `conda.yaml`, `setup.cfg`, etc.

1. **Add a `FileTypes` variant** in `src/parser/structs.rs`:
   ```rust
   pub enum FileTypes {
       // ...existing...
       Pipfile,  // ← add this (Hash is already derived)
   }
   ```

2. **Write the extractor** in `src/parser/extractor.rs`:
   ```rust
   pub fn extract_imports_pipfile(content: toml::Value, imp: &mut Vec<Dependency>) { ... }
   ```

3. **Wire it into `scan_dir()`** in `src/parser/mod.rs` — add filename match and `result.add(FoundFile { ..., filetype: FileTypes::Pipfile, ... })`. No counter fields or incrementor methods needed — `FoundFileResult::add()` handles counting automatically via `HashMap<FileTypes, u64>`.

4. **Wire it into `find_import()`** in `src/parser/mod.rs` — add `res.count(&FileTypes::Pipfile) > 0` check at desired priority level in the if/else-if chain.

5. **Create `async fn find_pipfile_imports(f: &[FoundFile])`** following the existing pattern. Return `crate::error::Result<()>`.

### 5.2 Add a New Vulnerability Database

**Goal**: Query a second advisory source alongside OSV (e.g., Snyk, GitHub Advisory).

1. **Create a new struct** in `src/scanner/api.rs` (e.g., `Snyk`).

2. **Implement constructor + query methods** mirroring `Osv::new()` and `Osv::query_batched()`.

3. **Add serde models** in `src/scanner/models.rs` for the new API's response format.

4. **Modify `scanner::start()`** in `src/scanner/mod.rs` to instantiate both and merge results. Return `crate::error::Result<()>`.

5. **Respect the `--skip` CLI argument** (currently hidden) in `src/main.rs` to allow users to skip databases.

### 5.3 Extend the CLI

**Goal**: Add a new subcommand or flag.

1. **For a flag**: Add a field to the `Cli` struct in `src/main.rs` with `#[arg(...)]`.

2. **For a subcommand**: Add a variant to `SubCommand` enum in `src/main.rs`.

3. **Access it anywhere** via `ARGS.get().unwrap().your_field` (the global `LazyLock` pattern).

4. **Handle it** in the `match &ARGS.get().unwrap().subcommand` block in `run()`.

### 5.4 Add a New Output Format

**Goal**: Export results as SARIF, CSV, HTML, etc.

1. **Check the `--output` flag** logic in `src/scanner/api.rs`.

2. **Currently only `.json` is supported** — the check uses `filename.ends_with(".json")`.

3. **Add new format branches** after the JSON branch:
   ```rust
   if filename.ends_with(".json") { /* existing */ }
   else if filename.ends_with(".sarif") { /* serialize to SARIF */ }
   else if filename.ends_with(".csv") { /* serialize to CSV */ }
   ```

4. **Better approach**: Refactor into an `OutputFormat` enum parsed from the filename extension, and move serialization to the `display` module.

### 5.5 Improve the Docker Integration

**Goal**: Fix or enhance Docker scanning.

1. All Docker logic is isolated in `src/docker/mod.rs`.
2. It creates a temp container, copies files out, calls `parser::scan_dir()` on the extracted path, then cleans up.
3. Uses `tokio::process::Command` for async subprocess execution.
4. Returns `crate::error::Result<()>` with `PyscanError::Docker` for failures.
5. **Remaining issue**: Hardcoded `./tmp/docker-files` path.

---

### 5.6 Context Checklist for LLM PRs

Before submitting any change to this codebase, verify:

- [ ] **Global statics**: Did you add a new global? Use `LazyLock<OnceLock<T>>` or `LazyLock<T>` from `std::sync`. Never `static mut`.
- [ ] **Error handling**: Don't add new `exit(1)` calls. Return `Err(PyscanError::...)` and use `?` to propagate. All functions should return `crate::error::Result<T>`.
- [ ] **Async discipline**: If calling `std::process::Command` in an async context, use `tokio::process::Command` or wrap with `tokio::task::spawn_blocking()`. Pip calls remain sync (called from `LazyLock` init).
- [ ] **Dependency struct**: All new parsers must produce `Dependency` with `VersionStatus { source: true }` when the version comes from the file.
- [ ] **File priority**: If adding a new file type, decide where it sits in the `find_import()` priority chain. Current order: `requirements.txt` > `constraints.txt` > `uv.lock` > `pyproject.toml` > `setup.py` > `.py`. Use `res.count(&FileTypes::NewType) > 0` in the if/else-if chain.
- [ ] **FoundFileResult**: Adding a new file type only requires adding a `FileTypes` enum variant (with `Hash` derive already present). No new counter fields or methods needed — `add()` and `count()` handle everything.
- [ ] **Version resolution**: If `version` is `None`, the scanner will call `VersionStatus::choose()`. Ensure your extractor sets it to `None` only when the source genuinely lacks version info.
- [ ] **Serde models**: When adding models for a new API, use `#[serde(rename = "...")]` to match the API's JSON keys exactly. Add `Option<T>` for fields that may be absent.
- [ ] **Testing**: The codebase has no tests currently. If you add one, place it in the same module with `#[cfg(test)]`. The `Result`-based error handling now makes functions testable (no `exit(1)` to worry about).
- [ ] **Exit code contract**: `exit(0)` = no vulns found, `exit(1)` = vulns found or error. The single exit point is in `main()`. Don't add `exit()` calls elsewhere.

---

## Appendix: File Index

| File | Lines | Purpose |
|---|---|---|
| `src/main.rs` | ~165 | CLI definition, global statics (`LazyLock`), `run() -> Result<()>` entry |
| `src/error.rs` | ~47 | Unified `PyscanError` enum with `thiserror`, `Result<T>` type alias |
| `src/utils.rs` | ~230 | HTTP helpers, pip/pypi version retrieval, PipCache, SysInfo |
| `src/parser/mod.rs` | ~175 | Directory scanning, file-type routing, import dispatch (returns `Result`) |
| `src/parser/extractor.rs` | ~460 | Extraction logic for requirements.txt, pyproject.toml, setup.py, uv.lock, .py |
| `src/parser/structs.rs` | ~135 | `Dependency`, `FoundFile`, `FoundFileResult` (HashMap-based), `VersionStatus`, `ScannedDependency` |
| `src/scanner/mod.rs` | ~25 | Scanner orchestration, `start()` entry point (returns `Result`) |
| `src/scanner/api.rs` | ~185 | `Osv` struct, single/batch query, parallel `vuln_id` detail fetch |
| `src/scanner/models.rs` | 431 | Serde models for OSV API + PyPI API responses |
| `src/display/mod.rs` | ~150 | `Progress` counter, `display_queried()`, `display_summary()` (`LazyLock`) |
| `src/docker/mod.rs` | ~85 | Docker container creation, async subprocess, file extraction, cleanup |
