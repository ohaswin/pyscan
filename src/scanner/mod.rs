pub mod api;
pub mod models;
use super::parser::structs::Dependency;
use super::display::SourceContext;
use super::display::theme::is_tty;

pub async fn start(imports: Vec<Dependency>, source: Option<SourceContext>) -> crate::error::Result<()> {
    let osv = api::Osv::new().await?;

    if is_tty() {
        println!(
            "  \x1b[1;32mℹ\x1b[0m  Found \x1b[1m{}\x1b[0m dependencies",
            imports.len()
        );
    }

    // collected contains the dependencies with found vulns
    let collected = osv.query_batched(imports, source).await?;

    // if we collected vulns, exit with non-zero code
    if !collected.is_empty() {
        std::process::exit(1)
    } else {
        Ok(())
    }
}
