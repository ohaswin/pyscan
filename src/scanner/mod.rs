pub mod api;
pub mod models;
use super::parser::structs::Dependency;
use console::{Term, style};

pub async fn start(imports: Vec<Dependency>) -> crate::error::Result<()> {
    let osv = api::Osv::new().await?;
    let cons = Term::stdout();
    let s = format!("Found {} dependencies", style(format!("{}", imports.len()))
    .bold()
    .green());

    cons.write_line(&s)?;

    // collected contains the dependencies with found vulns
    let collected = osv.query_batched(imports).await?;

    // if we collected vulns, exit with non-zero code
    if !collected.is_empty() {
        std::process::exit(1)
    } else {
        Ok(())
    }
}
