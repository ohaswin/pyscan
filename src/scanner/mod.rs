pub mod api;
pub mod models;
use std::process::exit;
use super::parser::structs::Dependency;
use console::{Term, style};


pub async fn start(imports: Vec<Dependency>) -> Result<(), std::io::Error> {
    let osv = api::Osv::new().await.unwrap(); // err handling done inside, unwrapping is safe
    let cons = Term::stdout();
    let s = format!("Found {} dependencies", style(format!("{}", imports.len()))
    .bold()
    .green());

    cons.write_line(&s)?;

    // collected contains the dependencies with found vulns. imports_info contains a name, version hashmap of all found dependencies so we can display for all imports if vulns have been found or not
    let collected = osv.query_batched(imports).await;
    // query_batched passes stuff onto display module after for printing to screen
    
    // if we collected vulns:
    if !collected.is_empty() {
        exit(1)
    }
    else {
        Ok(()) // if collected is zero means no vulns found, no need for a non-zero exit code.
    }
}


