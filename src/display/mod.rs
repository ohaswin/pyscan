use crate::parser::structs::ScannedDependency;
use console::{style, Term};
use std::sync::LazyLock;
use std::collections::HashMap;

static CONS: LazyLock<Term> = LazyLock::new(Term::stdout);

pub struct Progress {
    pub count: usize,
    current_displayed: usize,
}

impl Progress {
    pub fn new() -> Progress {
        Progress {
            count: 0,
            current_displayed: 0,
        }
    }
    pub fn display(&mut self) {
        if self.count > 1 {
            let _ = CONS.clear_last_lines(1);
        }

        if self.count > self.current_displayed {
            let _ = CONS.write_line(
                format!(
                    "Found {} vulnerabilities so far",
                    style(self.count).bold().bright().red()
                )
                .as_str(),
            );
            self.current_displayed = self.count;
        }
    }

    pub fn count_one(&mut self) {
        self.count += 1;
    }
    pub fn end(&mut self) {
        let _ = CONS.clear_last_lines(1);
    }
}

pub fn display_queried(
    collected: &[ScannedDependency],
    imports_info: &mut HashMap<String, String>,
) {
    // --- displaying query result starts here ---
    for dep in collected {
        let _ = CONS.write_line(
            format!(
                "|-| {} [{}]{:^5}",
                style(dep.name.as_str()).bold().bright().yellow(),
                style(dep.version.as_str()).bold().dim(),
                style(" -> Found vulnerabilities!").bold().bright().red()
            )
            .as_str(),
        );
    }

    // remove the deps with vulns from import_info so what remains is the safe deps
    for d in collected.iter() {
        imports_info.remove(d.name.as_str());
    }

    for (k, v) in imports_info.iter() {
        let _ = CONS.write_line(
            format!(
                "|-| {} [{}]{}",
                style(k.as_str()).bold().bright().yellow(),
                style(v.as_str()).bold().dim(),
                style(" -> No vulnerabilities found.")
                    .bold()
                    .bright()
                    .green()
            )
            .as_str(),
        );
    }
    let _ = display_summary(collected);
}

pub fn display_summary(collected: &[ScannedDependency]) -> std::io::Result<()> {
    if !collected.is_empty() {
        CONS.write_line(&format!(
            "{}",
            style("SUMMARY").bold().yellow().underlined()
        ))?;
        for v in collected {
            for vuln in &v.vuln.vulns {
                let name = format!(
                    "Dependency: {}",
                    style(v.name.clone()).bold().bright().red()
                );

                CONS.write_line(name.as_str())?;
                CONS.flush()?;

                let id = format!("ID: {}", style(vuln.id.as_str()).bold().bright().yellow());
                CONS.write_line(id.as_str())?;
                CONS.flush()?;

                let details = format!("Details: {}", style(vuln.details.as_str()).italic());
                CONS.write_line(details.as_str())?;
                CONS.flush()?;

                let vers: Vec<Vec<String>> = vuln
                    .affected
                    .iter()
                    .map(|affected| {
                        vec![
                            {
                                if let Some(v) = &affected.versions {
                                    v.first().unwrap().to_string()
                                } else {
                                    "This version".to_string()
                                }
                            },
                            {
                                if let Some(v) = &affected.versions {
                                    v.last().unwrap().to_string()
                                } else {
                                    "Unknown".to_string()
                                }
                            },
                        ]
                    })
                    .collect();

                let version = format!(
                    "Versions affected: {} to {}",
                    style(
                        vers.first()
                            .expect("No version found affected")
                            .first()
                            .unwrap()
                    )
                    .dim()
                    .underlined(),
                    style(
                        vers.last()
                            .expect("No version found affected")
                            .last()
                            .unwrap()
                    )
                    .dim()
                    .underlined()
                );

                println!();

                CONS.write_line(version.as_str())?;
                CONS.flush()?;
            }
        }
    } else {
        println!("Finished scanning all found dependencies.");
    }
    Ok(())
}
