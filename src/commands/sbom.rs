use std::path::Path;
use rustsec::Report;

use anyhow::{bail, Result};


/// Audit a component from a given path (will extract each component of a composition)
pub fn audit(path: &Path) -> Result<Vec<Report>> {
    let file_contents = match std::fs::read(path) {
        Ok(contents) => { contents },
        Err(_) => {
            bail!("Couldn't read file contents")
        }
    };

    let components = wasmshield::decompose::decompose(&file_contents);
    let mut reports = Vec::new();
    
    for component in components {
        match wasmshield::sbom::sbom_audit(&component, None) {
            Ok(report) => {
                reports.push(report);
            },
            Err(err) => {
                bail!("Something went wrong during the verification of one of the components: {}", err)
            }
        }
    }
    Ok(reports)
}

