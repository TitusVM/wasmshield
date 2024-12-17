use std::path::Path;
use rustsec::Report;

use anyhow::{bail, Result};


/// Audit a component from a given path (will extract each component of a composition)
pub fn audit(path: &Path) -> Result<Vec<(String, Report)>> {
    let file_contents = match std::fs::read(path) {
        Ok(contents) => { contents },
        Err(_) => {
            bail!("Couldn't read file contents")
        }
    };

    let components = wasmshield::decompose::decompose(&file_contents);
    let mut reports = Vec::new();
    // Given the way decomposition is implemented, the first component in the list is always the entire
    // component. This is useful for checking signatures but in this case, we don't want to show the
    // same dependency report twice. We can therefore always skip the first component as it
    // is the same dependency info as the second component.
    let skip = 0;
    let mut counter = 0;
    for component in components {
        let name = if counter == 0 {"composition".to_string()} else {wasmshield::decompose::get_name(&component)};
        // Skip the skipth component in the component list to avoid redundant reports
        if skip != counter {
            match wasmshield::sbom::sbom_audit(&component, true, None) {
                Ok(report) => {
                    reports.push((name, report));
                },
                Err(err) => {
                    bail!("Something went wrong during the verification of one of the components: {}", err)
                }
            }
        }
        counter += 1;
    }
    Ok(reports)
}

