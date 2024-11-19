use anyhow::{Error, bail};
use wasmshield::decompose::clean_extracted;
use std::path::Path;

/// Verify the signature of a component
pub fn verify_signature(file_path: &Path, key_path: &Path) -> Result<Vec<(String, Option<Error>)>, Error> {
    let file_contents = match std::fs::read(file_path) {
        Ok(contents) => {contents}
        Err(_) => {
            bail!("Couldn't read file contents")
        }
    };

    let components = wasmshield::decompose::decompose(&file_contents);
    let mut verifications = Vec::new();
    // Given the way decomposition is implemented, the first component in the list is always the entire
    // component. This is useful for checking signatures but in this case, we don't want to clean the first
    // component as it would invalidate its digest so we only call clean_extracted() on the subcomponents
    let skip = 0;
    let mut counter = 0;
    for mut component in components {
        if skip != counter { component = clean_extracted(&component) }

        let name = if counter == 0 {"composition".to_string()} else {wasmshield::decompose::get_name(&component)};
        match wasmshield::signature::verify(&component, key_path) {
            Ok(_) => {
                verifications.push((name, None));
            },
            Err(err) => {
                verifications.push((name, Some(err)))
            }
        }
        counter += 1; 
    }
    Ok(verifications)
}