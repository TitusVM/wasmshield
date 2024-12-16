use cargo_audit::config::AuditConfig;
use rustsec::{binary_deps::BinaryReport, Lockfile};
use anyhow::{bail, Result};
use serde_json::Value;
use rustsec::Report;

/// Audit the cargo auditable information that should be backed into each component
pub fn sbom_audit(bytes: &[u8], config: Option<&str>) -> Result<Report> {
    let toml_string = match config {
        Some(config) => match std::fs::read_to_string(config) {
            Ok(toml_string) => toml_string,
            Err(_) => bail!("Couldn't find audit config file at specified location {}", config),
        },
        None => {
            let default_path = format!("{}/.cargo/audit.toml", std::env::var("HOME").unwrap());
            match std::fs::read_to_string(&default_path) {
                Ok(toml_string) => toml_string,
                Err(_) => bail!("Couldn't find audit config file at default location {}", default_path),
            }
        }
    };

    // Vet
    let vet_components = toml_string.contains("vet_components = true");
    match vet_component(bytes) {
        Ok(_) => {}
        Err(e) => {
            if vet_components {
                bail!("Vet failed: {:?}", e);
            } else {
                println!("Vet failed but ignoring is enabled: {:?}", e);
            }
        }
    }

    let ignore_local_packages = toml_string.contains("ignore_local_packages = true");

    let config: AuditConfig = toml::from_str(&toml_string)?;

    let database = get_database(&config);

    let (_binary_format, report) = rustsec::binary_deps::load_deps_from_binary(bytes, Option::None)?;
    let rustsec_report;
    match report {
        BinaryReport::Complete(lockfile) | BinaryReport::Incomplete(lockfile) => {
            rustsec_report = Report::generate(&database, &lockfile, &config.report_settings());
            let local_packages = check_for_local_packages(lockfile);
            if !local_packages.is_empty() && !ignore_local_packages {
                bail!("Local packages found in lockfile. Please ensure that all packages are fetched from a remote source.");
            } else if !local_packages.is_empty() {
                println!("Found local packages but ignoring is enabled: {:?}", local_packages);
            }
        }
        BinaryReport::None => bail!("No dependency information found! Is this a Rust executable built with cargo?")
    }
    Ok(rustsec_report)
}

fn get_database(config: &AuditConfig) -> rustsec::Database {
    let advisory_db_url = config
        .database
        .url
        .as_ref()
        .map(AsRef::as_ref)
        .unwrap_or(rustsec::repository::git::DEFAULT_URL);

    let advisory_db_path = config
        .database
        .path
        .as_ref()
        .cloned()
        .unwrap_or_else(rustsec::repository::git::Repository::default_path);

    let database = if config.database.fetch {
        if !config.output.is_quiet() {
            println!("Fetching advisory database from `{}`", advisory_db_url);
        }

        let result = rustsec::repository::git::Repository::fetch(
            advisory_db_url,
            &advisory_db_path,
            !config.database.stale,
            core::time::Duration::from_secs(0),
        );
        // If the directory is locked, print a message and wait for it to become unlocked.
        // If we don't print the message, `cargo audit` would just hang with no explanation.
        if let Err(e) = &result {
            println!("Something went wrong... {}", e);
        }

        let advisory_db_repo = result.unwrap();

        rustsec::Database::load_from_repo(&advisory_db_repo).unwrap()
    } else {
        rustsec::Database::open(&advisory_db_path).unwrap()
    };

    database
}

fn check_for_local_packages(lockfile: Lockfile) -> Vec<rustsec::cargo_lock::Name>{
    let mut local_packages = Vec::new();
    for package in lockfile.packages {
        if package.source.is_none() {
            local_packages.push(package.name);
        }
    }
    local_packages
}


/// The vet_component function checks the binary for a custom section called "vet_info". This section
/// should contain the json output of the `cargo vet` command and should look something like this:
/// ```json
/// {
///   "conclusion": "success",
///   "vetted_fully": [
///     {
///       "name": "bitflags",
///       "version": "2.6.0"
///     }
///   ],
///   "vetted_partially": [],
///   "vetted_with_exemptions": [
///     {
///       "name": "wit-bindgen-rt",
///       "version": "0.32.0"
///     }
///   ]
/// }
/// ```
/// The `conclusion` field should be either "success" or "failure". If it is "failure", the function
/// will return an error. If it is "success", the function will return Ok(()).
fn vet_component(bytes: &[u8]) -> Result<()> {
    use wasmparser::{Payload, Parser};

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => continue,
        };
        match payload {
            Payload::CustomSection(reader) => {
                if reader.name() == ".vet-v0" {
                    let data = reader.data();
                    let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(data).unwrap();
                    let json: Value = serde_json::from_slice(&decompressed).map_err(|_| anyhow::Error::msg("Couldn't parse vet_info as json"))?;
                    let conclusion = json["conclusion"].as_str().unwrap_or("failure");
                    if conclusion != "success" {
                        bail!("Vet failed: {:?}", json);
                    } else {
                        return Ok(());
                    }
                }
            }
            // Ignore all other sections
            _ => {}
        }
    }
    bail!("Couldn't find vet_info section");
}