use cargo_audit::config::AuditConfig;
use rustsec::{binary_deps::BinaryReport, Lockfile};
use anyhow::{bail, Result};
use std::path::Path;
use rustsec::Report;


const AUDIT_CONFIG_PATH: &str = ".cargo/audit.toml";

/// Audit the cargo auditable information that should be backed into each component
pub fn sbom_audit(bytes: &[u8], config: Option<&str>) -> Result<Report> {
    let toml_string = match config {
        Some(config) => std::fs::read_to_string(config)?,
        None => std::fs::read_to_string(Path::new(AUDIT_CONFIG_PATH))?
    };

    // Read ignore_local_packages from the config file
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
            println!("Local package found: {}", package.name);
            local_packages.push(package.name);
        }
    }
    local_packages
}