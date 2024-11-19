//! The `wasmshield` command line tool.
//!
//! Primarily used to check WebAssembly components.
//! See `wasmshield --help` for usage.

use std::path::Path;

use clap::{Arg, ArgMatches, Command};

/// Main entry point of the CLI
fn main() {
    let matches = Command::new("wasmshield")
        .version("1.0")
        .author("Titus Abele <tvmab@pm.me>")
        .about("A CLI tool for verifying WASM components")
        .subcommand(
            Command::new("sbom")
                .about("Run audit on auditable data baked into the component with `cargo auditable`")
                .arg(
                    Arg::new("COMPONENT")
                        .help("The WASM component to analyze")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("signature")
                .about("Verify the signature of the specified WASM component")
                .arg(
                    Arg::new("COMPONENT")
                        .help("The WASM component to verify")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("PUBLIC-KEY")
                        .help("Path to the public key file associated to the signature")
                        .long("public-key")
                        .short('K')
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("sbom", sub_matches)) => handle_sbom(sub_matches),
        Some(("signature", sub_matches)) => handle_signature(sub_matches),
        _ => eprintln!("Invalid command. Use --help for usage."),
    }
}

fn handle_sbom(matches: &ArgMatches) {
    let file = matches.get_one::<String>("COMPONENT").expect("COMPONENT is required");
    if !Path::new(file).exists() {
        eprintln!("Error: File '{}' does not exist.", file);
        std::process::exit(1);
    }

    match wasmshield_cli::commands::sbom::audit(Path::new(file)) {
        Ok(reports) => {
            for report in reports {
                let name = report.0;
                let report = report.1;
                println!("Component: {}", name);
                println!("Has: {} Vulnerabilities, {} Warnings", report.vulnerabilities.count, report.warnings.len());
                if report.vulnerabilities.count != 0 {
                    for vuln in report.vulnerabilities.list {
                        println!("Vulnerability advisory: {}", vuln.advisory.title);
                        println!("Package: {}", vuln.package.name.as_str())
                    }
                }
                else if report.warnings.len() != 0 {
                    for (_, warns) in report.warnings {
                        for warn in warns {
                            println!("Warning type: {:?}", warn.kind);
                            println!("Package: {:?}", warn.package.name.as_str())
                        }
                    }
                } else {
                    println!("Nothing was found during the audit");
                }
            }
        },
        Err(err) => {
            eprintln!("Error occured while auditing component: {}", err);
            std::process::exit(1);
        }
    }
}

fn handle_signature(matches: &ArgMatches) {
    let file = matches.get_one::<String>("COMPONENT").expect("COMPONENT is required");
    if !Path::new(file).exists() {
        eprintln!("Error: File '{}' does not exist.", file);
        std::process::exit(1);
    }

    let key = matches.get_one::<String>("PUBLIC-KEY").expect("PUBLIC-KEY is required");
    if !Path::new(key).exists() {
        eprintln!("Error: File '{}' does not exist.", file);
        std::process::exit(1);
    }

    let mut flag = false;

    match wasmshield_cli::commands::signature::verify_signature(Path::new(file), Path::new(key)) {
        Ok(verifications) => {
            for verification in verifications {
                match verification.1 {
                    Some(err) => {
                        flag = true;
                        eprintln!("{} failed signature check {}", verification.0, err)
                    }
                    _ => {}
                }
            }
        }
        Err(err) => {
            eprintln!("Error occured while auditing component: {}", err);
            std::process::exit(1);
        }
    }
    println!("{}", if !flag {"All signatures match"} else {"Some verifications failed"})

}
