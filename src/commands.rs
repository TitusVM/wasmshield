//! The module for the Wasmshield CLI commands

/// Check Sbom information of a component built with cargo auditable
#[cfg(feature = "sbom")]
pub mod sbom;
#[cfg(feature = "sbom")]
pub use self::sbom::*;

/// Check Signature of a component
#[cfg(feature = "signature")]
pub mod signature;
#[cfg(feature = "signature")]
pub use self::signature::*;