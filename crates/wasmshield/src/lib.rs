//! The Wasmshield library.
//!
//! This crate implements Wasmshield.

#![deny(missing_docs)]
/// Sbom verification tools
pub mod sbom;

/// Decomposition of wac plugged composed components
pub mod decompose;

/// Signature verification tools
pub mod signature;