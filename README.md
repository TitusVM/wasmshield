# wasmshield CLI

`wasmshield` is a command-line tool designed for verifying and auditing WebAssembly (WASM) components. With its focus on security and integrity, `wasmshield` helps developers ensure their WASM components are robust and trustworthy.

---

## Features
- **SBOM Audit**: Analyze auditable data baked into components using `cargo auditable`.
- **Signature Verification**: Verify the digital signatures of WASM components for integrity checks.

---

## Installation

TBD
---

## Usage

To view the full list of commands and options:
```bash
wasmshield --help
```

### Commands

#### `sbom`
Audits a specified WASM component using its Software Bill of Materials (SBOM). This requires [`cargo auditable`](https://github.com/rust-secure-code/cargo-auditable) data baked into the component.

**Syntax**:
```bash
wasmshield sbom <COMPONENT>
```

**Arguments**:
- `<COMPONENT>`: Path to the WASM component to analyze.

**Example**:
```bash
wasmshield sbom my_component.wasm
```

#### `signature`
Verifies the signature of a specified WASM component to ensure it has not been tampered with.

**Syntax**:
```bash
wasmshield signature <COMPONENT> --public-key <PUBLIC-KEY>
```

**Arguments**:
- `<COMPONENT>`: Path to the WASM component to verify.
- `--public-key, -K`: Path to the public key file associated with the signature.

**Example**:
```bash
wasmshield signature my_component.wasm --public-key public_key.pem
```

---

## Error Handling

- **File not found**: If a specified file (e.g., WASM component or public key) does not exist, an appropriate error will be displayed.
- **Audit failures**: The `sbom` command will report vulnerabilities and warnings found during the audit.
- **Signature verification failures**: The `signature` command will notify if any signatures fail the verification process.

---

## Author

Developed by **Titus Abele**  
📧 tvmab@pm.me

---

## Contributing

Contributions are welcome! Please fork the repository, and submit a pull request with your changes.

---

## License

`wasmshield` is licensed under 
* [MIT License](https://opensource.org/license/MIT)
* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
at your option.