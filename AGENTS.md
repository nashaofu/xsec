# AGENTS.md

## Project overview

XSec (`xsec`) is intended to be a cross-platform data-encryption and protection
library. The core encryption, key management, storage format, error model, and
public API must remain usable across supported desktop and mobile targets.
Platform-specific capabilities, such as Windows biometric support, belong in
isolated optional adapters and must not become requirements of the core API.

## Repository layout

- `src/lib.rs` - crate module declarations and public exports.
- `src/xsec.rs` - primary `XSec` API and encryption/decryption flow.
- `src/key_manager.rs` - password-derived key management and rotation.
- `src/store.rs` - encrypted key/material persistence.
- `src/error.rs` - `XSecError` and `XSecResult` definitions.
- `src/biometric/` - optional biometric integrations, enabled by `biometric`.
- `examples/` - executable examples; feature-gated examples must declare
  `required-features` in `Cargo.toml`.

## Cross-platform architecture

- Keep cryptographic primitives, serialized formats, key derivation, and
  platform-independent file operations in shared Rust code.
- Put OS APIs, secure hardware, biometric prompts, credential stores, and
  native filesystem behavior behind target-specific modules or traits.
- Do not expose Windows, macOS, Linux, Android, or iOS types in the portable
  core API. Prefer stable Rust types and explicit adapter interfaces.
- Avoid platform-dependent assumptions about path syntax, permissions,
  endianness, newline handling, clocks, randomness, or available UI.
- Preserve encryption-format and error compatibility across platforms. Any
  platform-specific limitation must produce a documented `XSecError`, not a
  silent fallback that weakens protection.
- Keep security-sensitive operations asynchronous only where the API contract
  requires it; do not make portability depend on a particular async runtime.

## Development rules

- Keep the external brand as `XSec` and the Cargo crate name as lowercase
  `xsec`.
- Preserve the existing public API unless the task explicitly requests a
  breaking change. Update README examples and tests when an API changes.
- Do not log passwords, derived keys, plaintext, ciphertext, biometric
  signatures, or other secret material. Use redacted diagnostics when needed.
- Use fresh nonces for every encryption operation and preserve the existing
  authenticated-encryption format unless compatibility changes are requested.
- Keep optional platform code behind its existing feature and target gates;
  do not make Windows-only biometric code required on other platforms.
- When adding a platform integration, keep the portable implementation
  compiling without that target or feature and document the capability matrix.
- Before editing, inspect `git status` and preserve unrelated user changes.
  Never reset, restore, or overwrite unrelated working-tree edits.
- Prefer focused changes. Remove obsolete code rather than leaving duplicate
  commented-out implementations.

## Verification

Run the narrowest relevant checks after changes, and report each result
separately:

```text
cargo fmt -- --check
cargo check
cargo test
cargo check --features biometric
cargo test --features biometric
git diff --check
```

For cross-platform changes, also check every available target or at minimum
run a target compilation check for each affected platform. The biometric
checks require the relevant platform/toolchain support. A successful Windows
build or test run does not prove behavior on macOS, Linux, mobile platforms, or
a real biometric device. Separate portable-core evidence from platform-runtime
evidence, and do not claim runtime security or device behavior without the
corresponding evidence.

## Change reporting

Final reports should list:

1. changed files and the reason for each change;
2. the exact checks that passed or could not run;
3. any remaining platform, runtime, compatibility, or security limitations.
