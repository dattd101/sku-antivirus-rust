# SentinelAV (MVP)

Rust-based Windows antivirus scanner proof of concept. **Not a replacement for Microsoft Defender.** This version only detects files with SHA-256 hashes already listed in a local database; it does not provide real-time protection, behavioral analysis, ransomware prevention, quarantine, or a kernel driver.

## Usage

Create `signatures.txt` containing one known-malicious SHA-256 hash per line (comments starting with `#` allowed).

```powershell
cargo run --release -p sentinel-cli -- scan "C:\\Users\\Public\\Downloads" signatures.txt
```

Exit codes: 0 = no match and no scan errors; 1 = hash match detected; 2 = invalid input/configuration; 3 = incomplete scan due to errors. No match does **not** imply safety.

## Build

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p sentinel-cli --target x86_64-pc-windows-msvc
```

GitHub Actions builds on `windows-latest`, uploads a ZIP artifact, and publishes a GitHub Release when pushing a `v*` tag.

## Security notes

This MVP does not delete, quarantine, or execute scanned files. Do not store malware samples in the repository. Before commercial use add signed signature updates, strong filesystem identity handling, secure scan workers, limits, audit trails, and comprehensive tests.
