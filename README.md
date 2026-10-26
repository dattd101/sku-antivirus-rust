# SentinelAV Portable Windows x64

**Portable build:** Extract the Actions ZIP and double-click `SentinelAV.exe`. No NSIS setup or installation. Windows WebView2 Runtime is required. The portable app is an on-demand scanner only; it does not install a service, register an antivirus, or provide real-time protection.

# SentinelAV Desktop MVP (Rust + Tauri 2 + React)

A **manual SHA-256 signature scanner**, not a full antivirus. No realtime protection, malware signature feed, ransomware defense, quarantine, or kernel driver is included. Do **not** disable Microsoft Defender.

## Windows GitHub Actions

Push this project to a GitHub repository's `main` branch. Workflow `.github/workflows/windows.yml` runs formatting, Clippy, tests, React build, Windows CLI build, Tauri desktop EXE build, and portable ZIP packaging. Download `SentinelAV-Portable-Windows-x64` under the successful workflow's **Artifacts** section.

- **SentinelAV.exe**: GUI application (double-click to open)
- **sentinel-cli.exe**: command-line scanner (requires parameters)

The unsigned EXE may trigger Windows SmartScreen. Commercial distribution requires code signing. WebView2 Runtime must be present on the target PC.

## Local development (Windows)

Install Rust MSVC toolchain, Visual Studio C++ Build Tools, Node.js 22, WebView2 runtime, and Windows SDK. From project root:

```powershell
cargo fmt --all
cargo test --workspace
cd apps/sentinel-desktop
npm install
npm run tauri -- dev
npm run tauri -- build --target x86_64-pc-windows-msvc --no-bundle
```

## Usage

GUI: enter a Windows folder path and optionally a path to `signatures.txt`; click **Bắt đầu quét**. No default malware signatures are bundled; the embedded file is a comment-only example. Files not matching a known hash are **unknown**, not verified clean. The UI displays matching hashes and read errors. No files are deleted.

CLI:

```powershell
.\sentinel-cli.exe scan "C:\Users\Public\Downloads" ".\signatures.txt"
```

`signatures.txt` has one verified SHA-256 per line. CLI exit codes: 0 no matches/no errors; 1 matches; 2 bad usage/input; 3 scan errors.

## Source layout

- `apps/sentinel-desktop`: React/Vite frontend + Tauri 2 Rust backend
- `apps/sentinel-cli`: CLI
- `crates/sentinel-scanner`: streaming SHA-256 scanner
- `crates/sentinel-core`: verdict types
- `.github/workflows/windows.yml`: CI and release

## Security / limitations

This is an early-stage demonstration and does not provide on-access prevention, behavior detection, ransomware blocking, or a commercial-grade malware database. For large directories the current synchronous scan has no cancellation or progress streaming, although it runs in a blocking worker so the UI stays responsive. Do not use as the sole endpoint security control.
