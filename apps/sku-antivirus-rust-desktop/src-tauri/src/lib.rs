use sku_antivirus_rust_core::Verdict;
use sku_antivirus_rust_scanner::{load_signatures, scan_directory};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Instant;

const EMBEDDED_SIGNATURES: &str = include_str!("../../../../signatures.txt");

#[derive(Serialize)]
struct Detection {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct ScanReport {
    scanned_files: usize,
    detected_files: usize,
    errors: Vec<String>,
    detections: Vec<Detection>,
    elapsed_ms: u128,
}

fn parse_embedded_signatures() -> Result<std::collections::HashSet<String>, String> {
    let mut signatures = std::collections::HashSet::new();
    for (index, raw) in EMBEDDED_SIGNATURES.lines().enumerate() {
        let hash = raw.trim().to_ascii_lowercase();
        if hash.is_empty() || hash.starts_with('#') {
            continue;
        }
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("Invalid embedded signature at line {}", index + 1));
        }
        signatures.insert(hash);
    }
    Ok(signatures)
}

#[tauri::command]
async fn scan_folder(folder: String, signature_path: Option<String>) -> Result<ScanReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = PathBuf::from(folder);
        if !root.is_dir() {
            return Err(format!("Thư mục không tồn tại: {}", root.display()));
        }
        let signatures = match signature_path.filter(|s| !s.trim().is_empty()) {
            Some(path) => load_signatures(Path::new(&path)).map_err(|e| e.to_string())?,
            None => parse_embedded_signatures()?,
        };
        let start = Instant::now();
        let (findings, errors) = scan_directory(&root, &signatures);
        let scanned_files = findings.len();
        let detections: Vec<Detection> = findings
            .into_iter()
            .filter(|f| f.verdict == Verdict::KnownMalicious)
            .map(|f| Detection {
                path: f.path.to_string_lossy().into_owned(),
                sha256: f.sha256,
            })
            .collect();
        Ok(ScanReport {
            scanned_files,
            detected_files: detections.len(),
            errors,
            detections,
            elapsed_ms: start.elapsed().as_millis(),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![scan_folder])
        .run(tauri::generate_context!())
        .expect("failed to start SKU Antivirus Rust desktop");
}
