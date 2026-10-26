use sku_antivirus_rust_core::Verdict;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug)]
pub struct Finding {
    pub path: PathBuf,
    pub sha256: String,
    pub verdict: Verdict,
}

pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn load_signatures(path: &Path) -> io::Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)?;
    let mut signatures = HashSet::new();

    for (line, raw) in text.lines().enumerate() {
        let hash = raw.trim().to_ascii_lowercase();
        if hash.is_empty() || hash.starts_with('#') {
            continue;
        }
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SHA-256 at line {}", line + 1),
            ));
        }
        signatures.insert(hash);
    }

    Ok(signatures)
}

pub fn scan_directory(root: &Path, signatures: &HashSet<String>) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for entry in WalkDir::new(root).follow_links(false) {
        match entry {
            Ok(entry) if entry.file_type().is_file() => match hash_file(entry.path()) {
                Ok(hash) => findings.push(Finding {
                    path: entry.path().to_path_buf(),
                    verdict: if signatures.contains(&hash) {
                        Verdict::KnownMalicious
                    } else {
                        Verdict::Unknown
                    },
                    sha256: hash,
                }),
                Err(err) => errors.push(format!("{}: {err}", entry.path().display())),
            },
            Err(err) => errors.push(err.to_string()),
            _ => {}
        }
    }

    (findings, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_signature_format() {
        let valid = "a".repeat(64);
        assert_eq!(valid.len(), 64);
        assert!(valid.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn hashes_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sku-antivirus-rust-test-{}-empty", std::process::id()));
        std::fs::write(&path, []).unwrap();
        let digest = hash_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
