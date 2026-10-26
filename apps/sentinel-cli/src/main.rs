use sentinel_core::Verdict;
use sentinel_scanner::{load_signatures, scan_directory};
use std::path::Path;

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[1] != "scan" {
        eprintln!("Usage: sentinel-cli scan <directory> <signatures.txt>");
        return Ok(2);
    }

    let root = Path::new(&args[2]);
    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.display()).into());
    }

    let signatures = load_signatures(Path::new(&args[3]))?;
    let (findings, errors) = scan_directory(root, &signatures);
    let count = findings.len();
    let mut detected = 0;

    for finding in findings {
        if finding.verdict == Verdict::KnownMalicious {
            detected += 1;
            println!("[DETECTED] {} {}", finding.sha256, finding.path.display());
        }
    }

    for error in &errors {
        eprintln!("[ERROR] {error}");
    }

    println!(
        "Scanned {count} files; detected {detected}; errors {}",
        errors.len()
    );

    Ok(if !errors.is_empty() {
        3
    } else if detected > 0 {
        1
    } else {
        0
    })
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(2);
        }
    }
}
