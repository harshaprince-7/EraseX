use std::process::Command;
use std::env::consts::OS;
use tauri::command;
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Write;

#[command]
fn list_drives(pretty: Option<bool>) -> Result<Vec<String>, String> {
    let pretty = pretty.unwrap_or(false);

    if OS == "windows" {
        // Windows
        let output = Command::new("wmic")
            .args(&["logicaldisk", "get", "name"])
            .output()
            .map_err(|e| format!("Failed to execute WMIC: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives: Vec<String> = Vec::new();

        for line in stdout.lines().skip(1) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                drives.push(trimmed.to_string());
            }
        }

        Ok(drives)
    } else if OS == "linux" {
        // Linux
        let output = Command::new("lsblk")
            .args(&["-o", "NAME,MOUNTPOINT", "-nr"])
            .output()
            .map_err(|e| format!("Failed to execute lsblk: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if pretty {
                    drives.push(format!("{} ({})", parts[1], parts[0]));
                } else {
                    drives.push(format!("/dev/{}", parts[0]));
                }
            }
        }

        Ok(drives)
    } else if OS == "android" {
        // Android
        let storage_paths = std::fs::read_dir("/storage")
            .map_err(|e| format!("Failed to read /storage: {}", e))?;

        let mut drives = Vec::new();
        for entry in storage_paths {
            if let Ok(path) = entry {
                let path_str = path.path().display().to_string();
                if pretty {
                    drives.push(format!("Storage: {}", path_str));
                } else {
                    drives.push(path_str);
                }
            }
        }

        Ok(drives)
    } else {
        Err(format!("Unsupported OS: {}", OS))
    }
}
#[command]
fn generate_certificate(drive: String, wipe_mode: String, user: String) -> Result<String, String> {
    let timestamp = Utc::now().to_rfc3339();
    let certificate_content = format!(
        "Secure Wipe Certificate\n\
        ======================\n\
        Drive: {}\n\
        Wipe Mode: {}\n\
        User: {}\n\
        Timestamp: {}\n",
        drive, wipe_mode, user, timestamp
    );
    let mut hasher = Sha256::new();
    hasher.update(&certificate_content);
    let result = hasher.finalize();
    let hash_hex = format!("{:x}", result);
    let full_content = format!(
        "{}\nVerification Hash: {}\n",
        certificate_content, hash_hex
    );
    let sanitized_drive = drive
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_");
    let mut path: std::path::PathBuf = dirs::document_dir().ok_or("Could not find Documents directory")?;
    path.push("WipeCertificates");
    std::fs::create_dir_all(&path).map_err(|e| format!("Failed to create directory: {}", e))?;
    path.push(format!("certificate_{}.txt", sanitized_drive));
    let mut file = File::create(&path)
        .map_err(|e| format!("Failed to create certificate: {}", e))?;
    file.write_all(full_content.as_bytes())
        .map_err(|e| format!("Failed to write certificate: {}", e))?;
    Ok(path.display().to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_drives, generate_certificate])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
