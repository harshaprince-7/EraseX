use std::process::Command;
use std::env::consts::OS;
use tauri::command;
use chrono::Utc;
use sha2::{Sha256, Digest};

use std::io::Write;
use uuid::Uuid;
use machine_uid::get;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::fs::{File, set_permissions, Permissions};
use std::path::Path;

#[command]
fn list_drives(pretty: Option<bool>) -> Result<Vec<String>, String> {
    let pretty = pretty.unwrap_or(false);

    if OS == "windows" {
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

        let mtp_output = Command::new("ls")
            .args(&["/run/user/1000/gvfs"])
            .output();

        if let Ok(output) = mtp_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    drives.push(format!("/run/user/1000/gvfs/{}", trimmed));
                }
            }
        }

        Ok(drives)
    } else if OS == "android" {
        let output = Command::new("ls")
            .arg("/storage")
            .output()
            .map_err(|e| format!("Failed to list /storage: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives: Vec<String> = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                drives.push(trimmed.to_string());
            }
        }

        Ok(drives)
    } else {
        Err(format!("Unsupported OS: {}", OS))
    }
}

#[command]
fn drive_info() -> Result<Vec<(String, u64, u64)>, String> {
    let mut drives = Vec::new();

    if OS == "linux" || OS == "android" {
        let output = Command::new("df")
            .args(&["-B1", "--output=source,size,avail", "-x", "tmpfs", "-x", "overlay"])
            .output()
            .map_err(|e| format!("Failed to run df: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 3 {
                let name = parts[0].to_string();
                let total = parts[1].parse::<u64>().unwrap_or(0);
                let free = parts[2].parse::<u64>().unwrap_or(0);
                drives.push((name, total, free));
            }
        }

        if OS == "android" {
            let storage_output = Command::new("ls")
                .arg("/storage")
                .output()
                .map_err(|e| format!("Failed to list /storage: {}", e))?;

            let stdout = String::from_utf8_lossy(&storage_output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed != "self" && trimmed != "emulated" {
                    let path = format!("/storage/{}", trimmed);
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        let total = metadata.len();
                        drives.push((path.clone(), total, 0));
                    } else {
                        drives.push((path, 0, 0));
                    }
                }
            }
        }
    } else if OS == "windows" {
        let output = Command::new("wmic")
            .args(&["logicaldisk", "get", "size,freespace,caption"])
            .output()
            .map_err(|e| format!("Failed to run wmic: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let free = parts[1].parse::<u64>().unwrap_or(0);
                let total = parts[2].parse::<u64>().unwrap_or(0);
                drives.push((name, total, free));
            }
        }
    }

    Ok(drives)
}

#[command]
fn list_files(drive: String) -> Result<Vec<(String, u64)>, String> {
    let entries = std::fs::read_dir(&drive)
        .map_err(|e| format!("Failed to read {}: {}", drive, e))?;

    let mut files = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            let path = e.path();
            let size = if path.is_file() {
                std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
           if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                files.push((name.to_string(), size));
            }
        }
    }
    Ok(files)
}

/// Make file immutable (Linux/Android: chattr, Windows: icacls)
fn make_immutable(path: &Path) -> Result<(), String> {
    if OS == "linux" || OS == "android" {
        Command::new("chattr")
            .args(&["+i", path.to_str().unwrap()])
            .status()
            .map_err(|e| format!("Failed to set immutable: {}", e))?;
    } else if OS == "windows" {
        Command::new("icacls")
            .args(&[
                path.to_str().unwrap(),
                "/inheritance:r",       // remove inherited permissions
                "/grant:r", "Everyone:R" // grant read-only explicitly
            ])
            .status()
            .map_err(|e| format!("Failed to set ACL: {}", e))?;
    }
    Ok(())
}

#[command]
fn generate_certificate(drive: String, wipe_mode: String, user: String) -> Result<String, String> {
    let device_id = get().unwrap_or_else(|_| Uuid::new_v4().to_string());
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();

    let certificate_content = format!(
        "Secure Wipe Certificate\n\
        ======================\n\
        Drive: {}\n\
        Wipe Mode: {}\n\
        User: {}\n\
        Device ID: {}\n\
        Timestamp: {}\n",
        drive, wipe_mode, user, device_id, Utc::now().to_rfc3339()
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

    let mut path: std::path::PathBuf = dirs::document_dir()
        .ok_or("Could not find Documents directory")?;
    path.push("WipeCertificates");
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create directory: {}", e))?;

    path.push(format!("certificate_{}_{}.txt", sanitized_drive, timestamp));

    let mut file = File::create(&path)
        .map_err(|e| format!("Failed to create certificate: {}", e))?;
    file.write_all(full_content.as_bytes())
        .map_err(|e| format!("Failed to write certificate: {}", e))?;

    // Make tamper-proof
    make_immutable(&path)?;

    Ok(path.display().to_string())
}

#[command]
fn verify_certificate(content: String) -> Result<bool, String> {
    let content = content.replace("\r\n", "\n").replace("\r", "\n");

    let mut lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err("Invalid certificate format".to_string());
    }

    let last_line = lines.pop().unwrap();
    let stored_hash = last_line.replace("Verification Hash: ", "").trim().to_string();

    let data_to_hash = lines.join("\n") + "\n";

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let computed_hash = format!("{:x}", hasher.finalize());

    Ok(computed_hash == stored_hash)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_drives,
            drive_info,
            list_files,
            generate_certificate,
            verify_certificate
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
