use std::process::Command;
use std::env::consts::OS;
use tauri::command;

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
                    drives.push(format!("{} ({})", parts[1], parts[0])); // user-friendly
                } else {
                    drives.push(format!("/dev/{}", parts[0])); // raw device path
                }
            }
        }

        Ok(drives)
    } else if OS == "android" {
        // Android (mounted storage)
        // Note: No `lsblk` on Android, so list `/storage/*` instead.
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_drives])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
