#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use std::process::Command;

#[tauri::command]
fn list_drives() -> Result<Vec<String>, String> {
    let output = Command::new("wmic")
        .args(&["logicaldisk", "get", "name"])
        .output()
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut drives: Vec<String> = Vec::new();

    for line in stdout.lines().skip(1) { 
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            drives.push(trimmed.to_string());
        }
    }

    Ok(drives)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_drives])
        .run(tauri::generate_context!())
        .expect("error while running tauri app");
}
