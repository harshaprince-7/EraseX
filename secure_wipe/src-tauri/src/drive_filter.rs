use tauri::command;
use std::process::Command;

#[command]
pub async fn get_available_drives() -> Result<Vec<String>, String> {
    if cfg!(target_os = "windows") {
        let output = Command::new("powershell")
            .args(&["-Command", "Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object -ExpandProperty DeviceID"])
            .output()
            .map_err(|e| format!("Failed to get drives: {}", e))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        
        let drives: Vec<String> = output_str
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|drive| !drive.is_empty() && *drive != system_drive)
            .collect();
        
        Ok(drives)
    } else {
        Err("Drive enumeration not implemented for this OS".to_string())
    }
}