use std::process::Command;
use std::env::consts::OS;
use tauri::command;

#[command]
pub fn create_bootable_usb(usb_drive: String, iso_path: String) -> Result<String, String> {
    if OS == "windows" {
        // Use Rufus command line or diskpart
        let output = Command::new("diskpart")
            .args(&["/s", &format!("select disk {}\nclean\ncreate partition primary\nactive\nformat fs=fat32 quick\nassign", usb_drive)])
            .output()
            .map_err(|e| format!("Failed to format USB: {}", e))?;
        
        if !output.status.success() {
            return Err("USB formatting failed".to_string());
        }
        
        // Copy ISO contents to USB
        Command::new("xcopy")
            .args(&[&iso_path, &format!("{}:\\", usb_drive), "/E", "/H", "/Y"])
            .status()
            .map_err(|e| format!("Failed to copy files: {}", e))?;
            
    } else if OS == "linux" {
        // Use dd command
        Command::new("dd")
            .args(&[&format!("if={}", iso_path), &format!("of=/dev/{}", usb_drive), "bs=4M", "status=progress"])
            .status()
            .map_err(|e| format!("Failed to create bootable USB: {}", e))?;
    }
    
    Ok("Bootable USB created successfully".to_string())
}

#[command]
pub fn list_usb_drives() -> Result<Vec<String>, String> {
    let mut usb_drives = Vec::new();
    
    if OS == "windows" {
        let output = Command::new("wmic")
            .args(&["logicaldisk", "where", "drivetype=2", "get", "deviceid"])
            .output()
            .map_err(|e| format!("Failed to list USB drives: {}", e))?;
            
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                usb_drives.push(trimmed.to_string());
            }
        }
    } else if OS == "linux" {
        let output = Command::new("lsblk")
            .args(&["-o", "NAME,TRAN", "-nr"])
            .output()
            .map_err(|e| format!("Failed to list USB drives: {}", e))?;
            
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("usb") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    usb_drives.push(format!("/dev/{}", parts[0]));
                }
            }
        }
    }
    
    Ok(usb_drives)
}