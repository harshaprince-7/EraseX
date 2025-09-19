use tauri::command;
use std::process::{Command, Stdio};
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use rand::Rng;
use std::io::prelude::*;

fn is_nvme_device(device_path: &str) -> bool {
    device_path.to_lowercase().contains("nvme")
}

fn check_nvme_cli_available() -> bool {
    Command::new("nvme")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[command]
pub async fn replace_random_byte(method: String, selected_usb: String) -> Result<String, String> {
    if is_nvme_device(&selected_usb) {
        if cfg!(target_os = "windows") && !check_nvme_cli_available() {
            return Err("NVMe CLI not found. Install NVMe CLI tools for Windows.".to_string());
        }
        
        let output = Command::new("nvme")
            .args(&["format", &selected_usb, "-s", "2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

        if output.status.success() {
            Ok(format!("NVMe crypto-erase completed on: {}", selected_usb))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("NVMe format failed: {}. Administrator privileges may be required.", stderr))
        }
    } else {
        // HDD overwrite
        overwrite_hdd_data(method, selected_usb).await
    }
}

#[command]
pub async fn check_ssd_support() -> Result<String, String> {
    if cfg!(target_os = "windows") {
        if check_nvme_cli_available() {
            Ok("NVMe CLI available. SSD secure erase supported.".to_string())
        } else {
            Ok("NVMe CLI not found. Install from: https://github.com/linux-nvme/nvme-cli".to_string())
        }
    } else {
        Ok("Platform may support SSD operations.".to_string())
    }
}

fn get_drive_size(drive_path: &str) -> Result<u64, String> {
    if cfg!(target_os = "windows") {
        let output = Command::new("wmic")
            .args(&["diskdrive", "where", &format!("DeviceID='{}''", drive_path), "get", "Size", "/value"])
            .output()
            .map_err(|e| format!("Failed to get drive size: {}", e))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.starts_with("Size=") {
                return line[5..].parse::<u64>()
                    .map_err(|_| "Failed to parse drive size".to_string());
            }
        }
        Err("Could not determine drive size".to_string())
    } else {
        Err("Drive size detection not implemented for this OS".to_string())
    }
}

fn dismount_drive(drive_letter: &str) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        Command::new("mountvol")
            .args(&[drive_letter, "/d"])
            .output()
            .map_err(|e| format!("Failed to dismount {}: {}", drive_letter, e))?;
    }
    Ok(())
}

fn overwrite_hdd_passes(drive_path: &str, passes: u32) -> Result<String, String> {
    // Try to dismount associated volumes first
    if cfg!(target_os = "windows") && drive_path.contains("PhysicalDrive") {
        let _ = Command::new("diskpart")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = writeln!(stdin, "select disk {}", drive_path.chars().last().unwrap_or('0'));
                    let _ = writeln!(stdin, "offline disk");
                    let _ = writeln!(stdin, "exit");
                }
                child.wait()
            });
    }
    
    let size = get_drive_size(drive_path)?;
    let chunk_size = 1024 * 1024; // 1MB chunks
    let mut rng = rand::thread_rng();
    
    for pass in 1..=passes {
        let mut file = OpenOptions::new()
            .write(true)
            .create(false)
            .open(drive_path)
            .map_err(|e| format!("Failed to open drive (try running as admin): {}", e))?;
        
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek: {}", e))?;
        
        let mut written = 0u64;
        while written < size {
            let remaining = std::cmp::min(chunk_size, size - written);
            let mut buffer = vec![0u8; remaining as usize];
            
            // Different patterns for different passes
            match pass {
                1 => rng.fill(&mut buffer[..]), // Random
                2 => buffer.fill(0xFF),  // Ones
                _ => rng.fill(&mut buffer[..]), // Random
            }
            
            file.write_all(&buffer)
                .map_err(|e| format!("Write failed on pass {}: {}", pass, e))?;
            
            written += remaining;
        }
        
        file.sync_all()
            .map_err(|e| format!("Sync failed on pass {}: {}", pass, e))?;
    }
    
    Ok(format!("HDD overwrite completed with {} passes", passes))
}

#[command]
pub async fn overwrite_hdd_data(method: String, selected_drive: String) -> Result<String, String> {
    if is_nvme_device(&selected_drive) {
        return Err("Use NVMe secure erase for SSD devices".to_string());
    }
    
    let passes = match method.as_str() {
        "single" => 1,
        "3" => 3,
        "7" => 7,
        "gutmann" => 35,
        _ => return Err("Invalid method. Use: single, 3, 7, or gutmann".to_string()),
    };
    
    overwrite_hdd_passes(&selected_drive, passes)
}