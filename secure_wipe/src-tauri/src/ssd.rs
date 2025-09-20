use tauri::command;
use std::process::{Command, Stdio};
use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom};
use rand::Rng;

fn drive_letter_to_volume_path(drive_letter: &str) -> Result<String, String> {
    Ok(format!("\\\\.\\{}:", drive_letter.to_uppercase()))
}

fn is_system_drive(drive_letter: &str) -> bool {
    if cfg!(target_os = "windows") {
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let system_letter = system_drive.chars().next().unwrap_or('C');
        drive_letter.to_uppercase().chars().next().unwrap_or('X') == system_letter
    } else {
        false
    }
}

fn is_nvme_device(device_path: &str) -> bool {
    device_path.to_lowercase().contains("nvme")
}

fn is_sata_ssd(device_path: &str) -> bool {
    // Check if device is SSD but not NVMe (i.e., SATA SSD)
    if cfg!(target_os = "windows") {
        let drive_letter = device_path.chars().nth(4).unwrap_or('C');
        let output = Command::new("powershell")
            .args(&["-Command", &format!("Get-PhysicalDisk | Where-Object {{$_.DeviceId -like '*{}*'}} | Select-Object -ExpandProperty MediaType", drive_letter)])
            .output();
        
        if let Ok(output) = output {
            let media_type = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            return media_type.contains("ssd") && !media_type.contains("nvme");
        }
    } else {
        // Linux: Check if device is SSD via /sys/block
        let device_name = device_path.trim_start_matches("/dev/");
        let rotational_path = format!("/sys/block/{}/queue/rotational", device_name);
        if let Ok(content) = std::fs::read_to_string(&rotational_path) {
            return content.trim() == "0"; // 0 = SSD, 1 = HDD
        }
    }
    false
}

fn detect_drive_type(device_path: &str) -> String {
    if is_nvme_device(device_path) {
        "NVMe SSD".to_string()
    } else if is_sata_ssd(device_path) {
        "SATA SSD".to_string()
    } else {
        "HDD".to_string()
    }
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
pub async fn clear_drive_data(selected_usb: String) -> Result<String, String> {
    // Check if trying to clear system drive
    if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        if is_system_drive(&selected_usb) {
            return Err("Cannot clear system drive while Windows is running.".to_string());
        }
    }
    
    let drive_letter = if selected_usb.len() == 1 {
        format!("{}:", selected_usb.to_uppercase())
    } else {
        selected_usb.clone()
    };
    
    if cfg!(target_os = "windows") {
        let output = Command::new("cmd")
            .args(&["/c", &format!("del /f /s /q {}\\*.*", drive_letter)])
            .output()
            .map_err(|e| format!("Failed to delete files: {}", e))?;
        
        if output.status.success() {
            Ok(format!("Regular deletion completed on drive {}", drive_letter))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Deletion failed: {}", stderr))
        }
    } else {
        Err("Clear operation not implemented for this OS".to_string())
    }
}

#[command]
pub async fn replace_random_byte(method: String, selected_usb: String) -> Result<String, String> {
    // Check if trying to wipe system drive
    if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        if is_system_drive(&selected_usb) {
            return Err("Cannot wipe system drive while Windows is running. Boot from external media to wipe system drive.".to_string());
        }
    }
    
    // Map frontend method names to backend method names
    let backend_method = match method.as_str() {
        "Single Pass" => "single",
        "3 Pass DDOD" => "3",
        "7 Pass" => "7",
        "Gutmann" => "gutmann",
        _ => return Err(format!("Unknown wipe method: {}", method)),
    };
    
    // Convert drive letter to volume path if needed
    let drive_path = if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        drive_letter_to_volume_path(&selected_usb)?
    } else {
        selected_usb.clone()
    };
    
    if is_nvme_device(&drive_path) {
        if cfg!(target_os = "windows") && !check_nvme_cli_available() {
            return Err("NVMe CLI not found. Install NVMe CLI tools for Windows.".to_string());
        }
        
        let output = Command::new("nvme")
            .args(&["format", &drive_path, "-s", "2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

        if output.status.success() {
            Ok(format!("NVMe crypto-erase completed on: {}", drive_path))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("NVMe format failed: {}. Administrator privileges may be required.", stderr))
        }
    } else {
        // HDD overwrite
        overwrite_hdd_data(backend_method.to_string(), drive_path).await
    }
}

#[command]
pub async fn hybrid_crypto_erase(selected_usb: String) -> Result<String, String> {
    // Check if trying to erase system drive
    if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        if is_system_drive(&selected_usb) {
            return Err("Cannot erase system drive while Windows is running. Boot from external media to erase system drive.".to_string());
        }
    }
    
    // Convert drive letter to volume path if needed
    let drive_path = if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        drive_letter_to_volume_path(&selected_usb)?
    } else {
        selected_usb.clone()
    };
    
    let drive_type = detect_drive_type(&drive_path);
    
    match drive_type.as_str() {
        "NVMe SSD" => {
            // NVMe Crypto-Erase
            if cfg!(target_os = "windows") && !check_nvme_cli_available() {
                return Err("NVMe CLI not found. Install NVMe CLI tools for Windows.".to_string());
            }
            
            let output = Command::new("nvme")
                .args(&["format", &drive_path, "--ses=1", "--force"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

            if output.status.success() {
                Ok(format!("✅ NVMe crypto-erase completed instantly on: {} ({})", drive_path, drive_type))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("NVMe crypto-erase failed: {}. Administrator privileges may be required.", stderr))
            }
        },
        "SATA SSD" => {
            // SATA Secure Erase
            if cfg!(target_os = "linux") {
                // Linux: Use hdparm secure erase
                let device_name = drive_path.trim_start_matches("/dev/");
                
                // Set security password
                let set_pass = Command::new("hdparm")
                    .args(&["--user-master", "u", "--security-set-pass", "p", &format!("/dev/{}", device_name)])
                    .output()
                    .map_err(|e| format!("Failed to set security password: {}", e))?;
                
                if !set_pass.status.success() {
                    return Err("Failed to set security password for SATA secure erase".to_string());
                }
                
                // Execute secure erase
                let erase_output = Command::new("hdparm")
                    .args(&["--user-master", "u", "--security-erase", "p", &format!("/dev/{}", device_name)])
                    .output()
                    .map_err(|e| format!("Failed to execute secure erase: {}", e))?;
                
                if erase_output.status.success() {
                    Ok(format!("✅ SATA secure erase completed on: {} ({})", drive_path, drive_type))
                } else {
                    let stderr = String::from_utf8_lossy(&erase_output.stderr);
                    Err(format!("SATA secure erase failed: {}", stderr))
                }
            } else {
                // Windows: Fall back to random byte overwrite for SATA SSDs
                Ok(format!("⚠️ SATA secure erase not available on Windows. Use Random Byte method for SATA SSDs. Drive: {} ({})", drive_path, drive_type))
            }
        },
        _ => {
            // HDD: Recommend random byte overwrite
            Err(format!("Crypto-erase not applicable for HDDs. Use Random Byte method for secure overwriting. Drive: {} ({})", drive_path, drive_type))
        }
    }
}

#[command]
pub async fn detect_drive_info(selected_usb: String) -> Result<String, String> {
    let drive_path = if selected_usb.len() == 1 && selected_usb.chars().next().unwrap().is_alphabetic() {
        drive_letter_to_volume_path(&selected_usb)?
    } else {
        selected_usb.clone()
    };
    
    let drive_type = detect_drive_type(&drive_path);
    Ok(drive_type)
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
        let drive_letter = drive_path.chars().nth(4).unwrap_or('C');
        let output = Command::new("powershell")
            .args(&["-Command", &format!("Get-PartitionSupportedSize -DriveLetter {} | Select-Object -ExpandProperty SizeMax", drive_letter)])
            .output()
            .map_err(|e| format!("Failed to get drive size: {}", e))?;
        
        let output_string = String::from_utf8_lossy(&output.stdout);
        let output_str = output_string.trim();
        output_str.parse::<u64>()
            .map_err(|_| "Failed to parse drive size".to_string())
    } else {
        Err("Drive size detection not implemented for this OS".to_string())
    }
}

fn overwrite_hdd_passes(drive_path: &str, passes: u32) -> Result<String, String> {
    
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
    
    Ok(format!("Partition overwrite completed with {} passes on {}", passes, drive_path))
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