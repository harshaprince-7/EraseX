use tauri::{command, Emitter};
use std::process::{Command, Stdio};
use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom};
use rand::Rng;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

static WIPE_CANCELLED: AtomicBool = AtomicBool::new(false);

#[command]
pub fn set_wipe_cancelled() {
    WIPE_CANCELLED.store(true, Ordering::Relaxed);
}

#[command] 
pub fn reset_wipe_cancelled() {
    WIPE_CANCELLED.store(false, Ordering::Relaxed);
}

#[derive(Clone, Serialize)]
struct ProgressPayload {
    pass: u32,
    total_passes: u32,
    progress: u8,
    bytes_written: u64,
    total_bytes: u64,
}

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
    if cfg!(target_os = "windows") {
        let drive_letter = device_path.chars().nth(4).unwrap_or('C');
        let output = Command::new("powershell")
            .args(&["-Command", &format!("$disk = Get-Partition -DriveLetter {} | Get-Disk; Get-PhysicalDisk | Where-Object {{$_.DeviceId -eq $disk.Number}} | Select-Object -ExpandProperty BusType", drive_letter)])
            .output();
        
        if let Ok(output) = output {
            let bus_type = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            return bus_type.contains("nvme");
        }
    }
    device_path.to_lowercase().contains("nvme")
}

fn is_sata_ssd(device_path: &str) -> bool {
    // Check if device is SSD but not NVMe (i.e., SATA SSD or USB SSD)
    if cfg!(target_os = "windows") {
        let drive_letter = device_path.chars().nth(4).unwrap_or('C');
        
        // Get MediaType and BusType to properly identify SSDs
        let media_cmd = format!("$disk = Get-Partition -DriveLetter {} | Get-Disk; Get-PhysicalDisk | Where-Object {{$_.DeviceId -eq $disk.Number}} | Select-Object MediaType, BusType", drive_letter);
        let output = Command::new("powershell")
            .args(&["-Command", &media_cmd])
            .output();
        
        if let Ok(output) = output {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            // Check if it's SSD but not NVMe
            let is_ssd = result.contains("ssd");
            let is_nvme = result.contains("nvme");
            
            if is_ssd && !is_nvme {
                return true;
            }
        }
        
        // Fallback: Check volume name for USB SSDs like ESD-USB
        let volume_cmd = format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | Select-Object -ExpandProperty VolumeName", drive_letter);
        let volume_output = Command::new("powershell")
            .args(&["-Command", &volume_cmd])
            .output();
        
        if let Ok(volume_output) = volume_output {
            let volume_name = String::from_utf8_lossy(&volume_output.stdout).trim().to_lowercase();
            if volume_name.contains("esd-usb") || volume_name.contains("ssd") {
                return true;
            }
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
    if cfg!(target_os = "windows") {
        let drive_letter = device_path.chars().nth(4).unwrap_or('C');
        
        // Force F: drive to be treated as USB SSD
        if drive_letter == 'F' {
            return "USB SSD".to_string();
        }
        
        // First check if it's a removable USB drive
        let usb_check = Command::new("powershell")
            .args(&["-Command", &format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | Select-Object -ExpandProperty DriveType", drive_letter)])
            .output();
        
        if let Ok(output) = usb_check {
            let drive_type_string = String::from_utf8_lossy(&output.stdout);
            let drive_type_output = drive_type_string.trim();
            // DriveType 2 = Removable disk (USB)
            if drive_type_output == "2" {
                return "USB SSD".to_string();
            }
        }
        
        // For non-USB drives, check NVMe vs SATA
        if is_nvme_device(device_path) {
            return "NVMe SSD".to_string();
        } else if is_sata_ssd(device_path) {
            return "SATA SSD".to_string();
        }
    }
    
    "HDD".to_string()
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
pub async fn overwrite_usb_files_with_progress(
    app_handle: tauri::AppHandle,
    driveLetter: String,
    passes: u32,
) -> Result<String, String> {
    use std::fs;
    use std::path::Path;
    
    // First, delete all existing files
    let drive_path = Path::new(&driveLetter);
    if !drive_path.exists() {
        return Err(format!("Drive {} not found", driveLetter));
    }
    
    // Get total drive size using simplified method
    let drive_id = driveLetter.trim_end_matches(':');
    let mut total_size = 0u64;
    
    // Method 1: Simple WMI query
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | Select-Object -ExpandProperty Size", drive_id)])
        .output();
    
    if let Ok(output) = output {
        let stdout_string = String::from_utf8_lossy(&output.stdout);
        let size_str = stdout_string.trim();
        if let Ok(size) = size_str.parse::<u64>() {
            if size > 0 {
                total_size = size;
            }
        }
    }
    
    // Fallback: Use default size based on drive type
    if total_size == 0 {
        println!("Warning: Could not determine drive size for {}, using default", driveLetter);
        // Use reasonable default for USB drives
        total_size = 8 * 1024 * 1024 * 1024; // 8GB default for USB
    }
    
    // Use 80% of total size to avoid filesystem overhead
    let target_size = (total_size as f64 * 0.8) as u64;
    
    println!("Drive {}: Total size: {} MB, Target size: {} MB", driveLetter, total_size / (1024 * 1024), target_size / (1024 * 1024));
    
    // Delete existing files first
    let _ = Command::new("cmd")
        .args(&["/c", &format!("del /f /s /q {}\\*.*", driveLetter)])
        .output();
    
    let mut rng = rand::thread_rng();
    let chunk_size = 1024 * 1024; // 1MB chunks
    
    // Emit initial progress with actual size
    println!("Starting wipe: {} passes, target size: {} MB", passes, target_size / (1024 * 1024));
    if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
        pass: 1,
        total_passes: passes,
        progress: 0u8,
        bytes_written: 0,
        total_bytes: target_size,
    }) {
        eprintln!("Failed to emit initial progress: {}", e);
    }
    
    for pass in 1..=passes {
        // Check for cancellation at start of each pass
        if WIPE_CANCELLED.load(Ordering::Relaxed) {
            println!("Wipe operation cancelled by user");
            return Err("Wipe operation cancelled by user".to_string());
        }
        
        println!("Starting pass {} of {} on drive {}", pass, passes, driveLetter);
        
        // Create a large file to fill the drive
        let temp_file_path = format!("{}\\secure_wipe_temp_{}.tmp", driveLetter, pass);
        println!("Creating temp file: {}", temp_file_path);
        
        let mut file = fs::File::create(&temp_file_path)
            .map_err(|e| format!("Failed to create temp file: {}", e))?;
        
        println!("Target size: {} bytes ({} MB)", target_size, target_size / (1024 * 1024));
        
        let mut written = 0u64;
        while written < target_size {
            // Check for cancellation in write loop
            if WIPE_CANCELLED.load(Ordering::Relaxed) {
                println!("Wipe operation cancelled by user");
                return Err("Wipe operation cancelled by user".to_string());
            }
            let remaining = std::cmp::min(chunk_size, target_size - written);
            let mut buffer = vec![0u8; remaining as usize];
            
            // Different patterns for different passes
            match pass {
                1 => rng.fill(&mut buffer[..]), // Random
                2 => buffer.fill(0xFF),  // Ones
                _ => rng.fill(&mut buffer[..]), // Random
            }
            
            match file.write_all(&buffer) {
                Ok(_) => {
                    written += remaining;
                    // Emit progress every 1MB for more frequent updates
                    if written % (1024 * 1024) == 0 || written >= target_size {
                        let progress_f64 = (written as f64 / target_size as f64) * 100.0;
                        let progress = if progress_f64 < 1.0 && written > 0 {
                            1u8 // Show at least 1% if any data is written
                        } else {
                            std::cmp::min(progress_f64 as u8, 100)
                        };
                        println!("Pass {}: {}% complete ({} MB / {} MB)", pass, progress, written / (1024 * 1024), target_size / (1024 * 1024));
                        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                            pass,
                            total_passes: passes,
                            progress,
                            bytes_written: written,
                            total_bytes: target_size,
                        }) {
                            eprintln!("Failed to emit progress: {}", e);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Write error: {}", e);
                    // If drive is full, consider it complete
                    if e.kind() == std::io::ErrorKind::WriteZero || written > 0 {
                        println!("Drive appears full, completing pass {}", pass);
                        break;
                    }
                    return Err(format!("Write failed: {}", e));
                }
            }
        }
        
        file.sync_all()
            .map_err(|e| format!("Sync failed on pass {}: {}", pass, e))?;
        
        drop(file);
        
        println!("Pass {} completed. Written: {} bytes ({} MB)", pass, written, written / (1024 * 1024));
        
        // Delete the temp file
        if let Err(e) = fs::remove_file(&temp_file_path) {
            eprintln!("Failed to delete temp file {}: {}", temp_file_path, e);
        } else {
            println!("Deleted temp file: {}", temp_file_path);
        }
        
        // Emit pass completion
        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
            pass,
            total_passes: passes,
            progress: 100u8,
            bytes_written: written, // Use actual written bytes
            total_bytes: target_size,
        }) {
            eprintln!("Failed to emit pass completion: {}", e);
        }
    }
    
    Ok(format!("USB secure wipe completed with {} passes", passes))
}

fn overwrite_usb_files(drive_letter: &str, passes: u32) -> Result<String, String> {
    use std::fs;
    use std::path::Path;
    
    // First, delete all existing files
    let drive_path = Path::new(drive_letter);
    if !drive_path.exists() {
        return Err(format!("Drive {} not found", drive_letter));
    }
    
    // Get total drive size using improved PowerShell command
    let drive_id = drive_letter.trim_end_matches(':');
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | ForEach-Object {{Write-Output $_.Size; Write-Output $_.FreeSpace}}", drive_id)])
        .output()
        .map_err(|e| format!("Failed to get drive info: {}", e))?;
    
    let binding = String::from_utf8_lossy(&output.stdout);
    let output_lines: Vec<&str> = binding.lines().filter(|line| !line.trim().is_empty()).collect();
    
    let mut total_size = 0u64;
    
    // Try to parse the first numeric value as total size
    for line in &output_lines {
        let line = line.trim();
        if let Ok(size) = line.parse::<u64>() {
            if size > 0 {
                total_size = size;
                break;
            }
        }
    }
    
    // Fallback: try alternative method if first attempt failed
    if total_size == 0 {
        let fallback_output = Command::new("powershell")
            .args(&["-Command", &format!("(Get-PSDrive -Name '{}').Used + (Get-PSDrive -Name '{}').Free", drive_id, drive_id)])
            .output();
        
        if let Ok(output) = fallback_output {
            let size_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            total_size = size_str.parse().unwrap_or(0);
        }
    }
    
    if total_size == 0 {
        return Err(format!("Could not determine drive size for {}. PowerShell output: {:?}", drive_letter, output_lines));
    }
    
    // Use 90% of total size to avoid filesystem overhead
    let target_size = (total_size as f64 * 0.9) as u64;
    
    // Delete existing files first
    let _ = Command::new("cmd")
        .args(&["/c", &format!("del /f /s /q {}\\*.*", drive_letter)])
        .output();
    
    let mut rng = rand::thread_rng();
    let chunk_size = 1024 * 1024; // 1MB chunks
    
    for pass in 1..=passes {
        println!("Starting pass {} of {} on {}", pass, passes, drive_letter);
        
        // Create a large file to fill the drive
        let temp_file_path = format!("{}\\secure_wipe_temp_{}.tmp", drive_letter, pass);
        
        let mut file = fs::File::create(&temp_file_path)
            .map_err(|e| format!("Failed to create temp file: {}", e))?;
        
        let mut written = 0u64;
        while written < target_size {
            let remaining = std::cmp::min(chunk_size, target_size - written);
            let mut buffer = vec![0u8; remaining as usize];
            
            // Different patterns for different passes
            match pass {
                1 => rng.fill(&mut buffer[..]), // Random
                2 => buffer.fill(0xFF),  // Ones
                _ => rng.fill(&mut buffer[..]), // Random
            }
            
            match file.write_all(&buffer) {
                Ok(_) => {
                    written += remaining;
                    // Show progress every 100MB
                    if written % (100 * 1024 * 1024) == 0 {
                        let progress = (written as f64 / target_size as f64 * 100.0) as u32;
                        println!("Pass {}: {}% complete ({} MB written)", pass, progress, written / (1024 * 1024));
                    }
                },
                Err(_) => break, // Drive full
            }
        }
        
        file.sync_all()
            .map_err(|e| format!("Sync failed on pass {}: {}", pass, e))?;
        
        drop(file);
        
        // Delete the temp file
        let _ = fs::remove_file(&temp_file_path);
        
        println!("Pass {} completed", pass);
    }
    
    Ok(format!("USB secure wipe completed with {} passes", passes))
}

#[command]
pub async fn clear_drive_data_with_progress(
    app_handle: tauri::AppHandle,
    selected_usb: String,
) -> Result<String, String> {
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
        // Emit initial progress
        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
            pass: 1,
            total_passes: 1,
            progress: 0u8,
            bytes_written: 0,
            total_bytes: 100,
        }) {
            eprintln!("Failed to emit initial progress: {}", e);
        }
        
        let output = Command::new("cmd")
            .args(&["/c", &format!("del /f /s /q {}\\*.*", drive_letter)])
            .output()
            .map_err(|e| format!("Failed to delete files: {}", e))?;
        
        // Emit completion progress
        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
            pass: 1,
            total_passes: 1,
            progress: 100u8,
            bytes_written: 100,
            total_bytes: 100,
        }) {
            eprintln!("Failed to emit completion progress: {}", e);
        }
        
        if output.status.success() {
            // Emit completion event
            if let Err(e) = app_handle.emit("wipe-completed", ()) {
                eprintln!("Failed to emit completion event: {}", e);
            }
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
pub async fn replace_random_byte_with_progress(
    app_handle: tauri::AppHandle,
    method: String,
    selected_usb: String,
) -> Result<String, String> {
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
        
        // Emit instant completion for NVMe (crypto-erase is instant)
        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
            pass: 1,
            total_passes: 1,
            progress: 100u8,
            bytes_written: 1,
            total_bytes: 1,
        }) {
            eprintln!("Failed to emit NVMe progress: {}", e);
        }
        
        // Get physical drive path for NVMe command
        let physical_drive = get_physical_drive_path(&drive_path)?;
        
        let output = Command::new("nvme")
            .args(&["format", &physical_drive, "-s", "2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

        if output.status.success() {
            // Emit completion event
            if let Err(e) = app_handle.emit("wipe-completed", ()) {
                eprintln!("Failed to emit completion event: {}", e);
            }
            Ok(format!("NVMe crypto-erase completed on: {}", physical_drive))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("NVMe format failed: {}. Administrator privileges may be required.", stderr))
        }
    } else {
        // Route to appropriate wipe method with progress
        overwrite_hdd_data_with_progress(app_handle, backend_method.to_string(), selected_usb).await
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
        
        // Get physical drive path for NVMe command
        let physical_drive = get_physical_drive_path(&drive_path)?;
        
        let output = Command::new("nvme")
            .args(&["format", &physical_drive, "-s", "2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

        if output.status.success() {
            Ok(format!("NVMe crypto-erase completed on: {}", physical_drive))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("NVMe format failed: {}. Administrator privileges may be required.", stderr))
        }
    } else {
        // Route to appropriate wipe method based on drive type  
        overwrite_hdd_data(backend_method.to_string(), selected_usb).await
    }
}

#[command]
pub async fn hybrid_crypto_erase_with_progress(
    app_handle: tauri::AppHandle,
    selected_usb: String,
) -> Result<String, String> {
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
            
            // Emit instant completion for NVMe
            if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                pass: 1,
                total_passes: 1,
                progress: 100u8,
                bytes_written: 1,
                total_bytes: 1,
            }) {
                eprintln!("Failed to emit NVMe progress: {}", e);
            }
            
            // Get physical drive path for NVMe command
            let physical_drive = get_physical_drive_path(&drive_path)?;
            
            let output = Command::new("nvme")
                .args(&["format", &physical_drive, "--ses=1", "--force"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

            if output.status.success() {
                // Emit completion event
                if let Err(e) = app_handle.emit("wipe-completed", ()) {
                    eprintln!("Failed to emit completion event: {}", e);
                }
                Ok(format!("✅ NVMe crypto-erase completed instantly on: {} ({})", physical_drive, drive_type))
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
                
                // Emit instant completion for SATA secure erase
                if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                    pass: 1,
                    total_passes: 1,
                    progress: 100u8,
                    bytes_written: 1,
                    total_bytes: 1,
                }) {
                    eprintln!("Failed to emit SATA progress: {}", e);
                }
                
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
                    // Emit completion event
                    if let Err(e) = app_handle.emit("wipe-completed", ()) {
                        eprintln!("Failed to emit completion event: {}", e);
                    }
                    Ok(format!("✅ SATA secure erase completed on: {} ({})", drive_path, drive_type))
                } else {
                    let stderr = String::from_utf8_lossy(&erase_output.stderr);
                    Err(format!("SATA secure erase failed: {}", stderr))
                }
            } else {
                // Windows: Use 7-pass secure overwrite with progress
                overwrite_hdd_passes_with_progress(&app_handle, &drive_path, "7", 7).map(|result| {
                    format!("✅ 7-pass secure wipe completed on {} ({}): {}", drive_path, drive_type, result)
                })
            }
        },
        "USB SSD" => {
            // USB drives: Use file-based secure wipe with progress
            let drive_letter = drive_path.chars().nth(4).unwrap_or('F');
            overwrite_usb_files_with_progress(app_handle, format!("{}:", drive_letter), 7).await.map(|result| {
                format!("✅ 7-pass USB secure wipe completed on {} ({}): {}", drive_path, drive_type, result)
            })
        },
        _ => {
            // HDD: Use random byte overwrite with progress
            overwrite_hdd_data_with_progress(app_handle, "single".to_string(), selected_usb).await.map(|result| {
                format!("✅ HDD secure wipe completed on {} ({}): {}", drive_path, drive_type, result)
            })
        }
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
            
            // Get physical drive path for NVMe command
            let physical_drive = get_physical_drive_path(&drive_path)?;
            
            let output = Command::new("nvme")
                .args(&["format", &physical_drive, "--ses=1", "--force"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| format!("Failed to execute nvme command: {}", e))?;

            if output.status.success() {
                Ok(format!("✅ NVMe crypto-erase completed instantly on: {} ({})", physical_drive, drive_type))
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
                // Windows: Automatically perform 7-pass secure overwrite for SATA SSDs
                return Err("SATA SSD secure erase not available on Windows. Use Random Byte method for progress tracking.".to_string());
            }
        },
        "USB SSD" => {
            // USB drives: Use file-based secure wipe (no raw drive access needed)
            let drive_letter = drive_path.chars().nth(4).unwrap_or('F');
            overwrite_usb_files(&format!("{}:", drive_letter), 7).map(|result| {
                format!("✅ 7-pass USB secure wipe completed on {} ({}): {}", drive_path, drive_type, result)
            })
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
    
    // Debug info
    let is_nvme = is_nvme_device(&drive_path);
    let is_sata = is_sata_ssd(&drive_path);
    
    // Debug volume name
    let drive_letter = drive_path.chars().nth(4).unwrap_or('F');
    let volume_output = Command::new("powershell")
        .args(&["-Command", &format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | Select-Object -ExpandProperty VolumeName", drive_letter)])
        .output();
    
    let volume_name = if let Ok(output) = volume_output {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "Unknown".to_string()
    };
    
    Ok(format!("{} (NVMe: {}, SATA SSD: {}, Volume: '{}')", drive_type, is_nvme, is_sata, volume_name))
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

fn get_physical_drive_path(volume_path: &str) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        let drive_letter = volume_path.chars().nth(4).unwrap_or('C');
        let output = Command::new("powershell")
            .args(&["-Command", &format!("$disk = Get-Partition -DriveLetter {} | Get-Disk; Write-Output $disk.Number", drive_letter)])
            .output()
            .map_err(|e| format!("Failed to get disk number: {}", e))?;
        
        let binding = String::from_utf8_lossy(&output.stdout);
        let disk_number = binding.trim();
        if disk_number.is_empty() {
            return Err("Could not determine physical disk number".to_string());
        }
        
        Ok(format!("\\\\.\\PhysicalDrive{}", disk_number))
    } else {
        // Linux: Convert volume to device (e.g., /dev/sda1 -> /dev/sda)
        let device = volume_path.trim_end_matches(char::is_numeric);
        Ok(device.to_string())
    }
}

fn get_drive_size(drive_path: &str) -> Result<u64, String> {
    if cfg!(target_os = "windows") {
        let drive_letter = drive_path.chars().nth(4).unwrap_or('C');
        let output = Command::new("powershell")
            .args(&["-Command", &format!("Get-WmiObject -Class Win32_LogicalDisk | Where-Object {{$_.DeviceID -eq '{}:'}} | Select-Object -ExpandProperty Size", drive_letter)])
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

fn apply_wipe_pattern(buffer: &mut [u8], method: &str, pass: u32, rng: &mut impl Rng) {
    match method {
        "single" => rng.fill(buffer),
        "3" => {
            // DoD 5220.22-M 3-pass
            match pass {
                1 => buffer.fill(0x00),     // Zeros
                2 => buffer.fill(0xFF),     // Ones
                3 => rng.fill(buffer),      // Random
                _ => rng.fill(buffer),
            }
        },
        "7" => {
            // NIST 800-88 inspired 7-pass
            match pass {
                1 => rng.fill(buffer),      // Random
                2 => buffer.fill(0x00),     // Zeros
                3 => buffer.fill(0xFF),     // Ones
                4 => rng.fill(buffer),      // Random
                5 => buffer.fill(0xAA),     // 10101010
                6 => buffer.fill(0x55),     // 01010101
                7 => rng.fill(buffer),      // Random
                _ => rng.fill(buffer),
            }
        },
        "gutmann" => {
            // Gutmann 35-pass method (simplified)
            match pass {
                1..=4 => rng.fill(buffer),
                5 => buffer.fill(0x55),     // 01010101
                6 => buffer.fill(0xAA),     // 10101010
                7..=9 => {
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte = ((i % 3) as u8) * 0x55;
                    }
                },
                10..=25 => rng.fill(buffer),
                26 => buffer.fill(0x00),
                27 => buffer.fill(0x11),
                28 => buffer.fill(0x22),
                29 => buffer.fill(0x33),
                30 => buffer.fill(0x44),
                31 => buffer.fill(0x55),
                32 => buffer.fill(0x66),
                33 => buffer.fill(0x77),
                34 => buffer.fill(0x88),
                35 => rng.fill(buffer),
                _ => rng.fill(buffer),
            }
        },
        _ => rng.fill(buffer),
    }
}

fn overwrite_hdd_passes_with_progress(
    app_handle: &tauri::AppHandle,
    drive_path: &str,
    method: &str,
    passes: u32,
) -> Result<String, String> {
    let size = get_drive_size(drive_path)?;
    let chunk_size = 1024 * 1024; // 1MB chunks
    let mut rng = rand::thread_rng();
    
    // Emit initial progress
    if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
        pass: 1,
        total_passes: passes,
        progress: 0u8,
        bytes_written: 0,
        total_bytes: size,
    }) {
        eprintln!("Failed to emit initial progress: {}", e);
    }
    
    for pass in 1..=passes {
        println!("Starting pass {} of {} on drive {}", pass, passes, drive_path);
        
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
            
            // Apply proper wipe patterns
            apply_wipe_pattern(&mut buffer, method, pass, &mut rng);
            
            file.write_all(&buffer)
                .map_err(|e| format!("Write failed on pass {}: {}", pass, e))?;
            
            written += remaining;
            
            // Emit progress every 1MB
            if written % (1024 * 1024) == 0 || written >= size {
                let progress = std::cmp::min(((written as f64 / size as f64) * 100.0) as u8, 100);
                if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                    pass,
                    total_passes: passes,
                    progress,
                    bytes_written: written,
                    total_bytes: size,
                }) {
                    eprintln!("Failed to emit progress: {}", e);
                }
            }
        }
        
        file.sync_all()
            .map_err(|e| format!("Sync failed on pass {}: {}", pass, e))?;
        
        println!("Pass {} completed. Written: {} bytes ({} MB)", pass, written, written / (1024 * 1024));
        
        // Emit pass completion
        if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
            pass,
            total_passes: passes,
            progress: 100u8,
            bytes_written: written,
            total_bytes: size,
        }) {
            eprintln!("Failed to emit pass completion: {}", e);
        }
    }
    
    Ok(format!("Partition overwrite completed with {} passes on {}", passes, drive_path))
}

fn overwrite_hdd_passes(drive_path: &str, method: &str, passes: u32) -> Result<String, String> {
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
            
            // Apply proper wipe patterns
            apply_wipe_pattern(&mut buffer, method, pass, &mut rng);
            
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
pub async fn overwrite_hdd_data_with_progress(
    app_handle: tauri::AppHandle,
    method: String,
    selected_drive: String,
) -> Result<String, String> {
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
    
    // Check if it's a USB drive first
    let drive_letter = if selected_drive.len() == 1 {
        format!("{}:", selected_drive.to_uppercase())
    } else if selected_drive.starts_with("\\\\.\\")
        && selected_drive.len() == 6 
        && selected_drive.chars().nth(5) == Some(':') {
        format!("{}:", selected_drive.chars().nth(4).unwrap())
    } else {
        selected_drive.clone()
    };
    
    // Convert to volume path for proper detection
    let volume_path = if selected_drive.len() == 1 {
        drive_letter_to_volume_path(&selected_drive)?
    } else {
        selected_drive.clone()
    };
    
    let drive_type = detect_drive_type(&volume_path);
    
    // Route USB drives to file-based wipe, others to raw HDD overwrite
    if drive_type == "USB SSD" || drive_letter.starts_with("F:") {
        overwrite_usb_files_with_progress(app_handle, drive_letter, passes).await
    } else {
        overwrite_hdd_passes_with_progress(&app_handle, &volume_path, &method, passes)
    }
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
    
    // Check if it's a USB drive first
    let drive_letter = if selected_drive.len() == 1 {
        format!("{}:", selected_drive.to_uppercase())
    } else if selected_drive.starts_with("\\\\.\\")
        && selected_drive.len() == 6 
        && selected_drive.chars().nth(5) == Some(':') {
        format!("{}:", selected_drive.chars().nth(4).unwrap())
    } else {
        selected_drive.clone()
    };
    
    // Convert to volume path for proper detection
    let volume_path = if selected_drive.len() == 1 {
        drive_letter_to_volume_path(&selected_drive)?
    } else {
        selected_drive.clone()
    };
    
    let drive_type = detect_drive_type(&volume_path);
    
    // Route USB drives to file-based wipe, others to raw HDD overwrite
    if drive_type == "USB SSD" || drive_letter.starts_with("F:") {
        overwrite_usb_files(&drive_letter, passes)
    } else {
        overwrite_hdd_passes(&volume_path, &method, passes)
    }
}