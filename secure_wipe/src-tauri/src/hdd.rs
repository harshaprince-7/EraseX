use tauri::{command, Emitter};
use std::process::Command;
use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom};
use rand::Rng;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs;

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
        if WIPE_CANCELLED.load(Ordering::Relaxed) {
            return Err("Wipe cancelled by user.".to_string());
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(false)
            .open(drive_path)
            .map_err(|e| format!("Failed to open drive (try running as admin): {}", e))?;
        
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek: {}", e))?;
        
        let mut written = 0u64;
        while written < size {
            if WIPE_CANCELLED.load(Ordering::Relaxed) {
                return Err("Wipe cancelled by user.".to_string());
            }

            let remaining = std::cmp::min(chunk_size, size - written);
            let mut buffer = vec![0u8; remaining as usize];
            
            apply_wipe_pattern(&mut buffer, method, pass, &mut rng);
            
            file.write_all(&buffer)
                .map_err(|e| format!("Write failed on pass {}: {}", pass, e))?;
            
            written += remaining;
            
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
    }
    
    Ok(format!("Partition overwrite completed with {} passes on {}", passes, drive_path))
}

#[command]
pub async fn overwrite_hdd_data_with_progress(
    app_handle: tauri::AppHandle,
    method: String,
    selected_drive: String,
) -> Result<String, String> {
    let passes = match method.as_str() {
        "single" => 1,
        "3" => 3,
        _ => {
            // Use Alpine bundle for advanced wiping
            return perform_alpine_hdd_wipe(&app_handle, &method, &selected_drive).await;
        }
    };
    
    let _drive_letter = if selected_drive.len() == 1 {
        format!("{}:", selected_drive.to_uppercase())
    } else if selected_drive.starts_with("\\\\.\\")
        && selected_drive.len() == 6 
        && selected_drive.chars().nth(5) == Some(':') {
        format!("{}:", selected_drive.chars().nth(4).unwrap())
    } else {
        selected_drive.clone()
    };
    
    let volume_path = if selected_drive.len() == 1 {
        drive_letter_to_volume_path(&selected_drive)?
    } else {
        selected_drive.clone()
    };
    
    overwrite_hdd_passes_with_progress(&app_handle, &volume_path, &method, passes)
}

async fn perform_alpine_hdd_wipe(
    app_handle: &tauri::AppHandle,
    method: &str,
    selected_drive: &str,
) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Extract bundled Alpine environment
        let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
        let temp_dir = "C:\\temp";
        let temp_archive = format!("{}\\alpine-hdd.tar.gz", temp_dir);
        
        fs::create_dir_all(temp_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;
        fs::write(&temp_archive, alpine_data)
            .map_err(|e| format!("Failed to write archive: {}", e))?;
        
        // Extract using tar
        let extract_result = Command::new("tar")
            .args(&["-xzf", &temp_archive, "-C", temp_dir])
            .output();
            
        if extract_result.is_err() {
            return Err("Failed to extract Alpine environment. Ensure tar is available (Git Bash/WSL).".into());
        }
        
        // Use Alpine tools for secure HDD wipe
        run_alpine_hdd_wipe(app_handle, method, selected_drive).await
    }
    
    #[cfg(target_os = "linux")]
    {
        // Direct Alpine extraction on Linux
        let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
        let temp_archive = "/tmp/alpine-hdd.tar.gz";
        
        fs::write(temp_archive, alpine_data)
            .map_err(|e| format!("Failed to write archive: {}", e))?;
        
        Command::new("tar")
            .args(&["-xzf", temp_archive, "-C", "/tmp"])
            .status()
            .map_err(|e| format!("Failed to extract: {}", e))?;
        
        run_alpine_hdd_wipe(app_handle, method, selected_drive).await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Alpine HDD wipe not supported on this platform".into())
}

async fn run_alpine_hdd_wipe(
    app_handle: &tauri::AppHandle,
    method: &str,
    selected_drive: &str,
) -> Result<String, String> {
    if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
        pass: 1,
        total_passes: 1,
        progress: 0u8,
        bytes_written: 0,
        total_bytes: 100,
    }) {
        eprintln!("Failed to emit initial progress: {}", e);
    }
    
    #[cfg(target_os = "windows")]
    {
        // Use extracted Alpine tools via WSL/Git Bash
        let drive_path = format!("{}:", selected_drive);
        
        // Try dd command for secure overwrite
        let dd_result = Command::new("bash")
            .args(&["-c", &format!("dd if=/dev/urandom of={} bs=1M status=progress", drive_path)])
            .output();
            
        if let Ok(output) = dd_result {
            if output.status.success() {
                if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                    pass: 1,
                    total_passes: 1,
                    progress: 100u8,
                    bytes_written: 100,
                    total_bytes: 100,
                }) {
                    eprintln!("Failed to emit completion progress: {}", e);
                }
                return Ok(format!("Alpine secure wipe completed on {}", drive_path));
            }
        }
        
        Err("Alpine HDD wipe failed. Use bootable media for complete hardware access.".into())
    }
    
    #[cfg(target_os = "linux")]
    {
        let drive_path = format!("/dev/{}", selected_drive);
        
        // Use dd for secure overwrite
        let dd_result = Command::new("dd")
            .args(&["if=/dev/urandom", &format!("of={}", drive_path), "bs=1M", "status=progress"])
            .output();
            
        if let Ok(output) = dd_result {
            if output.status.success() {
                if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                    pass: 1,
                    total_passes: 1,
                    progress: 100u8,
                    bytes_written: 100,
                    total_bytes: 100,
                }) {
                    eprintln!("Failed to emit completion progress: {}", e);
                }
                return Ok(format!("Alpine secure wipe completed on {}", drive_path));
            }
        }
        
        Err("Alpine HDD wipe failed".into())
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Platform not supported".into())
}

#[command]
pub async fn overwrite_usb_files_with_progress(
    app_handle: tauri::AppHandle,
    drive_letter: String,
    passes: u32,
) -> Result<String, String> {
    let drive_path = if drive_letter.len() == 1 {
        format!("{}:\\", drive_letter.to_uppercase())
    } else {
        drive_letter.clone()
    };
    
    if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
        pass: 1,
        total_passes: passes,
        progress: 0u8,
        bytes_written: 0,
        total_bytes: 100,
    }) {
        eprintln!("Failed to emit initial progress: {}", e);
    }
    
    // Get all files in the drive
    let files = std::fs::read_dir(&drive_path)
        .map_err(|e| format!("Failed to read drive: {}", e))?;
    
    let mut total_files = 0;
    let mut processed_files = 0;
    
    // Count total files
    for entry in std::fs::read_dir(&drive_path).map_err(|e| format!("Failed to count files: {}", e))? {
        if entry.is_ok() {
            total_files += 1;
        }
    }
    
    // Overwrite each file multiple passes
    for pass in 1..=passes {
        if WIPE_CANCELLED.load(Ordering::Relaxed) {
            return Err("Wipe cancelled by user.".to_string());
        }
        
        processed_files = 0;
        for entry in std::fs::read_dir(&drive_path).map_err(|e| format!("Failed to read drive: {}", e))? {
            if let Ok(entry) = entry {
                if WIPE_CANCELLED.load(Ordering::Relaxed) {
                    return Err("Wipe cancelled by user.".to_string());
                }
                
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = overwrite_file_passes(&path, 1) {
                        eprintln!("Failed to overwrite {}: {}", path.display(), e);
                    }
                }
                
                processed_files += 1;
                let progress = ((processed_files * 100) / total_files.max(1)) as u8;
                
                if let Err(e) = app_handle.emit("wipe-progress", ProgressPayload {
                    pass,
                    total_passes: passes,
                    progress,
                    bytes_written: processed_files as u64,
                    total_bytes: total_files as u64,
                }) {
                    eprintln!("Failed to emit progress: {}", e);
                }
            }
        }
    }
    
    // Delete all files after overwriting
    for entry in std::fs::read_dir(&drive_path).map_err(|e| format!("Failed to read drive: {}", e))? {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    
    if let Err(e) = app_handle.emit("wipe-completed", ()) {
        eprintln!("Failed to emit completion event: {}", e);
    }
    
    Ok(format!("USB drive {} overwritten with {} passes", drive_letter, passes))
}

fn overwrite_file_passes(file_path: &std::path::Path, passes: u32) -> Result<(), String> {
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let file_size = metadata.len();
    
    for pass in 1..=passes {
        let mut file = OpenOptions::new()
            .write(true)
            .open(file_path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek: {}", e))?;
        
        let pattern = match pass {
            1 => 0x00u8,
            2 => 0xFFu8,
            _ => rand::thread_rng().gen::<u8>(),
        };
        
        let buffer = vec![pattern; 4096];
        let mut remaining = file_size;
        
        while remaining > 0 {
            let write_size = std::cmp::min(remaining, buffer.len() as u64) as usize;
            file.write_all(&buffer[..write_size])
                .map_err(|e| format!("Failed to write: {}", e))?;
            remaining -= write_size as u64;
        }
        
        file.sync_all()
            .map_err(|e| format!("Failed to sync: {}", e))?;
    }
    
    Ok(())
}

#[command]
pub async fn clear_drive_data_with_progress(
    app_handle: tauri::AppHandle,
    selected_usb: String,
) -> Result<String, String> {
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
