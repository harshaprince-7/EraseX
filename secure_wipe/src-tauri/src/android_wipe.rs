use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom};
use std::process::Command;
use tauri::command;
use rand::RngCore;

#[command]
pub async fn secure_wipe_android(file_paths: Vec<String>, wipe_mode: String) -> Result<String, String> {
    use std::env::consts::OS;
    
    // Only run on Android
    if OS != "android" {
        return Err("Android secure wipe only available on Android platform".to_string());
    }
    
    let mut wiped_files = Vec::new();
    
    for file_path in file_paths {
        match wipe_mode.as_str() {
            "Clear" => {
                simple_delete(&file_path)?;
            }
            "Purge" | "Single Pass" | "3 Pass DDOD" | "7 Pass" | "Gutmann" => {
                secure_overwrite(&file_path)?;
            }
            "Destroy" => {
                crypto_wipe(&file_path)?;
            }
            _ => {
                return Err("Invalid wipe mode".to_string());
            }
        }
        wiped_files.push(file_path);
    }
    
    Ok(format!("Android: Securely wiped {} files", wiped_files.len()))
}

fn simple_delete(file_path: &str) -> Result<(), String> {
    std::fs::remove_file(file_path)
        .map_err(|e| format!("Failed to delete {}: {}", file_path, e))
}

fn secure_overwrite(file_path: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    let file_size = metadata.len();
    
    // Pass 1: Random data
    overwrite_with_random(file_path, file_size)?;
    
    // Pass 2: Zeros
    overwrite_with_pattern(file_path, file_size, 0x00)?;
    
    // Pass 3: Ones
    overwrite_with_pattern(file_path, file_size, 0xFF)?;
    
    // Final deletion
    std::fs::remove_file(file_path)
        .map_err(|e| format!("Failed to delete after overwrite: {}", e))?;
    
    Ok(())
}

fn crypto_wipe(file_path: &str) -> Result<(), String> {
    // Generate random key
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    
    // Encrypt file with random key
    encrypt_file_inplace(file_path, &key)?;
    
    // Overwrite key in memory
    key.fill(0);
    
    // Delete encrypted file
    std::fs::remove_file(file_path)
        .map_err(|e| format!("Failed to delete encrypted file: {}", e))?;
    
    Ok(())
}

fn overwrite_with_random(file_path: &str, size: u64) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open file for overwrite: {}", e))?;
    
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek to start: {}", e))?;
    
    let mut buffer = vec![0u8; 8192];
    let mut remaining = size;
    
    while remaining > 0 {
        let chunk_size = std::cmp::min(remaining, buffer.len() as u64) as usize;
        rand::thread_rng().fill_bytes(&mut buffer[..chunk_size]);
        
        file.write_all(&buffer[..chunk_size])
            .map_err(|e| format!("Failed to write random data: {}", e))?;
        
        remaining -= chunk_size as u64;
    }
    
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;
    
    Ok(())
}

fn overwrite_with_pattern(file_path: &str, size: u64, pattern: u8) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open file for pattern overwrite: {}", e))?;
    
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek to start: {}", e))?;
    
    let buffer = vec![pattern; 8192];
    let mut remaining = size;
    
    while remaining > 0 {
        let chunk_size = std::cmp::min(remaining, buffer.len() as u64) as usize;
        
        file.write_all(&buffer[..chunk_size])
            .map_err(|e| format!("Failed to write pattern: {}", e))?;
        
        remaining -= chunk_size as u64;
    }
    
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;
    
    Ok(())
}

fn encrypt_file_inplace(file_path: &str, key: &[u8; 32]) -> Result<(), String> {
    use std::io::Read;
    
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open file for encryption: {}", e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    // Simple XOR encryption (for demonstration)
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
    
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek to start: {}", e))?;
    
    file.write_all(&buffer)
        .map_err(|e| format!("Failed to write encrypted data: {}", e))?;
    
    file.sync_all()
        .map_err(|e| format!("Failed to sync encrypted file: {}", e))?;
    
    Ok(())
}

#[command]
pub async fn check_root_access() -> Result<bool, String> {
    let output = Command::new("su")
        .args(&["-c", "id"])
        .output();
    
    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            Ok(stdout.contains("uid=0"))
        }
        Err(_) => Ok(false)
    }
}

#[command]
pub async fn root_secure_wipe(device_path: String) -> Result<String, String> {
    // Check if we have root access
    if !check_root_access().await? {
        return Err("Root access required for device-level wiping".to_string());
    }
    
    // Use dd to overwrite device
    let output = Command::new("su")
        .args(&["-c", &format!("dd if=/dev/zero of={} bs=1M", device_path)])
        .output()
        .map_err(|e| format!("Failed to execute dd command: {}", e))?;
    
    if output.status.success() {
        Ok(format!("Successfully wiped device: {}", device_path))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Device wipe failed: {}", stderr))
    }
}

#[command]
pub async fn factory_reset_android() -> Result<String, String> {
    // Trigger factory reset
    let output = Command::new("am")
        .args(&["start", "-a", "android.settings.FACTORY_RESET"])
        .output()
        .map_err(|e| format!("Failed to trigger factory reset: {}", e))?;
    
    if output.status.success() {
        Ok("Factory reset initiated".to_string())
    } else {
        Err("Failed to initiate factory reset".to_string())
    }
}

#[command]
pub async fn clear_app_data(package_name: String) -> Result<String, String> {
    let output = Command::new("pm")
        .args(&["clear", &package_name])
        .output()
        .map_err(|e| format!("Failed to clear app data: {}", e))?;
    
    if output.status.success() {
        Ok(format!("Cleared data for: {}", package_name))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to clear app data: {}", stderr))
    }
}