use tauri::command;
use std::process::Command;
use std::fs;

#[cfg(target_os = "linux")]
extern crate libc;

#[command]
pub async fn alpine_ssd_erase(drive_input: String) -> Result<String, String> {
    // Use Alpine bundle for SSD erase on both Windows and Linux
    extract_and_run_alpine_ssd(&drive_input).await
}

async fn extract_and_run_alpine_ssd(_drive_input: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // Extract Alpine environment on Windows
        fs::create_dir_all("C:\\temp").map_err(|e| format!("Failed to create temp dir: {}", e))?;
        
        let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
        let temp_archive = "C:\\temp\\alpine-ssd.tar.gz";
        
        fs::write(temp_archive, alpine_data)
            .map_err(|e| format!("Failed to write archive: {}", e))?;
        
        // Extract using tar (requires Git Bash or WSL)
        let extract_result = Command::new("tar")
            .args(&["-xzf", temp_archive, "-C", "C:\\temp"])
            .output();
            
        if extract_result.is_err() {
            return Err("Failed to extract Alpine environment. Ensure tar is available (Git Bash/WSL).".into());
        }
        
        // Use bootable media for complete hardware access on Windows
        Err("Use the Bootable USB/ISO feature for complete SSD hardware access on Windows.".into())
    }
    
    #[cfg(target_os = "linux")]
    {
        // Extract and run Alpine tools directly on Linux
        let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
        let temp_archive = "/tmp/alpine-ssd.tar.gz";
        
        fs::write(temp_archive, alpine_data)
            .map_err(|e| format!("Failed to write archive: {}", e))?;
        
        Command::new("tar")
            .args(&["-xzf", temp_archive, "-C", "/tmp"])
            .status()
            .map_err(|e| format!("Failed to extract: {}", e))?;
        
        run_alpine_ssd_wipe(drive_input).await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Platform not supported".into())
}

#[cfg(target_os = "linux")]
async fn run_alpine_ssd_wipe(drive_input: &str) -> Result<String, String> {
    // Check if running as root
    if unsafe { libc::geteuid() } != 0 {
        return Err("Root privileges required for direct drive access".into());
    }
    
    let drive_name = drive_input.replace("/dev/", "");
    let drive_path = format!("/dev/{}", drive_name);
    
    // Check if it's an SSD
    let rotational_path = format!("/sys/block/{}/queue/rotational", drive_name);
    let is_ssd = std::fs::read_to_string(&rotational_path)
        .map(|content| content.trim() == "0")
        .unwrap_or(false);
    
    if !is_ssd {
        return Err("This function is for SSDs only. Use HDD wipe methods for traditional drives.".into());
    }
    
    // Detect SSD type and use appropriate method
    if drive_name.starts_with("nvme") {
        // NVMe SSD - use crypto erase
        let nvme_result = Command::new("nvme")
            .args(&["format", &drive_path, "--ses=1", "--force"])
            .output();
        
        if let Ok(output) = nvme_result {
            if output.status.success() {
                return Ok("NVMe SSD crypto-erase completed (instant)".into());
            }
        }
        
        return Err("NVMe crypto-erase failed - nvme-cli not available".into());
    }
    
    // SATA/USB SSD - use ATA secure erase
    let set_pass = Command::new("hdparm")
        .args(&["--user-master", "u", "--security-set-pass", "p", &drive_path])
        .output();
    
    if let Ok(_) = set_pass {
        let erase = Command::new("hdparm")
            .args(&["--user-master", "u", "--security-erase", "p", &drive_path])
            .output();
        
        if let Ok(output) = erase {
            if output.status.success() {
                return Ok("SATA SSD secure erase completed".into());
            }
        }
    }
    
    Err("SATA SSD secure erase failed - hdparm not available or drive locked".into())
}

#[cfg(not(target_os = "linux"))]
async fn run_alpine_ssd_wipe(_drive_input: &str) -> Result<String, String> {
    Err("Alpine SSD wipe only available on Linux".into())
}

#[command]
pub async fn detect_ssd_info(selected_usb: String) -> Result<String, String> {
    let _drive_name = if selected_usb.len() == 1 {
        format!("sd{}", selected_usb.to_lowercase())
    } else {
        selected_usb.replace("/dev/", "")
    };
    
    #[cfg(target_os = "linux")]
    {
        // Check if it's an SSD
        let rotational_path = format!("/sys/block/{}/queue/rotational", drive_name);
        let is_ssd = std::fs::read_to_string(&rotational_path)
            .map(|content| content.trim() == "0")
            .unwrap_or(false);
        
        if !is_ssd {
            return Ok("HDD detected - use HDD wipe methods".into());
        }
        
        // Detect SSD type
        let mut ssd_type = "Unknown SSD";
        let mut interface = "Unknown";
        let mut erase_method = "ATA Secure Erase";
        
        // Check if it's NVMe
        if drive_name.starts_with("nvme") {
            ssd_type = "NVMe SSD";
            interface = "PCIe/NVMe";
            erase_method = "NVMe Crypto Erase (Instant)";
        } else {
            // Check transport type for SATA SSDs
            let transport_path = format!("/sys/block/{}/device/transport", drive_name);
            if let Ok(transport) = std::fs::read_to_string(&transport_path) {
                match transport.trim() {
                    "sata" => {
                        ssd_type = "SATA SSD";
                        interface = "SATA";
                    }
                    "usb" => {
                        ssd_type = "USB SSD";
                        interface = "USB";
                    }
                    _ => {
                        ssd_type = "SATA SSD";
                        interface = "SATA";
                    }
                }
            }
        }
        
        // Get model info if available
        let model_path = format!("/sys/block/{}/device/model", drive_name);
        let model = std::fs::read_to_string(&model_path)
            .unwrap_or_else(|_| "Unknown Model".to_string())
            .trim()
            .to_string();
        
        Ok(format!("{} ({}) - {} - Alpine Method: {}", ssd_type, interface, model, erase_method))
    }
    
    #[cfg(not(target_os = "linux"))]
    Ok("Drive type detection available on Linux only".into())
}

#[command]
pub async fn check_erase_support() -> Result<String, String> {
    Ok("Alpine bundle provides nvme-cli and hdparm tools for all SSD types".into())
}

#[command]
pub async fn one_click_secure_erase(selected_usb: String) -> Result<String, String> {
    alpine_ssd_erase(selected_usb).await
}

