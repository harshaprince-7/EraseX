use tauri::command;
use std::process::Command;
use serde::Serialize;

#[cfg(target_os = "windows")]
use {
    std::ffi::OsStr,
    std::os::windows::ffi::OsStrExt,
    std::ptr, std::mem,
    winapi::um::winnt::{HANDLE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE},
    winapi::um::fileapi::{CreateFileW, OPEN_EXISTING},
    winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    winapi::um::ioapiset::DeviceIoControl,
    winapi::um::processthreadsapi::GetCurrentProcess,
    winapi::um::securitybaseapi::GetTokenInformation,
    winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
};

#[cfg(target_os = "windows")]
#[repr(C)]
struct StorageProtocolCommand {
    version: u32,
    length: u32,
    protocol_type: u32,
    flags: u32,
    return_status: u32,
    error_info_length: u32,
    data_to_device_transfer_length: u32,
    data_from_device_transfer_length: u32,
    timeout_value: u32,
    error_info_offset: u32,
    data_to_device_offset: u32,
    data_from_device_offset: u32,
    command_length: u32,
    fixed_protocol_return_data: u32,
    command_specific: [u8; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct AtaPassThroughEx {
    length: u16,
    ata_flags: u16,
    path_id: u8,
    target_id: u8,
    lun: u8,
    reserved_as_uchar: u8,
    data_transfer_length: u32,
    timeout_value: u32,
    reserved_as_ulong: u32,
    data_buffer_offset: u32,
    previous_task_file: [u8; 8],
    current_task_file: [u8; 8],
}

#[derive(Debug, Clone, Serialize)]
pub struct EraseResult {
    pub success: bool,
    pub message: String,
    pub requires_reboot: bool,
}

#[command]
pub async fn hybrid_erase(drive_input: String) -> Result<EraseResult, String> {
    // Check admin privileges first
    if !check_admin_privileges() {
        return Err("Administrator privileges required for secure erase".into());
    }
    
    let hardware_result = match std::env::consts::OS {
        "windows" => perform_windows_erase(&drive_input).await,
        "linux" => perform_linux_erase(&drive_input).await,
        _ => Err("Unsupported OS".into()),
    };
    
    match hardware_result {
        Ok(msg) => Ok(EraseResult {
            success: true,
            message: msg,
            requires_reboot: false,
        }),
        Err(_) => {
            // Try bundled Linux environment
            if let Ok(linux_msg) = launch_bundled_linux(&drive_input).await {
                Ok(EraseResult {
                    success: true,
                    message: linux_msg,
                    requires_reboot: true,
                })
            } else if let Ok(trim_msg) = perform_trim_fallback(&drive_input).await {
                Ok(EraseResult {
                    success: true,
                    message: trim_msg,
                    requires_reboot: false,
                })
            } else {
                prepare_linux_reboot(drive_input).await
            }
        }
    }
}

fn check_admin_privileges() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            let mut token_handle = ptr::null_mut();
            let process = GetCurrentProcess();
            
            if winapi::um::processthreadsapi::OpenProcessToken(
                process, TOKEN_QUERY, &mut token_handle
            ) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0u32;
            
            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );
            
            winapi::um::handleapi::CloseHandle(token_handle);
            result != 0 && elevation.TokenIsElevated != 0
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() == 0 }
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    false
}

async fn perform_windows_erase(drive_input: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        if let Some(drive_char) = drive_input.chars().next() {
            // Try DeviceIoControl for hardware erase
            if let Ok(msg) = windows_device_erase(drive_char) {
                return Ok(msg);
            }
        }
    }
    
    Err("Windows hardware erase not supported".into())
}

#[cfg(target_os = "windows")]
fn windows_device_erase(drive_letter: char) -> Result<String, String> {
    let drive_path = format!("\\\\.\\PhysicalDrive0");
    let wide_path: Vec<u16> = OsStr::new(&drive_path).encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let handle = CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            return Err("Failed to open drive".into());
        }

        // Try NVMe with proper STORAGE_PROTOCOL_COMMAND structure
        let mut nvme_cmd = StorageProtocolCommand {
            version: 1,
            length: mem::size_of::<StorageProtocolCommand>() as u32,
            protocol_type: 3, // ProtocolTypeNvme
            flags: 1, // STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST
            return_status: 0,
            error_info_length: 0,
            data_to_device_transfer_length: 0,
            data_from_device_transfer_length: 0,
            timeout_value: 30,
            error_info_offset: 0,
            data_to_device_offset: 0,
            data_from_device_offset: 0,
            command_length: 64,
            fixed_protocol_return_data: 0,
            command_specific: [0; 16],
        };
        
        // NVMe Format command (0x80) with crypto erase
        nvme_cmd.command_specific[0] = 0x80; // Format NVM
        nvme_cmd.command_specific[11] = 0x01; // Secure Erase Setting = Crypto Erase
        
        let mut bytes_returned = 0u32;
        let nvme_success = DeviceIoControl(
            handle,
            0x004D0008, // IOCTL_STORAGE_PROTOCOL_COMMAND
            &mut nvme_cmd as *mut _ as *mut _,
            mem::size_of::<StorageProtocolCommand>() as u32,
            &mut nvme_cmd as *mut _ as *mut _,
            mem::size_of::<StorageProtocolCommand>() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        );
        
        if nvme_success != 0 {
            CloseHandle(handle);
            return Ok("NVMe crypto-erase completed".into());
        }
        
        // Try ATA with proper ATA_PASS_THROUGH_EX structure
        let mut ata_cmd = AtaPassThroughEx {
            length: mem::size_of::<AtaPassThroughEx>() as u16,
            ata_flags: 0x02, // ATA_FLAGS_DATA_OUT
            path_id: 0,
            target_id: 0,
            lun: 0,
            reserved_as_uchar: 0,
            data_transfer_length: 512,
            timeout_value: 120,
            reserved_as_ulong: 0,
            data_buffer_offset: mem::size_of::<AtaPassThroughEx>() as u32,
            previous_task_file: [0; 8],
            current_task_file: [0; 8],
        };
        
        // ATA SECURITY ERASE UNIT command (0xF4)
        ata_cmd.current_task_file[6] = 0xF4;
        
        let mut buffer = vec![0u8; mem::size_of::<AtaPassThroughEx>() + 512];
        ptr::copy_nonoverlapping(
            &ata_cmd as *const _ as *const u8,
            buffer.as_mut_ptr(),
            mem::size_of::<AtaPassThroughEx>(),
        );
        
        let ata_success = DeviceIoControl(
            handle,
            0x0004D02C, // IOCTL_ATA_PASS_THROUGH
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        );
        
        CloseHandle(handle);
        
        if ata_success != 0 {
            Ok("ATA secure erase completed".into())
        } else {
            Err("Hardware erase failed".into())
        }
    }
}

async fn perform_linux_erase(drive_input: &str) -> Result<String, String> {
    // Check if tools are available
    let nvme_available = Command::new("which").arg("nvme").output()
        .map_or(false, |out| out.status.success());
    let hdparm_available = Command::new("which").arg("hdparm").output()
        .map_or(false, |out| out.status.success());
    
    if !nvme_available && !hdparm_available {
        return Err("nvme-cli and hdparm not installed. Run: sudo apt install nvme-cli hdparm".into());
    }
    
    // Try NVMe crypto erase if available
    if nvme_available {
        let nvme_result = Command::new("nvme")
            .args(&["format", drive_input, "--ses=1", "--force"])
            .output();
        
        if let Ok(output) = nvme_result {
            if output.status.success() {
                return Ok("NVMe crypto-erase completed".into());
            }
        }
    }
    
    // Try ATA secure erase if available
    if hdparm_available {
        let set_pass = Command::new("hdparm")
            .args(&["--user-master", "u", "--security-set-pass", "p", drive_input])
            .output();
        
        if let Ok(_) = set_pass {
            let erase = Command::new("hdparm")
                .args(&["--user-master", "u", "--security-erase", "p", drive_input])
                .output();
            
            if let Ok(output) = erase {
                if output.status.success() {
                    return Ok("ATA secure erase completed".into());
                }
            }
        }
    }
    
    Err("Hardware erase failed or tools missing".into())
}

async fn perform_trim_fallback(drive_input: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("defrag")
            .args(&[&format!("{}:", drive_input.chars().next().unwrap_or('C')), "/L"])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok("TRIM completed (WARNING: Not equivalent to secure erase)".into()),
            _ => Err("TRIM failed".into()),
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("fstrim")
            .args(&["-av"])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok("TRIM completed (WARNING: Not equivalent to secure erase)".into()),
            _ => Err("TRIM failed".into()),
        }
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("TRIM not supported".into())
}

async fn launch_bundled_linux(drive_input: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use std::fs;
        use std::path::Path;
        
        // Create temp directory
        fs::create_dir_all("C:\\temp").map_err(|e| format!("Failed to create temp dir: {}", e))?;
        
        // Extract bundled Alpine Linux environment
        let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
        let temp_archive = "C:\\temp\\alpine-nvme.tar.gz";
        let extract_dir = "C:\\temp\\alpine_extract";
        
        // Write archive to temp
        fs::write(temp_archive, alpine_data)
            .map_err(|e| format!("Failed to write archive: {}", e))?;
        
        // Extract using tar (requires Git Bash or WSL)
        let extract_result = Command::new("tar")
            .args(&["-xzf", temp_archive, "-C", "C:\\temp"])
            .output();
            
        if extract_result.is_err() {
            // Fallback: Try PowerShell extraction
            let ps_script = format!(
                "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('{}', '{}')",
                temp_archive, extract_dir
            );
            
            Command::new("powershell")
                .args(&["-Command", &ps_script])
                .output()
                .map_err(|e| format!("Failed to extract archive: {}", e))?;
        }
        
        // Run wipe directly using extracted Alpine tools
        run_extracted_alpine_wipe(drive_input, extract_dir).await
    }
    
    #[cfg(target_os = "linux")]
    {
        // Direct extraction and execution on Linux
        extract_and_run_alpine(drive_input).await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Bundled Linux environment not supported on this platform".into())
}

async fn prepare_linux_reboot(drive_input: String) -> Result<EraseResult, String> {
    // Try to use bundled Alpine environment first
    match launch_bundled_linux(&drive_input).await {
        Ok(msg) => Ok(EraseResult {
            success: true,
            message: msg,
            requires_reboot: false,
        }),
        Err(_) => Ok(EraseResult {
            success: false,
            message: format!("Drive {} requires bootable media. Use the 'Bootable USB/ISO' feature to create secure wipe media.", drive_input),
            requires_reboot: true,
        })
    }
}

async fn run_extracted_alpine_wipe(drive_input: &str, _alpine_dir: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // On Windows, suggest using the existing bootable creation method
        Err("Use the dedicated Bootable USB/ISO feature for offline wiping. This provides a complete Alpine Linux environment.".into())
    }
    
    #[cfg(target_os = "linux")]
    {
        // On Linux, run the wipe directly
        run_alpine_wipe(drive_input).await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Platform not supported".into())
}

async fn extract_and_run_alpine(drive_input: &str) -> Result<String, String> {
    use std::fs;
    
    // Extract Alpine environment to /tmp
    let alpine_data = include_bytes!("../assets/alpine-nvme.tar.gz");
    let temp_archive = "/tmp/alpine-nvme.tar.gz";
    
    fs::write(temp_archive, alpine_data)
        .map_err(|e| format!("Failed to write archive: {}", e))?;
    
    // Extract archive
    Command::new("tar")
        .args(&["-xzf", temp_archive, "-C", "/tmp"])
        .status()
        .map_err(|e| format!("Failed to extract: {}", e))?;
    
    // Run secure wipe directly
    run_alpine_wipe(drive_input).await
}



#[cfg(target_os = "linux")]
async fn run_alpine_wipe(drive_input: &str) -> Result<String, String> {
    // Check if running as root
    if unsafe { libc::geteuid() } != 0 {
        return Err("Root privileges required for direct drive access".into());
    }
    
    // Detect drive type and run appropriate wipe
    let drive_path = format!("/dev/{}", drive_input);
    
    // Check if it's an SSD
    let rotational_path = format!("/sys/block/{}/queue/rotational", drive_input);
    let is_ssd = std::fs::read_to_string(&rotational_path)
        .map(|content| content.trim() == "0")
        .unwrap_or(false);
    
    if is_ssd {
        // Try NVMe crypto erase first
        let nvme_result = Command::new("nvme")
            .args(&["format", &drive_path, "--ses=1", "--force"])
            .output();
        
        if let Ok(output) = nvme_result {
            if output.status.success() {
                return Ok("SSD crypto-erase completed using NVMe command".into());
            }
        }
        
        // Fallback to ATA secure erase
        let set_pass = Command::new("hdparm")
            .args(&["--user-master", "u", "--security-set-pass", "p", &drive_path])
            .output();
        
        if let Ok(_) = set_pass {
            let erase = Command::new("hdparm")
                .args(&["--user-master", "u", "--security-erase", "p", &drive_path])
                .output();
            
            if let Ok(output) = erase {
                if output.status.success() {
                    return Ok("SSD secure erase completed using ATA command".into());
                }
            }
        }
        
        return Err("SSD secure erase failed - tools not available".into());
    } else {
        // HDD - use multi-pass overwrite
        let passes = [
            ("zero", "/dev/zero"),
            ("random", "/dev/urandom"),
            ("zero", "/dev/zero"),
        ];
        
        for (pass_name, source) in &passes {
            println!("Running {} pass...", pass_name);
            let result = Command::new("dd")
                .args(&[&format!("if={}", source), &format!("of={}", drive_path), "bs=1M", "status=progress"])
                .status();
            
            if result.is_err() {
                return Err(format!("Failed during {} pass", pass_name));
            }
        }
        
        // Sync to ensure all data is written
        Command::new("sync").status().ok();
        
        Ok("HDD multi-pass wipe completed (3 passes)".into())
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_alpine_wipe(_drive_input: &str) -> Result<String, String> {
    Err("Alpine wipe only available on Linux".into())
}

#[command]
pub async fn detect_ssd_info(selected_usb: String) -> Result<String, String> {
    let drive_path = if selected_usb.len() == 1 {
        format!("/dev/sd{}", selected_usb.to_lowercase())
    } else {
        selected_usb
    };
    
    #[cfg(target_os = "linux")]
    {
        let rotational_path = format!("/sys/block/{}/queue/rotational", drive_path.replace("/dev/", ""));
        let is_ssd = std::fs::read_to_string(&rotational_path)
            .map(|content| content.trim() == "0")
            .unwrap_or(false);
        
        if is_ssd {
            Ok("SSD detected - supports hardware crypto-erase".into())
        } else {
            Ok("HDD detected - will use multi-pass overwrite".into())
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    Ok("Drive type detection available on Linux only".into())
}

#[command]
pub async fn check_erase_support() -> Result<String, String> {
    let nvme_available = Command::new("which").arg("nvme").output()
        .map_or(false, |out| out.status.success());
    let hdparm_available = Command::new("which").arg("hdparm").output()
        .map_or(false, |out| out.status.success());
    
    if nvme_available && hdparm_available {
        Ok("Full SSD erase support available (nvme-cli + hdparm)".into())
    } else if nvme_available {
        Ok("NVMe erase support available".into())
    } else if hdparm_available {
        Ok("ATA secure erase support available".into())
    } else {
        Ok("No hardware erase tools available - install nvme-cli and hdparm".into())
    }
}

#[command]
pub async fn one_click_secure_erase(selected_usb: String) -> Result<String, String> {
    hybrid_erase(selected_usb).await.map(|result| result.message)
}

#[command]
pub async fn initiate_reboot() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        Command::new("shutdown")
            .args(&["/r", "/t", "10", "/c", "Rebooting to Secure Wipe Environment"])
            .output()
            .map_err(|_| "Failed to initiate reboot")?;
        
        Ok("System will reboot to Linux environment in 10 seconds".into())
    }
    
    #[cfg(not(target_os = "windows"))]
    Err("Reboot only supported on Windows".into())
}

