use std::process::Command;
use std::fs;
use tauri::command;

#[command]
pub fn create_iso() -> Result<String, String> {
    let iso_path = "secure_wipe_boot.iso";
    
    // Create minimal Linux ISO with secure wipe tools
    let output = Command::new("genisoimage")
        .args(&[
            "-o", iso_path,
            "-b", "isolinux/isolinux.bin",
            "-c", "isolinux/boot.cat",
            "-no-emul-boot",
            "-boot-load-size", "4",
            "-boot-info-table",
            "boot/"
        ])
        .output()
        .map_err(|e| format!("Failed to create ISO: {}", e))?;
    
    if output.status.success() {
        Ok(format!("ISO created: {}", iso_path))
    } else {
        Err("ISO creation failed".to_string())
    }
}

#[command] 
pub fn build_bootable_environment() -> Result<String, String> {
    // Create boot directory structure
    fs::create_dir_all("boot/isolinux")
        .map_err(|e| format!("Failed to create directory: {}", e))?;
    
    // Copy secure wipe binary
    fs::copy("target/release/secure_wipe", "boot/secure_wipe")
        .map_err(|e| format!("Failed to copy binary: {}", e))?;
    
    // Create autorun script
    let autorun = r#"#!/bin/bash
echo "Secure Wipe Bootable Environment"
echo "Available drives:"
lsblk
echo "Starting secure wipe tool..."
./secure_wipe
"#;
    
    fs::write("boot/autorun.sh", autorun)
        .map_err(|e| format!("Failed to write script: {}", e))?;
    
    Ok("Bootable environment ready".to_string())
}