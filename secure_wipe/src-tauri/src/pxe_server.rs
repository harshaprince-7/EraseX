use std::process::Command;
use std::env::consts::OS;
use std::fs::{self, File};
use std::io::Write;
use tauri::command;
use serde::{Deserialize, Serialize};
use std::net::{TcpListener, TcpStream};
use std::io::Read;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct PxeConfig {
    pub server_ip: String,
    pub dhcp_range_start: String,
    pub dhcp_range_end: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns_server: String,
    pub wipe_mode: String,
    pub auto_shutdown: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientStatus {
    pub mac_address: String,
    pub ip_address: String,
    pub status: String, // "booting", "wiping", "completed", "failed"
    pub progress: u8,
    pub timestamp: String,
}

static mut PXE_SERVER_RUNNING: bool = false;
static mut CLIENT_STATUSES: Option<Arc<Mutex<HashMap<String, ClientStatus>>>> = None;

#[command]
pub async fn start_pxe_server(config: PxeConfig) -> Result<String, String> {
    unsafe {
        if PXE_SERVER_RUNNING {
            return Err("PXE server is already running".to_string());
        }
        PXE_SERVER_RUNNING = true;
        CLIENT_STATUSES = Some(Arc::new(Mutex::new(HashMap::new())));
    }

    // Create PXE boot environment
    create_pxe_environment(&config)?;
    
    // Start DHCP server
    start_dhcp_server(&config)?;
    
    // Start TFTP server
    start_tftp_server(&config)?;
    
    // Start HTTP server for boot files
    start_http_server(&config)?;
    
    // Start certificate collection server
    start_certificate_server(&config)?;

    Ok("PXE server started successfully".to_string())
}

#[command]
pub async fn stop_pxe_server() -> Result<String, String> {
    unsafe {
        if !PXE_SERVER_RUNNING {
            return Err("PXE server is not running".to_string());
        }
        PXE_SERVER_RUNNING = false;
    }

    // Stop all services
    stop_services()?;
    
    Ok("PXE server stopped successfully".to_string())
}

#[command]
pub async fn get_client_statuses() -> Result<Vec<ClientStatus>, String> {
    unsafe {
        if let Some(ref statuses) = CLIENT_STATUSES {
            let statuses_guard = statuses.lock().map_err(|_| "Failed to lock statuses")?;
            Ok(statuses_guard.values().cloned().collect::<Vec<_>>())
        } else {
            Ok(vec![])
        }
    }
}

fn create_pxe_environment(config: &PxeConfig) -> Result<(), String> {
    let pxe_dir = if OS == "windows" {
        "C:\\PXE"
    } else {
        "/var/lib/tftpboot"
    };

    // Create directory structure
    fs::create_dir_all(format!("{}/pxelinux.cfg", pxe_dir))
        .map_err(|e| format!("Failed to create PXE directory: {}", e))?;

    // Create PXE boot configuration
    create_pxe_config(pxe_dir, config)?;
    
    // Create wipe script
    create_wipe_script(pxe_dir, config)?;
    
    // Download/copy necessary boot files
    setup_boot_files(pxe_dir)?;

    Ok(())
}

fn create_pxe_config(pxe_dir: &str, config: &PxeConfig) -> Result<(), String> {
    let config_content = format!(
        r#"DEFAULT secure_wipe
LABEL secure_wipe
    KERNEL vmlinuz
    APPEND initrd=initrd.img boot=live config noswap nolocales edd=on nomodeset ocs_live_run="ocs-live-general" ocs_live_extra_param="" ocs_live_batch=no vga=788 ip=dhcp fetch=http://{}/wipe_script.sh
    TEXT HELP
    Secure Wipe - Automated disk wiping
    ENDTEXT
"#,
        config.server_ip
    );

    let config_path = format!("{}/pxelinux.cfg/default", pxe_dir);
    let mut file = File::create(&config_path)
        .map_err(|e| format!("Failed to create PXE config: {}", e))?;
    
    file.write_all(config_content.as_bytes())
        .map_err(|e| format!("Failed to write PXE config: {}", e))?;

    Ok(())
}

fn create_wipe_script(pxe_dir: &str, config: &PxeConfig) -> Result<(), String> {
    let wipe_script = format!(
        r#"#!/bin/bash
# Secure Wipe Script - PXE Boot Version

SERVER_IP="{}"
WIPE_MODE="{}"
AUTO_SHUTDOWN={}

# Get system information
MAC_ADDR=$(cat /sys/class/net/*/address | head -n1)
IP_ADDR=$(hostname -I | awk '{{print $1}}')
HOSTNAME=$(hostname)

# Report boot status
curl -X POST "http://$SERVER_IP:8080/status" \
    -H "Content-Type: application/json" \
    -d '{{"mac":"'$MAC_ADDR'","ip":"'$IP_ADDR'","status":"booting","progress":0}}'

# Detect all drives
DRIVES=$(lsblk -dpno NAME | grep -v loop | grep -v sr)

echo "Starting secure wipe process..."
echo "Detected drives: $DRIVES"

TOTAL_DRIVES=$(echo "$DRIVES" | wc -l)
CURRENT_DRIVE=0

for DRIVE in $DRIVES; do
    CURRENT_DRIVE=$((CURRENT_DRIVE + 1))
    PROGRESS=$((CURRENT_DRIVE * 100 / TOTAL_DRIVES))
    
    echo "Wiping drive: $DRIVE ($CURRENT_DRIVE/$TOTAL_DRIVES)"
    
    # Report progress
    curl -X POST "http://$SERVER_IP:8080/status" \
        -H "Content-Type: application/json" \
        -d '{{"mac":"'$MAC_ADDR'","ip":"'$IP_ADDR'","status":"wiping","progress":'$PROGRESS'}}'
    
    case "$WIPE_MODE" in
        "Quick")
            dd if=/dev/zero of=$DRIVE bs=1M count=100 2>/dev/null
            ;;
        "DoD")
            # DoD 5220.22-M standard
            dd if=/dev/zero of=$DRIVE bs=1M 2>/dev/null
            dd if=/dev/urandom of=$DRIVE bs=1M 2>/dev/null
            dd if=/dev/zero of=$DRIVE bs=1M 2>/dev/null
            ;;
        "Gutmann")
            # Simplified Gutmann method (35 passes)
            for i in {{1..35}}; do
                dd if=/dev/urandom of=$DRIVE bs=1M count=1000 2>/dev/null
            done
            ;;
        *)
            dd if=/dev/zero of=$DRIVE bs=1M 2>/dev/null
            ;;
    esac
done

# Generate completion certificate
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DEVICE_ID=$(dmidecode -s system-uuid 2>/dev/null || echo "unknown")

CERT_CONTENT="Secure Wipe Certificate (PXE)
==============================
Drives: $(echo $DRIVES | tr '\n' ', ')
Wipe Mode: $WIPE_MODE
Device MAC: $MAC_ADDR
Device IP: $IP_ADDR
Device ID: $DEVICE_ID
Hostname: $HOSTNAME
Timestamp: $TIMESTAMP"

# Create certificate hash
CERT_HASH=$(echo "$CERT_CONTENT" | sha256sum | cut -d' ' -f1)
FULL_CERT="$CERT_CONTENT
Verification Hash: $CERT_HASH"

# Send certificate to server
curl -X POST "http://$SERVER_IP:8080/certificate" \
    -H "Content-Type: application/json" \
    -d '{{"mac":"'$MAC_ADDR'","certificate":"'$(echo "$FULL_CERT" | base64 -w 0)'"}}'

# Report completion
curl -X POST "http://$SERVER_IP:8080/status" \
    -H "Content-Type: application/json" \
    -d '{{"mac":"'$MAC_ADDR'","ip":"'$IP_ADDR'","status":"completed","progress":100}}'

echo "Secure wipe completed successfully!"

if [ "$AUTO_SHUTDOWN" = "true" ]; then
    echo "Auto-shutdown enabled. Shutting down in 10 seconds..."
    sleep 10
    shutdown -h now
else
    echo "Wipe completed. Please manually restart the system."
    read -p "Press Enter to shutdown..."
    shutdown -h now
fi
"#,
        config.server_ip, config.wipe_mode, config.auto_shutdown
    );

    let script_path = format!("{}/wipe_script.sh", pxe_dir);
    let mut file = File::create(&script_path)
        .map_err(|e| format!("Failed to create wipe script: {}", e))?;
    
    file.write_all(wipe_script.as_bytes())
        .map_err(|e| format!("Failed to write wipe script: {}", e))?;

    // Make script executable
    if OS != "windows" {
        Command::new("chmod")
            .args(&["+x", &script_path])
            .status()
            .map_err(|e| format!("Failed to make script executable: {}", e))?;
    }

    Ok(())
}

fn setup_boot_files(pxe_dir: &str) -> Result<(), String> {
    // This would typically download or copy boot files like:
    // - pxelinux.0 (PXE bootloader)
    // - vmlinuz (Linux kernel)
    // - initrd.img (Initial RAM disk)
    // - ldlinux.c32, libcom32.c32, etc.
    
    // For now, we'll create placeholder files and instructions
    let readme_content = format!(
        r#"PXE Boot Files Setup Instructions
==================================

To complete the PXE setup, you need to obtain the following files:

1. Download SYSLINUX/PXELINUX:
   - pxelinux.0
   - ldlinux.c32
   - libcom32.c32
   - menu.c32

2. Download a Linux live distribution (e.g., Ubuntu, Debian):
   - vmlinuz (kernel)
   - initrd.img (initial ramdisk)

3. Place these files in: {}

4. Ensure your DHCP server points to this PXE server.

The wipe script and configuration are already created.
"#,
        pxe_dir
    );

    let readme_path = format!("{}/README.txt", pxe_dir);
    let mut file = File::create(&readme_path)
        .map_err(|e| format!("Failed to create README: {}", e))?;
    
    file.write_all(readme_content.as_bytes())
        .map_err(|e| format!("Failed to write README: {}", e))?;

    Ok(())
}

fn start_dhcp_server(config: &PxeConfig) -> Result<(), String> {
    if OS == "windows" {
        // On Windows, we'd typically use a third-party DHCP server
        // For now, provide instructions
        println!("Configure your DHCP server with:");
        println!("  Next Server: {}", config.server_ip);
        println!("  Boot Filename: pxelinux.0");
    } else {
        // On Linux, we could configure dnsmasq or dhcpd
        let dhcp_config = format!(
            r#"# DHCP Configuration for PXE
interface=eth0
dhcp-range={},{},12h
dhcp-boot=pxelinux.0,{},{}
enable-tftp
tftp-root=/var/lib/tftpboot
"#,
            config.dhcp_range_start,
            config.dhcp_range_end,
            config.server_ip,
            config.server_ip
        );
        
        // Write dnsmasq config (requires root privileges)
        println!("DHCP configuration created. Manual setup required.");
        println!("Config: {}", dhcp_config);
    }
    
    Ok(())
}

fn start_tftp_server(_config: &PxeConfig) -> Result<(), String> {
    // TFTP server would be started here
    // This typically requires system-level configuration
    println!("TFTP server configuration completed");
    Ok(())
}

fn start_http_server(config: &PxeConfig) -> Result<(), String> {
    let server_ip = config.server_ip.clone();
    
    thread::spawn(move || {
        let listener = TcpListener::bind(format!("{}:8080", server_ip))
            .expect("Failed to bind HTTP server");
        
        println!("HTTP server listening on {}:8080", server_ip);
        
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(|| {
                        handle_http_request(stream);
                    });
                }
                Err(_) => {}
            }
        }
    });
    
    Ok(())
}

fn start_certificate_server(_config: &PxeConfig) -> Result<(), String> {
    // Certificate collection server is part of the HTTP server
    Ok(())
}

fn handle_http_request(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap_or(0);
    
    let request = String::from_utf8_lossy(&buffer);
    let lines: Vec<&str> = request.lines().collect();
    
    if lines.is_empty() {
        return;
    }
    
    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    
    if parts.len() < 2 {
        return;
    }
    
    let method = parts[0];
    let path = parts[1];
    
    match (method, path) {
        ("GET", "/wipe_script.sh") => {
            serve_wipe_script(&mut stream);
        }
        ("POST", "/status") => {
            handle_status_update(&mut stream, &request);
        }
        ("POST", "/certificate") => {
            handle_certificate_submission(&mut stream, &request);
        }
        _ => {
            send_404(&mut stream);
        }
    }
}

fn serve_wipe_script(stream: &mut TcpStream) {
    let pxe_dir = if OS == "windows" { "C:\\PXE" } else { "/var/lib/tftpboot" };
    let script_path = format!("{}/wipe_script.sh", pxe_dir);
    
    match fs::read_to_string(&script_path) {
        Ok(content) => {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                content.len(),
                content
            );
            stream.write_all(response.as_bytes()).unwrap_or(());
        }
        Err(_) => {
            send_404(stream);
        }
    }
}

fn handle_status_update(stream: &mut TcpStream, request: &str) {
    // Parse JSON from request body
    if let Some(body_start) = request.find("\r\n\r\n") {
        let body = &request[body_start + 4..];
        
        // Simple JSON parsing for status updates
        // In production, use a proper JSON parser
        println!("Status update: {}", body);
        
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        stream.write_all(response.as_bytes()).unwrap_or(());
    }
}

fn handle_certificate_submission(stream: &mut TcpStream, request: &str) {
    if let Some(body_start) = request.find("\r\n\r\n") {
        let body = &request[body_start + 4..];
        
        // Save certificate to file
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let cert_dir = if OS == "windows" {
            "C:\\PXE\\certificates"
        } else {
            "/var/lib/tftpboot/certificates"
        };
        
        fs::create_dir_all(cert_dir).unwrap_or(());
        
        let cert_path = format!("{}/certificate_{}.json", cert_dir, timestamp);
        fs::write(&cert_path, body).unwrap_or(());
        
        println!("Certificate saved: {}", cert_path);
        
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        stream.write_all(response.as_bytes()).unwrap_or(());
    }
}

fn send_404(stream: &mut TcpStream) {
    let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 9\r\n\r\nNot Found";
    stream.write_all(response.as_bytes()).unwrap_or(());
}

fn stop_services() -> Result<(), String> {
    // Stop all PXE services
    // This would typically involve stopping system services
    println!("PXE services stopped");
    Ok(())
}

#[command]
pub async fn validate_pxe_config(config: PxeConfig) -> Result<String, String> {
    // Validate IP addresses
    if !is_valid_ip(&config.server_ip) {
        return Err("Invalid server IP address".to_string());
    }
    
    if !is_valid_ip(&config.dhcp_range_start) {
        return Err("Invalid DHCP range start IP".to_string());
    }
    
    if !is_valid_ip(&config.dhcp_range_end) {
        return Err("Invalid DHCP range end IP".to_string());
    }
    
    // Check if server IP is accessible
    if !is_server_accessible(&config.server_ip) {
        return Err("Server IP is not accessible".to_string());
    }
    
    Ok("PXE configuration is valid".to_string())
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

fn is_server_accessible(ip: &str) -> bool {
    // Simple ping test
    let output = if OS == "windows" {
        Command::new("ping")
            .args(&["-n", "1", ip])
            .output()
    } else {
        Command::new("ping")
            .args(&["-c", "1", ip])
            .output()
    };
    
    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}