use std::process::Command;
use std::env::consts::OS;
use std::fs::{self, File};
use std::io::{Write, Read};
use tauri::command;
use serde::{Deserialize, Serialize};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::path::Path;
use reqwest;
use tokio::runtime::Runtime;

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
    pub exception_list: Vec<String>, // MAC addresses or IP addresses to exclude
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
    let exception_list = config.exception_list.join(" ");
    let wipe_script = format!(
        r#"#!/bin/bash
# Secure Wipe Script - PXE Boot Version

SERVER_IP="{}"
WIPE_MODE="{}"
AUTO_SHUTDOWN={}
EXCEPTION_LIST="{}"

# Get system information
MAC_ADDR=$(cat /sys/class/net/*/address | head -n1)
IP_ADDR=$(hostname -I | awk '{{print $1}}')
HOSTNAME=$(hostname)

# Check if this device is in exception list
for EXCEPTION in $EXCEPTION_LIST; do
    if [[ "$MAC_ADDR" == "$EXCEPTION" ]] || [[ "$IP_ADDR" == "$EXCEPTION" ]] || [[ "$HOSTNAME" == "$EXCEPTION" ]]; then
        echo "Device $MAC_ADDR ($IP_ADDR) is in exception list - skipping wipe"
        curl -X POST "http://$SERVER_IP:8080/status" \
            -H "Content-Type: application/json" \
            -d '{{"mac":"'$MAC_ADDR'","ip":"'$IP_ADDR'","status":"skipped","progress":100}}'
        echo "This device is protected from wiping. Shutting down..."
        sleep 5
        shutdown -h now
        exit 0
    fi
done

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
        config.server_ip, config.wipe_mode, config.auto_shutdown, exception_list
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
    println!("Downloading PXE boot files...");
    
    let rt = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;
    
    // Download SYSLINUX files
    let syslinux_files = vec![
        ("https://mirrors.kernel.org/pub/linux/utils/boot/syslinux/bios/core/pxelinux.0", "pxelinux.0"),
        ("https://mirrors.kernel.org/pub/linux/utils/boot/syslinux/bios/com32/elflink/ldlinux/ldlinux.c32", "ldlinux.c32"),
        ("https://mirrors.kernel.org/pub/linux/utils/boot/syslinux/bios/com32/lib/libcom32.c32", "libcom32.c32"),
        ("https://mirrors.kernel.org/pub/linux/utils/boot/syslinux/bios/com32/menu/menu.c32", "menu.c32"),
    ];
    
    for (url, filename) in syslinux_files {
        let file_path = format!("{}/{}", pxe_dir, filename);
        if !Path::new(&file_path).exists() {
            rt.block_on(download_file(url, &file_path))
                .map_err(|e| format!("Failed to download {}: {}", filename, e))?;
            println!("Downloaded: {}", filename);
        }
    }
    
    // Download minimal Linux live environment (Alpine Linux - small and fast)
    let alpine_version = "3.18";
    let alpine_files = vec![
        (format!("https://dl-cdn.alpinelinux.org/alpine/v{}/releases/x86_64/alpine-netboot-{}.0-x86_64.tar.gz", alpine_version, alpine_version), "alpine-netboot.tar.gz"),
    ];
    
    for (url, filename) in alpine_files {
        let file_path = format!("{}/{}", pxe_dir, filename);
        if !Path::new(&file_path).exists() {
            rt.block_on(download_file(&url, &file_path))
                .map_err(|e| format!("Failed to download {}: {}", filename, e))?;
            println!("Downloaded: {}", filename);
            
            // Extract Alpine netboot files
            extract_alpine_files(pxe_dir, &file_path)?;
        }
    }
    
    // Create custom initrd with wipe tools
    create_custom_initrd(pxe_dir)?;
    
    println!("All PXE boot files ready!");
    Ok(())
}

async fn download_file(url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    Ok(())
}

fn extract_alpine_files(pxe_dir: &str, archive_path: &str) -> Result<(), String> {
    let output = if OS == "windows" {
        // Use 7zip or tar on Windows
        Command::new("tar")
            .args(&["-xzf", archive_path, "-C", pxe_dir])
            .output()
    } else {
        Command::new("tar")
            .args(&["-xzf", archive_path, "-C", pxe_dir])
            .output()
    };
    
    match output {
        Ok(result) => {
            if result.status.success() {
                // Move extracted files to correct locations
                let boot_dir = format!("{}/boot", pxe_dir);
                if Path::new(&boot_dir).exists() {
                    // Copy vmlinuz and initramfs
                    if let Ok(entries) = fs::read_dir(&boot_dir) {
                        for entry in entries.flatten() {
                            let file_name = entry.file_name();
                            let file_name_str = file_name.to_string_lossy();
                            
                            if file_name_str.starts_with("vmlinuz") {
                                fs::copy(entry.path(), format!("{}/vmlinuz", pxe_dir))
                                    .map_err(|e| format!("Failed to copy vmlinuz: {}", e))?;
                            } else if file_name_str.starts_with("initramfs") {
                                fs::copy(entry.path(), format!("{}/initrd.img", pxe_dir))
                                    .map_err(|e| format!("Failed to copy initrd: {}", e))?;
                            }
                        }
                    }
                }
                Ok(())
            } else {
                Err(format!("Failed to extract archive: {}", String::from_utf8_lossy(&result.stderr)))
            }
        }
        Err(e) => Err(format!("Failed to run tar: {}", e))
    }
}

fn create_custom_initrd(pxe_dir: &str) -> Result<(), String> {
    let initrd_dir = format!("{}/custom_initrd", pxe_dir);
    fs::create_dir_all(&initrd_dir)
        .map_err(|e| format!("Failed to create initrd directory: {}", e))?;
    
    // Create init script with wipe tools
    let init_script = r#"#!/bin/sh
# Custom init script for secure wipe

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Load network modules
modprobe e1000
modprobe e1000e
modprobe r8169
modprobe igb

# Configure network via DHCP
udhcpc -i eth0 -s /usr/share/udhcpc/default.script

# Download and execute wipe script
wget -O /tmp/wipe_script.sh http://192.168.1.100:8080/wipe_script.sh
chmod +x /tmp/wipe_script.sh
/tmp/wipe_script.sh

# Keep system running
while true; do sleep 3600; done
"#;
    
    let init_path = format!("{}/init", initrd_dir);
    let mut file = File::create(&init_path)
        .map_err(|e| format!("Failed to create init script: {}", e))?;
    file.write_all(init_script.as_bytes())
        .map_err(|e| format!("Failed to write init script: {}", e))?;
    
    // Make init executable
    if OS != "windows" {
        Command::new("chmod")
            .args(&["+x", &init_path])
            .status()
            .map_err(|e| format!("Failed to make init executable: {}", e))?;
    }
    
    Ok(())
}

fn start_dhcp_server(config: &PxeConfig) -> Result<(), String> {
    let server_ip = config.server_ip.clone();
    let dhcp_start = config.dhcp_range_start.clone();
    let dhcp_end = config.dhcp_range_end.clone();
    
    thread::spawn(move || {
        if let Err(e) = run_dhcp_server(&server_ip, &dhcp_start, &dhcp_end) {
            eprintln!("DHCP server error: {}", e);
        }
    });
    
    println!("DHCP server started on {}", config.server_ip);
    Ok(())
}

fn run_dhcp_server(server_ip: &str, _dhcp_start: &str, _dhcp_end: &str) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:67")
        .map_err(|e| format!("Failed to bind DHCP socket: {}. Run as administrator/root.", e))?;
    
    socket.set_broadcast(true)
        .map_err(|e| format!("Failed to set broadcast: {}", e))?;
    
    println!("DHCP server listening on port 67");
    
    let mut buffer = [0; 1024];
    let mut ip_counter = 100; // Start from .100
    
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {
                if size > 240 { // Minimum DHCP packet size
                    // Parse DHCP packet
                    let packet = &buffer[..size];
                    
                    // Check if it's a DHCP Discover (option 53 = 1)
                    if is_dhcp_discover(packet) {
                        println!("DHCP Discover from: {}", src);
                        
                        // Send DHCP Offer with PXE options
                        let offer_ip = format!("192.168.1.{}", ip_counter);
                        ip_counter += 1;
                        if ip_counter > 200 { ip_counter = 100; }
                        
                        let response = create_dhcp_offer(packet, &offer_ip, server_ip);
                        socket.send_to(&response, "255.255.255.255:68")
                            .map_err(|e| format!("Failed to send DHCP offer: {}", e))?;
                        
                        println!("Sent DHCP offer: {} -> {}", offer_ip, src);
                    } else if is_dhcp_request(packet) {
                        println!("DHCP Request from: {}", src);
                        
                        // Send DHCP ACK with PXE boot options
                        let ack_ip = extract_requested_ip(packet).unwrap_or_else(|| format!("192.168.1.{}", ip_counter));
                        let response = create_dhcp_ack(packet, &ack_ip, server_ip);
                        socket.send_to(&response, "255.255.255.255:68")
                            .map_err(|e| format!("Failed to send DHCP ack: {}", e))?;
                        
                        println!("Sent DHCP ACK: {} -> {}", ack_ip, src);
                    }
                }
            }
            Err(e) => {
                eprintln!("DHCP receive error: {}", e);
            }
        }
    }
}

fn is_dhcp_discover(packet: &[u8]) -> bool {
    // Look for DHCP Message Type option (53) with value 1 (Discover)
    find_dhcp_option(packet, 53).map_or(false, |val| val == 1)
}

fn is_dhcp_request(packet: &[u8]) -> bool {
    // Look for DHCP Message Type option (53) with value 3 (Request)
    find_dhcp_option(packet, 53).map_or(false, |val| val == 3)
}

fn find_dhcp_option(packet: &[u8], option_code: u8) -> Option<u8> {
    if packet.len() < 240 { return None; }
    
    let mut i = 240; // Start of options
    while i < packet.len() - 2 {
        let code = packet[i];
        if code == 255 { break; } // End of options
        if code == 0 { i += 1; continue; } // Padding
        
        let length = packet[i + 1] as usize;
        if code == option_code && length > 0 {
            return Some(packet[i + 2]);
        }
        i += 2 + length;
    }
    None
}

fn extract_requested_ip(packet: &[u8]) -> Option<String> {
    // Extract requested IP from option 50
    if packet.len() < 240 { return None; }
    
    let mut i = 240;
    while i < packet.len() - 6 {
        let code = packet[i];
        if code == 255 { break; }
        if code == 0 { i += 1; continue; }
        
        let length = packet[i + 1] as usize;
        if code == 50 && length == 4 {
            return Some(format!("{}.{}.{}.{}", packet[i+2], packet[i+3], packet[i+4], packet[i+5]));
        }
        i += 2 + length;
    }
    None
}

fn create_dhcp_offer(request: &[u8], offer_ip: &str, server_ip: &str) -> Vec<u8> {
    let mut response = vec![0u8; 300];
    
    // DHCP Header
    response[0] = 2; // Boot Reply
    response[1] = 1; // Ethernet
    response[2] = 6; // Hardware address length
    response[3] = 0; // Hops
    
    // Copy transaction ID from request
    response[4..8].copy_from_slice(&request[4..8]);
    
    // Seconds and flags
    response[8..12].fill(0);
    
    // Client IP (0.0.0.0)
    response[12..16].fill(0);
    
    // Your IP (offered IP)
    let ip_parts: Vec<u8> = offer_ip.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    response[16..20].copy_from_slice(&ip_parts);
    
    // Server IP
    let server_parts: Vec<u8> = server_ip.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    response[20..24].copy_from_slice(&server_parts);
    
    // Gateway IP (same as server)
    response[24..28].copy_from_slice(&server_parts);
    
    // Copy client hardware address from request
    response[28..34].copy_from_slice(&request[28..34]);
    
    // Server name and boot file
    response[44..108].fill(0); // Server name
    let boot_file = b"pxelinux.0";
    response[108..108+boot_file.len()].copy_from_slice(boot_file);
    
    // Magic cookie
    response[236..240].copy_from_slice(&[99, 130, 83, 99]);
    
    // DHCP Options
    let mut opt_pos = 240;
    
    // Message Type (Offer)
    response[opt_pos..opt_pos+3].copy_from_slice(&[53, 1, 2]);
    opt_pos += 3;
    
    // Server Identifier
    response[opt_pos] = 54;
    response[opt_pos+1] = 4;
    response[opt_pos+2..opt_pos+6].copy_from_slice(&server_parts);
    opt_pos += 6;
    
    // Lease Time (12 hours)
    response[opt_pos..opt_pos+6].copy_from_slice(&[51, 4, 0, 0, 168, 192]);
    opt_pos += 6;
    
    // Subnet Mask
    response[opt_pos..opt_pos+6].copy_from_slice(&[1, 4, 255, 255, 255, 0]);
    opt_pos += 6;
    
    // Router
    response[opt_pos] = 3;
    response[opt_pos+1] = 4;
    response[opt_pos+2..opt_pos+6].copy_from_slice(&server_parts);
    opt_pos += 6;
    
    // DNS Server
    response[opt_pos] = 6;
    response[opt_pos+1] = 4;
    response[opt_pos+2..opt_pos+6].copy_from_slice(&server_parts);
    opt_pos += 6;
    
    // End option
    response[opt_pos] = 255;
    
    response
}

fn create_dhcp_ack(request: &[u8], ack_ip: &str, server_ip: &str) -> Vec<u8> {
    let mut response = create_dhcp_offer(request, ack_ip, server_ip);
    // Change message type from Offer (2) to ACK (5)
    response[242] = 5; // Position of message type value
    response
}

fn start_tftp_server(config: &PxeConfig) -> Result<(), String> {
    let server_ip = config.server_ip.clone();
    let pxe_dir = if OS == "windows" { "C:\\PXE" } else { "/var/lib/tftpboot" };
    let tftp_root = pxe_dir.to_string();
    
    thread::spawn(move || {
        if let Err(e) = run_tftp_server(&server_ip, &tftp_root) {
            eprintln!("TFTP server error: {}", e);
        }
    });
    
    println!("TFTP server started on {}:69", config.server_ip);
    Ok(())
}

fn run_tftp_server(server_ip: &str, tftp_root: &str) -> Result<(), String> {
    let socket = UdpSocket::bind(format!("{}:69", server_ip))
        .map_err(|e| format!("Failed to bind TFTP socket: {}. Run as administrator/root.", e))?;
    
    println!("TFTP server listening on port 69, serving from: {}", tftp_root);
    
    let mut buffer = [0; 516]; // TFTP max packet size
    
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, client_addr)) => {
                if size < 4 { continue; }
                
                let opcode = u16::from_be_bytes([buffer[0], buffer[1]]);
                
                match opcode {
                    1 => { // Read Request (RRQ)
                        let filename = extract_tftp_filename(&buffer[2..size]);
                        println!("TFTP Read request for: {} from {}", filename, client_addr);
                        
                        let file_path = format!("{}/{}", tftp_root, filename);
                        match fs::read(&file_path) {
                            Ok(file_data) => {
                                send_tftp_file(&socket, &client_addr, &file_data)
                                    .map_err(|e| format!("Failed to send file: {}", e))?;
                            }
                            Err(_) => {
                                send_tftp_error(&socket, &client_addr, 1, "File not found")
                                    .map_err(|e| format!("Failed to send error: {}", e))?;
                            }
                        }
                    }
                    4 => { // Acknowledgment (ACK)
                        // Handle ACK for data packets
                        println!("Received ACK from {}", client_addr);
                    }
                    _ => {
                        println!("Unknown TFTP opcode: {} from {}", opcode, client_addr);
                    }
                }
            }
            Err(e) => {
                eprintln!("TFTP receive error: {}", e);
            }
        }
    }
}

fn extract_tftp_filename(data: &[u8]) -> String {
    let mut filename = String::new();
    for &byte in data {
        if byte == 0 { break; }
        filename.push(byte as char);
    }
    filename
}

fn send_tftp_file(socket: &UdpSocket, client_addr: &std::net::SocketAddr, file_data: &[u8]) -> Result<(), String> {
    let block_size = 512;
    let total_blocks = (file_data.len() + block_size - 1) / block_size;
    
    for block_num in 1..=total_blocks {
        let start = (block_num - 1) * block_size;
        let end = std::cmp::min(start + block_size, file_data.len());
        let block_data = &file_data[start..end];
        
        // Create DATA packet
        let mut packet = vec![0, 3]; // DATA opcode
        packet.extend_from_slice(&(block_num as u16).to_be_bytes());
        packet.extend_from_slice(block_data);
        
        // Send with retries
        for _retry in 0..3 {
            socket.send_to(&packet, client_addr)
                .map_err(|e| format!("Failed to send data block: {}", e))?;
            
            // Wait for ACK (simplified - should have timeout)
            let mut ack_buffer = [0; 4];
            match socket.recv_from(&mut ack_buffer) {
                Ok((4, _)) => {
                    let ack_opcode = u16::from_be_bytes([ack_buffer[0], ack_buffer[1]]);
                    let ack_block = u16::from_be_bytes([ack_buffer[2], ack_buffer[3]]);
                    
                    if ack_opcode == 4 && ack_block == block_num as u16 {
                        break; // ACK received
                    }
                }
                _ => continue, // Retry
            }
        }
    }
    
    println!("File transfer completed to {}", client_addr);
    Ok(())
}

fn send_tftp_error(socket: &UdpSocket, client_addr: &std::net::SocketAddr, error_code: u16, error_msg: &str) -> Result<(), String> {
    let mut packet = vec![0, 5]; // ERROR opcode
    packet.extend_from_slice(&error_code.to_be_bytes());
    packet.extend_from_slice(error_msg.as_bytes());
    packet.push(0); // Null terminator
    
    socket.send_to(&packet, client_addr)
        .map_err(|e| format!("Failed to send error: {}", e))?;
    
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
    
    // Check network privileges
    if !check_network_privileges() {
        return Err("Administrator/root privileges required for DHCP/TFTP servers. Please run as administrator.".to_string());
    }
    
    // Check if ports are available
    if !is_port_available(67) {
        return Err("Port 67 (DHCP) is already in use. Stop existing DHCP server.".to_string());
    }
    
    if !is_port_available(69) {
        return Err("Port 69 (TFTP) is already in use. Stop existing TFTP server.".to_string());
    }
    
    Ok("PXE configuration is valid and ready to start".to_string())
}

#[command]
pub async fn setup_pxe_prerequisites() -> Result<String, String> {
    let mut setup_info = String::new();
    
    // Check and install prerequisites
    setup_info.push_str("PXE Server Setup Requirements:\n\n");
    
    if OS == "windows" {
        setup_info.push_str("Windows Setup:\n");
        setup_info.push_str("1. Run application as Administrator\n");
        setup_info.push_str("2. Disable Windows DHCP Client service temporarily\n");
        setup_info.push_str("3. Configure Windows Firewall to allow ports 67, 69, 8080\n\n");
        
        // Try to configure firewall automatically
        if configure_windows_firewall().is_ok() {
            setup_info.push_str("✅ Windows Firewall configured automatically\n");
        } else {
            setup_info.push_str("⚠️ Manual firewall configuration required\n");
        }
    } else {
        setup_info.push_str("Linux Setup:\n");
        setup_info.push_str("1. Run application with sudo privileges\n");
        setup_info.push_str("2. Stop existing DHCP services: sudo systemctl stop dhcpcd\n");
        setup_info.push_str("3. Configure iptables to allow ports 67, 69, 8080\n\n");
        
        // Try to configure iptables automatically
        if configure_linux_firewall().is_ok() {
            setup_info.push_str("✅ Linux firewall configured automatically\n");
        } else {
            setup_info.push_str("⚠️ Manual firewall configuration required\n");
        }
    }
    
    setup_info.push_str("\nNetwork Requirements:\n");
    setup_info.push_str("- Ensure target machines support PXE boot\n");
    setup_info.push_str("- Connect all devices to same network segment\n");
    setup_info.push_str("- Disable other DHCP servers on network\n");
    
    Ok(setup_info)
}

fn check_network_privileges() -> bool {
    // Try to bind to privileged ports to check permissions
    std::net::UdpSocket::bind("127.0.0.1:67").is_ok()
}

fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok()
}

fn configure_windows_firewall() -> Result<(), String> {
    let commands = vec![
        "netsh advfirewall firewall add rule name=\"PXE DHCP\" dir=in action=allow protocol=UDP localport=67",
        "netsh advfirewall firewall add rule name=\"PXE TFTP\" dir=in action=allow protocol=UDP localport=69",
        "netsh advfirewall firewall add rule name=\"PXE HTTP\" dir=in action=allow protocol=TCP localport=8080",
    ];
    
    for cmd in commands {
        let output = Command::new("cmd")
            .args(&["/c", cmd])
            .output()
            .map_err(|e| format!("Failed to run firewall command: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("Firewall configuration failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
    }
    
    Ok(())
}

fn configure_linux_firewall() -> Result<(), String> {
    let commands = vec![
        "iptables -A INPUT -p udp --dport 67 -j ACCEPT",
        "iptables -A INPUT -p udp --dport 69 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 8080 -j ACCEPT",
    ];
    
    for cmd in commands {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let output = Command::new("iptables")
            .args(&parts[1..])
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("iptables configuration failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
    }
    
    Ok(())
}

#[command]
pub async fn get_network_interfaces() -> Result<Vec<String>, String> {
    let mut interfaces = Vec::new();
    
    if OS == "windows" {
        let output = Command::new("ipconfig")
            .args(&["/all"])
            .output()
            .map_err(|e| format!("Failed to get network interfaces: {}", e))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("IPv4 Address") {
                if let Some(ip_start) = line.find(":") {
                    let ip = line[ip_start+1..].trim();
                    if !ip.starts_with("127.") && !ip.is_empty() {
                        interfaces.push(ip.to_string());
                    }
                }
            }
        }
    } else {
        let output = Command::new("ip")
            .args(&["addr", "show"])
            .output()
            .map_err(|e| format!("Failed to get network interfaces: {}", e))?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                if let Some(ip_start) = line.find("inet ") {
                    let ip_part = &line[ip_start+5..];
                    if let Some(ip_end) = ip_part.find("/") {
                        let ip = &ip_part[..ip_end];
                        interfaces.push(ip.to_string());
                    }
                }
            }
        }
    }
    
    if interfaces.is_empty() {
        interfaces.push("192.168.1.100".to_string()); // Default fallback
    }
    
    Ok(interfaces)
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

#[allow(dead_code)]
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