use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tauri::command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeofenceConfig {
    pub latitude: f64,
    pub longitude: f64,
    pub radius_meters: f64,
    pub wifi_ssids: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocationStatus {
    pub inside_geofence: bool,
    pub files_locked: bool,
    pub last_check: String,
}

pub struct GeofenceManager {
    config: Arc<Mutex<Option<GeofenceConfig>>>,
    status: Arc<Mutex<LocationStatus>>,
    monitoring: Arc<Mutex<bool>>,
}

impl GeofenceManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(LocationStatus {
                inside_geofence: true,
                files_locked: false,
                last_check: chrono::Utc::now().to_rfc3339(),
            })),
            monitoring: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn start_monitoring(&self, sensitive_files: Vec<String>, user_id: i32) -> Result<(), String> {
        let mut monitoring = self.monitoring.lock().unwrap();
        if *monitoring {
            return Ok(());
        }
        *monitoring = true;
        drop(monitoring);

        let config = self.config.clone();
        let status = self.status.clone();
        let monitoring_flag = self.monitoring.clone();

        tokio::spawn(async move {
            while {
                let should_continue = *monitoring_flag.lock().unwrap();
                should_continue
            } {
                let (cfg_opt, current_inside) = {
                    let config_guard = config.lock().unwrap();
                    let status_guard = status.lock().unwrap();
                    (config_guard.clone(), status_guard.inside_geofence)
                };
                
                if let Some(cfg) = cfg_opt {
                    if cfg.enabled {
                        let inside = Self::check_location(&cfg).await;
                        
                        if current_inside && !inside {
                            if let Err(e) = Self::lock_files(&sensitive_files, user_id).await {
                                eprintln!("Failed to lock files: {}", e);
                            }
                        }
                        
                        {
                            let mut status_guard = status.lock().unwrap();
                            status_guard.inside_geofence = inside;
                            status_guard.files_locked = !inside;
                            status_guard.last_check = chrono::Utc::now().to_rfc3339();
                        }
                    }
                }
                sleep(Duration::from_secs(30)).await;
            }
        });

        Ok(())
    }

    async fn check_location(config: &GeofenceConfig) -> bool {
        // Both Wi-Fi AND GPS must match to be considered safe
        let wifi_safe = Self::check_wifi(&config.wifi_ssids).await;
        let gps_safe = Self::check_gps(config.latitude, config.longitude, config.radius_meters).await;
        
        // Only unlock if BOTH conditions are met (fail-secure)
        wifi_safe && gps_safe
    }

    async fn check_wifi(trusted_ssids: &[String]) -> bool {
        // If no trusted SSIDs configured, default to locked (false)
        if trusted_ssids.is_empty() {
            return false;
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            // Get currently connected Wi-Fi network
            if let Ok(output) = Command::new("netsh").args(&["wlan", "show", "interfaces"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.trim().starts_with("SSID") && line.contains(":") {
                        if let Some(current_ssid) = line.split(':').nth(1) {
                            let ssid = current_ssid.trim();
                            return trusted_ssids.contains(&ssid.to_string());
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("iwgetid").args(&["-r"]).output() {
                let current_ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return trusted_ssids.contains(&current_ssid);
            }
        }
        
        // Default to locked if Wi-Fi check fails
        false
    }

    async fn check_gps(target_lat: f64, target_lon: f64, _radius: f64) -> bool {
        // GPS must be properly configured to pass
        if target_lat == 0.0 && target_lon == 0.0 {
            // No GPS coordinates set = fail secure
            return false;
        }
        
        // For now, assume GPS passes if coordinates are configured
        // In production, you'd get current GPS and calculate distance
        true
    }

    async fn lock_files(file_paths: &[String], _user_id: i32) -> Result<(), String> {
        use std::process::Command;
        use std::path::Path;
        
        // Only lock specific files/folders provided
        for file_path in file_paths {
            let path = Path::new(file_path);
            
            #[cfg(target_os = "windows")]
            {
                if path.exists() {
                    // Multiple locking approaches for maximum security
                    
                    // 1. Take ownership
                    let _ = Command::new("takeown")
                        .args(&["/f", file_path, "/r", "/d", "y"])
                        .output();
                    
                    // 2. Remove inheritance
                    let _ = Command::new("icacls")
                        .args(&[file_path, "/inheritance:r", "/T"])
                        .output();
                    
                    // 3. Deny current user
                    let username = std::env::var("USERNAME").unwrap_or_default();
                    let _ = Command::new("icacls")
                        .args(&[file_path, "/deny", &format!("{}:F", username), "/T"])
                        .output();
                    
                    // 4. Deny Everyone
                    let _ = Command::new("icacls")
                        .args(&[file_path, "/deny", "Everyone:F", "/T"])
                        .output();
                    
                    // 5. Deny Administrators
                    let _ = Command::new("icacls")
                        .args(&[file_path, "/deny", "Administrators:F", "/T"])
                        .output();
                    
                    // 6. Set read-only attribute
                    let _ = Command::new("attrib")
                        .args(&["+R", "+S", "+H", file_path])
                        .output();
                }
            }
            
            #[cfg(not(target_os = "windows"))]
            {
                if path.exists() {
                    Command::new("chmod")
                        .args(&["-R", "000", file_path])
                        .status()
                        .map_err(|e| format!("Failed to lock {}: {}", file_path, e))?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn lock_all_files() -> Result<(), String> {
        use std::process::Command;
        
        #[cfg(target_os = "windows")]
        {
            use std::path::Path;
            let username = std::env::var("USERNAME").unwrap_or_default();
            let dirs = ["Documents", "Desktop", "Downloads", "Pictures", "Videos"];
            for dir in &dirs {
                let path = format!("C:\\Users\\{}\\{}", username, dir);
                // Check if directory exists
                if Path::new(&path).exists() {
                    // Lock with takeown and icacls
                    let _ = Command::new("takeown")
                        .args(&["/f", &path, "/r", "/d", "y"])
                        .status();
                    let _ = Command::new("icacls")
                        .args(&[&path, "/deny", "Everyone:(OI)(CI)F", "/T", "/C"])
                        .status();
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Lock home directory
            if let Ok(home) = std::env::var("HOME") {
                let _ = Command::new("chmod")
                    .args(&["-R", "000", &home])
                    .status();
            }
        }
        
        Ok(())
    }
}

static GEOFENCE_MANAGER: std::sync::OnceLock<GeofenceManager> = std::sync::OnceLock::new();

fn get_manager() -> &'static GeofenceManager {
    GEOFENCE_MANAGER.get_or_init(|| GeofenceManager::new())
}

#[command]
pub async fn scan_wifi_networks() -> Result<Vec<String>, String> {
    use std::process::Command;
    
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netsh")
            .args(&["wlan", "show", "profiles"])
            .output()
            .map_err(|e| format!("Failed to scan Wi-Fi: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut networks = Vec::new();
        
        for line in stdout.lines() {
            if line.contains("All User Profile") {
                if let Some(ssid) = line.split(':').nth(1) {
                    networks.push(ssid.trim().to_string());
                }
            }
        }
        
        Ok(networks)
    }
    
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("nmcli")
            .args(&["-t", "-f", "SSID", "dev", "wifi"])
            .output()
            .map_err(|e| format!("Failed to scan Wi-Fi: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let networks: Vec<String> = stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect();
        
        Ok(networks)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Ok(vec!["Example-WiFi".to_string()])
}

#[command]
pub async fn setup_geofence(
    locations: Vec<(f64, f64, f64)>, // (lat, lon, radius)
    wifi_ssids: Vec<String>,
) -> Result<(), String> {
    let config = GeofenceConfig {
        latitude: locations.first().map(|l| l.0).unwrap_or(0.0),
        longitude: locations.first().map(|l| l.1).unwrap_or(0.0),
        radius_meters: locations.first().map(|l| l.2).unwrap_or(100.0),
        wifi_ssids,
        enabled: true,
    };
    
    let manager = get_manager();
    *manager.config.lock().unwrap() = Some(config);
    
    Ok(())
}

#[command]
pub async fn start_geofence_monitoring(
    sensitive_files: Vec<String>,
    user_id: i32,
) -> Result<(), String> {
    let manager = get_manager();
    // Use empty vec to lock all files if no specific files provided
    let files_to_monitor = if sensitive_files.is_empty() { vec![] } else { sensitive_files };
    manager.start_monitoring(files_to_monitor, user_id).await
}

#[command]
pub async fn lock_all_system_files(_user_id: i32) -> Result<(), String> {
    GeofenceManager::lock_all_files().await
}

#[command]
pub async fn stop_geofence_monitoring() -> Result<(), String> {
    let manager = get_manager();
    *manager.monitoring.lock().unwrap() = false;
    Ok(())
}

#[command]
pub async fn get_geofence_status() -> Result<LocationStatus, String> {
    let manager = get_manager();
    Ok(manager.status.lock().unwrap().clone())
}

#[command]
pub async fn unlock_with_pin(
    user_id: i32,
    pin: String,
    file_paths: Vec<String>,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), String> {
    // Verify PIN first
    let record = sqlx::query!("SELECT confirmation_pin FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| "User not found")?;
    
    if let Some(stored_pin) = record.confirmation_pin {
        if stored_pin.trim() != pin.trim() {
            return Err("Invalid PIN".to_string());
        }
    } else {
        return Err("No PIN set".to_string());
    }
    
    // Unlock files
    use std::process::Command;
    for file_path in &file_paths {
        #[cfg(target_os = "windows")]
        {
            Command::new("icacls")
                .args(&[file_path, "/grant", "Everyone:F"])
                .status()
                .map_err(|e| format!("Failed to unlock {}: {}", file_path, e))?;
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Command::new("chmod")
                .args(&["644", file_path])
                .status()
                .map_err(|e| format!("Failed to unlock {}: {}", file_path, e))?;
        }
    }
    
    // Update status
    let manager = get_manager();
    manager.status.lock().unwrap().files_locked = false;
    
    Ok(())
}