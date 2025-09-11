use std::process::Command;
use std::env::consts::OS;
use tauri::command;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use dotenv::dotenv;
use thiserror::Error;


// Database connection pool
pub struct AppState {
    db: Pool<Postgres>,
}

// JWT secret key
const JWT_SECRET: &[u8] = b"wipe_data_in_devices_in_one_click";

// Custom error type
#[derive(Error, Debug, Serialize)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Hashing error: {0}")]
    Hash(String),
    #[error("JWT error: {0}")]
    Jwt(String),
    #[error("IO error: {0}")]
    Io(String),
}

// JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i32, // user id
    exp: usize, // expiration time
    email: String,
}

// User registration data
#[derive(Debug, Deserialize)]
struct RegisterData {
    email: String,
    password: String,
    username: String,
}

// User login data
#[derive(Debug, Deserialize)]
struct LoginData {
    email: String,
    password: String,
}

// Response types
#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
    user_id: i32,
    username: String,
    email: String,
}

#[derive(Debug, Serialize)]
struct UserProfile {
    id: i32,
    username: String,
    email: String,
}

#[command]
async fn register_user(
    email: String,
    password: String,
    username: String,
    state: tauri::State<'_, AppState>,
) -> Result<AuthResponse, String> {
    // Hash the password
    let hashed_password = hash(password, DEFAULT_COST)
        .map_err(|e| format!("Password hashing failed: {}", e))?;

    // Insert user into database
    let result = sqlx::query!(
        "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id, username, email",
        email,
        hashed_password,
        username
    )
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(record) => {
            // Create JWT token
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("valid timestamp")
                .timestamp() as usize;

            let claims = Claims {
                sub: record.id,
                exp: expiration,
                email: record.email.clone(),
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET),
            )
            .map_err(|e| format!("JWT creation failed: {}", e))?;

            Ok(AuthResponse {
                token,
                user_id: record.id,
                username: record.username,
                email: record.email,
            })
        }
        Err(e) => {
            if e.to_string().contains("duplicate key") {
                Err("Email already exists".to_string())
            } else {
                Err(format!("Registration failed: {}", e))
            }
        }
    }
}

#[command]
async fn login_user(
    email: String,
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<AuthResponse, String> {
    // Get user from database
    let user = sqlx::query!(
        "SELECT id, password, username, email FROM users WHERE email = $1",
        email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    match user {
        Some(user_record) => {
            // Verify password
            if verify(password, &user_record.password)
                .map_err(|e| format!("Password verification failed: {}", e))?
            {
                // Create JWT token
                let expiration = Utc::now()
                    .checked_add_signed(Duration::hours(24))
                    .expect("valid timestamp")
                    .timestamp() as usize;

                let claims = Claims {
                    sub: user_record.id,
                    exp: expiration,
                    email: user_record.email.clone(),
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(JWT_SECRET),
                )
                .map_err(|e| format!("JWT creation failed: {}", e))?;

                Ok(AuthResponse {
                    token,
                    user_id: user_record.id,
                    username: user_record.username,
                    email: user_record.email,
                })
            } else {
                Err("Invalid credentials".to_string())
            }
        }
        None => Err("User not found".to_string()),
    }
}

#[command]
async fn verify_token(
    token: String,
    state: tauri::State<'_, AppState>,
) -> Result<UserProfile, String> {
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|e| format!("Invalid token: {}", e))?;

    // Get user from database to ensure they still exist
    let user = sqlx::query!(
        "SELECT id, username, email FROM users WHERE id = $1",
        token_data.claims.sub
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("User not found: {}", e))?;

    Ok(UserProfile {
        id: user.id,
        username: user.username,
        email: user.email,
    })
}

#[command]
async fn update_profile(
    user_id: i32,
    username: String,
    email: String,
    state: tauri::State<'_, AppState>,
) -> Result<UserProfile, String> {
    let result = sqlx::query!(
        "UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING id, username, email",
        username,
        email,
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("Update failed: {}", e))?;

    Ok(UserProfile {
        id: result.id,
        username: result.username,
        email: result.email,
    })
}
use sha2::{Sha256, Digest};

use std::io::Write;
use uuid::Uuid;
use machine_uid::get;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::fs::{File, set_permissions, Permissions};
use std::path::Path;

#[command]
fn list_drives(pretty: Option<bool>) -> Result<Vec<String>, String> {
    let pretty = pretty.unwrap_or(false);

    if OS == "windows" {
        let output = Command::new("wmic")
            .args(&["logicaldisk", "get", "name"])
            .output()
            .map_err(|e| format!("Failed to execute WMIC: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives: Vec<String> = Vec::new();

        for line in stdout.lines().skip(1) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                drives.push(trimmed.to_string());
            }
        }

        Ok(drives)
    } else if OS == "linux" {
        let output = Command::new("lsblk")
            .args(&["-o", "NAME,MOUNTPOINT", "-nr"])
            .output()
            .map_err(|e| format!("Failed to execute lsblk: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if pretty {
                    drives.push(format!("{} ({})", parts[1], parts[0]));
                } else {
                    drives.push(format!("/dev/{}", parts[0]));
                }
            }
        }

        let mtp_output = Command::new("ls")
            .args(&["/run/user/1000/gvfs"])
            .output();

        if let Ok(output) = mtp_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    drives.push(format!("/run/user/1000/gvfs/{}", trimmed));
                }
            }
        }

        Ok(drives)
    } else if OS == "android" {
        let output = Command::new("ls")
            .arg("/storage")
            .output()
            .map_err(|e| format!("Failed to list /storage: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut drives: Vec<String> = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                drives.push(trimmed.to_string());
            }
        }

        Ok(drives)
    } else {
        Err(format!("Unsupported OS: {}", OS))
    }
}

#[command]
fn drive_info() -> Result<Vec<(String, u64, u64)>, String> {
    let mut drives = Vec::new();

    if OS == "linux" || OS == "android" {
        let output = Command::new("df")
            .args(&["-B1", "--output=source,size,avail", "-x", "tmpfs", "-x", "overlay"])
            .output()
            .map_err(|e| format!("Failed to run df: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 3 {
                let name = parts[0].to_string();
                let total = parts[1].parse::<u64>().unwrap_or(0);
                let free = parts[2].parse::<u64>().unwrap_or(0);
                drives.push((name, total, free));
            }
        }

        if OS == "android" {
            let storage_output = Command::new("ls")
                .arg("/storage")
                .output()
                .map_err(|e| format!("Failed to list /storage: {}", e))?;

            let stdout = String::from_utf8_lossy(&storage_output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && trimmed != "self" && trimmed != "emulated" {
                    let path = format!("/storage/{}", trimmed);
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        let total = metadata.len();
                        drives.push((path.clone(), total, 0));
                    } else {
                        drives.push((path, 0, 0));
                    }
                }
            }
        }
    } else if OS == "windows" {
        let output = Command::new("wmic")
            .args(&["logicaldisk", "get", "size,freespace,caption"])
            .output()
            .map_err(|e| format!("Failed to run wmic: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let free = parts[1].parse::<u64>().unwrap_or(0);
                let total = parts[2].parse::<u64>().unwrap_or(0);
                drives.push((name, total, free));
            }
        }
    }

    Ok(drives)
}

#[command]
fn list_files(drive: String) -> Result<Vec<(String, u64)>, String> {
    let entries = std::fs::read_dir(&drive)
        .map_err(|e| format!("Failed to read {}: {}", drive, e))?;

    let mut files = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            let path = e.path();
            let size = if path.is_file() {
                std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
           if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                files.push((name.to_string(), size));
            }
        }
    }
    Ok(files)
}

/// Make file immutable (Linux/Android: chattr, Windows: icacls)
fn make_immutable(path: &Path) -> Result<(), String> {
    if OS == "linux" || OS == "android" {
        Command::new("chattr")
            .args(&["+i", path.to_str().unwrap()])
            .status()
            .map_err(|e| format!("Failed to set immutable: {}", e))?;
    } else if OS == "windows" {
        Command::new("icacls")
            .args(&[
                path.to_str().unwrap(),
                "/inheritance:r",       // remove inherited permissions
                "/grant:r", "Everyone:R" // grant read-only explicitly
            ])
            .status()
            .map_err(|e| format!("Failed to set ACL: {}", e))?;
    }
    Ok(())
}

#[command]
fn generate_certificate(drive: String, wipe_mode: String, user: String) -> Result<String, String> {
    let device_id = get().unwrap_or_else(|_| Uuid::new_v4().to_string());
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();

    let certificate_content = format!(
        "Secure Wipe Certificate\n\
        ======================\n\
        Drive: {}\n\
        Wipe Mode: {}\n\
        User: {}\n\
        Device ID: {}\n\
        Timestamp: {}\n",
        drive, wipe_mode, user, device_id, Utc::now().to_rfc3339()
    );

    let mut hasher = Sha256::new();
    hasher.update(&certificate_content);
    let result = hasher.finalize();
    let hash_hex = format!("{:x}", result);

    let full_content = format!(
        "{}\nVerification Hash: {}\n",
        certificate_content, hash_hex
    );

    let sanitized_drive = drive
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_");

    let mut path: std::path::PathBuf = dirs::document_dir()
        .ok_or("Could not find Documents directory")?;
    path.push("WipeCertificates");
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create directory: {}", e))?;

    path.push(format!("certificate_{}_{}.txt", sanitized_drive, timestamp));

    let mut file = File::create(&path)
        .map_err(|e| format!("Failed to create certificate: {}", e))?;
    file.write_all(full_content.as_bytes())
        .map_err(|e| format!("Failed to write certificate: {}", e))?;

    // Make tamper-proof
    make_immutable(&path)?;

    Ok(path.display().to_string())
}

#[command]
fn verify_certificate(content: String) -> Result<bool, String> {
    let content = content.replace("\r\n", "\n").replace("\r", "\n");

    let mut lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err("Invalid certificate format".to_string());
    }

    let last_line = lines.pop().unwrap();
    let stored_hash = last_line.replace("Verification Hash: ", "").trim().to_string();

    let data_to_hash = lines.join("\n") + "\n";

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let computed_hash = format!("{:x}", hasher.finalize());

    Ok(computed_hash == stored_hash)
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to database");

    // Wrap the pool in AppState
    let state = AppState { db: pool };

    tauri::Builder::default()
        .manage(state) // ✅ Make AppState available to all commands
        .invoke_handler(tauri::generate_handler![
            register_user,
            login_user,
            verify_token,
            update_profile,
            list_drives,
            generate_certificate
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

