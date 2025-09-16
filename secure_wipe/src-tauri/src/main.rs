use std::process::Command;
use std::env::consts::OS;
use tauri::command;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use dotenv::dotenv;
use thiserror::Error;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::RngCore; 
use std::path::Path;       // for &Path
use std::fs::File;          // for File operations
use machine_uid::get;       // for device UID
use uuid::Uuid;             // for Uuid::new_v4()
use sha2::{Sha256, Digest};
use std::io::Write;
use chrono::{Utc, Duration, SubsecRound};

mod bootable;
mod iso_builder;
mod pxe_server;
mod geofence;







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
    confirmation_pin: String, // <-- add this
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
    let record = sqlx::query!(
        "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id, username, email",
        email,
        hashed_password,
        username
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            "Email already exists".to_string()
        } else {
            format!("Registration failed: {}", e)
        }
    })?;

    // Generate a random 6-digit confirmation PIN using Send-safe RNG
    let mut rng = StdRng::from_entropy();
    let confirmation_pin = format!("{:06}", rng.next_u32() % 1_000_000);

    // Store the confirmation PIN in the database
    sqlx::query!(
        "UPDATE users SET confirmation_pin = $1 WHERE id = $2",
        &confirmation_pin,
        record.id
    )
    .execute(&state.db)
    .await
    .map_err(|e| format!("Failed to store confirmation PIN: {}", e))?;

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

    // Return AuthResponse with confirmation PIN
    Ok(AuthResponse {
    token,
    user_id: record.id,
    username: record.username,
    email: record.email,
    confirmation_pin, // must match the struct
})
}


#[command]
async fn verify_user_pin(
    user_id: i32,
    pin: String,
    state: tauri::State<'_, AppState>
) -> Result<bool, String> {
    let record = sqlx::query!("SELECT confirmation_pin FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| "User not found".to_string())?;

    if let Some(stored_pin) = record.confirmation_pin {
        Ok(stored_pin.trim() == pin.trim())
    } else {
        Ok(false)
    }
}

#[command]
async fn login_user(
    email: String,
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<AuthResponse, String> {
    // Get user from database including the confirmation_pin
    let user = sqlx::query!(
        "SELECT id, password, username, email, confirmation_pin FROM users WHERE email = $1",
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

                // Return AuthResponse including confirmation_pin
                Ok(AuthResponse {
                    token,
                    user_id: user_record.id,
                    username: user_record.username,
                    email: user_record.email,
                    confirmation_pin: user_record.confirmation_pin.unwrap_or_default(),
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

#[command]
fn list_all_files(path: String) -> Result<Vec<(String, u64, bool, String)>, String> {
    let entries = std::fs::read_dir(&path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;

    let mut files = Vec::new();
    for entry in entries {
        if let Ok(e) = entry {
            let entry_path = e.path();
            let is_directory = entry_path.is_dir();
            let size = if entry_path.is_file() {
                std::fs::metadata(&entry_path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
            
            if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                let full_path = entry_path.to_string_lossy().to_string();
                files.push((name.to_string(), size, is_directory, full_path));
            }
        }
    }
    
    // Sort directories first, then files
    files.sort_by(|a, b| {
        match (a.2, b.2) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.0.cmp(&b.0),
        }
    });
    
    Ok(files)
}

#[command]
async fn verify_user_password(
    user_id: i32,
    password: String,
    state: tauri::State<'_, AppState>
) -> Result<bool, String> {
    let record = sqlx::query!("SELECT password FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| "User not found".to_string())?;

    verify(password, &record.password)
        .map_err(|e| format!("Password verification failed: {}", e))
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
async fn generate_certificate(
    drive: String,
    wipe_mode: String,
    user: String,
    user_id: i32,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let device_id = get().unwrap_or_else(|_| Uuid::new_v4().to_string());

    // Round timestamp to seconds to avoid fractional second mismatch
    let timestamp = Utc::now().trunc_subsecs(0);

    let certificate_content = format!(
        "Secure Wipe Certificate\n\
        ======================\n\
        Drive: {}\n\
        Wipe Mode: {}\n\
        User: {}\n\
        Device ID: {}\n\
        Timestamp: {}\n",
        drive, wipe_mode, user, device_id, timestamp.to_rfc3339()
    );

    let mut hasher = Sha256::new();
    hasher.update(&certificate_content);
    let result = hasher.finalize();
    let hash_hex = format!("{:x}", result);

    let full_content = format!("{}\nVerification Hash: {}\n", certificate_content, hash_hex);

    // Insert into database
    sqlx::query!(
    "INSERT INTO certificates (user_id, drive, wipe_mode, device_id, timestamp, content, hash) 
     VALUES ($1, $2, $3, $4, $5, $6, $7)",
    user_id,
    drive,
    wipe_mode,
    device_id,
    timestamp,
    full_content,
    hash_hex
)

    .execute(&state.db)
    .await
    .map_err(|e| format!("Failed to save certificate in DB: {}", e))?;

    // Save to file
    let sanitized_drive = drive.replace("/", "_").replace("\\", "_").replace(":", "_").replace(" ", "_");
    let mut path: std::path::PathBuf = dirs::document_dir().ok_or("Could not find Documents directory")?;
    path.push("WipeCertificates");
    std::fs::create_dir_all(&path).map_err(|e| format!("Failed to create directory: {}", e))?;
    path.push(format!("certificate_{}_{}.txt", sanitized_drive, timestamp.format("%Y%m%d_%H%M%S")));

    let mut file = File::create(&path).map_err(|e| format!("Failed to create certificate: {}", e))?;
    file.write_all(full_content.as_bytes()).map_err(|e| format!("Failed to write certificate: {}", e))?;
    make_immutable(&path)?;

    Ok(path.display().to_string())
}




#[command]
async fn verify_certificate(
    content: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    // Normalize line endings for Windows/Linux compatibility
    let content = content.replace("\r\n", "\n").replace("\r", "\n");
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() < 3 {
        return Err("Invalid certificate format".to_string());
    }

    // Extract fields by prefix
    let drive = lines.iter()
        .find(|l| l.starts_with("Drive:"))
        .ok_or("Drive not found")?
        .replace("Drive:", "")
        .trim_matches(|c: char| c == '\r' || c == '\n' || c.is_whitespace())
        .to_string();

    let timestamp_str = lines.iter()
        .find(|l| l.starts_with("Timestamp:"))
        .ok_or("Timestamp not found")?
        .replace("Timestamp:", "")
        .trim_matches(|c: char| c == '\r' || c == '\n' || c.is_whitespace())
        .to_string();

    let file_hash = lines.iter()
        .find(|l| l.starts_with("Verification Hash:"))
        .ok_or("Verification Hash not found")?
        .replace("Verification Hash:", "")
        .trim_matches(|c: char| c == '\r' || c == '\n' || c.is_whitespace())
        .to_string();

    // Parse timestamp safely
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
        .map_err(|_| format!("Invalid timestamp format: '{}'", timestamp_str))?
        .with_timezone(&chrono::Utc);

    // Recompute hash using certificate content without the Verification Hash line
    let data_to_hash = lines.iter()
        .filter(|l| !l.starts_with("Verification Hash:"))
        .map(|l| *l)
        .collect::<Vec<&str>>()
        .join("\n") + "\n";

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let computed_hash = format!("{:x}", hasher.finalize());

    if computed_hash != file_hash {
        return Ok(false); // Hash mismatch → tampered
    }

    // Check database for exact drive and timestamp match
    let row = sqlx::query!(
        "SELECT hash FROM certificates WHERE drive = $1 AND timestamp = $2",
        drive,
        timestamp
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;

    Ok(match row {
        Some(record) => record.hash == computed_hash,
        None => false,
    })
}


#[derive(Debug, Serialize)]
struct FileEntry {
    name: String,
    size: u64,
}



#[derive(Debug, Serialize)]
struct Certificate {
    id: i32,
    user_id: Option<i32>,  // <-- changed
    drive: String,
    wipe_mode: String,
    device_id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    content: String,
    hash: String,
}


#[command]
async fn list_certificates(
    user_id: i32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Certificate>, String> {
    let rows = sqlx::query!(
        r#"
        SELECT id, user_id, drive, wipe_mode, device_id, timestamp, content, hash
        FROM certificates
        WHERE user_id = $1
        ORDER BY timestamp DESC
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("Failed to fetch certificates: {}", e))?;

    let certs = rows
        .into_iter()
        .map(|row| Certificate {
            id: row.id,
            user_id: row.user_id,
            drive: row.drive,
            wipe_mode: row.wipe_mode,
            device_id: row.device_id,
            timestamp: row.timestamp,
            content: row.content,
            hash: row.hash,
        })
        .collect();

    Ok(certs)
}

#[command]
async fn download_certificate(
    content: String,
    filename: String,
) -> Result<(), String> {
    let save_path = rfd::FileDialog::new()
        .set_file_name(&filename)
        .save_file()
        .ok_or("User cancelled download")?;
    
    std::fs::write(&save_path, content)
        .map_err(|e| format!("Failed to save file: {}", e))?;
    
    Ok(())
}

#[command]
async fn download_certificate_pdf(
    drive: String,
    wipe_mode: String,
    device_id: String,
    timestamp: String,
    hash: String,
    filename: String,
) -> Result<(), String> {
    use printpdf::*;
    
    let save_path = rfd::FileDialog::new()
        .set_file_name(&filename)
        .save_file()
        .ok_or("User cancelled download")?;
    
    let (doc, page1, layer1) = PdfDocument::new("Secure Wipe Certificate", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);
    
    let font = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| format!("Font error: {}", e))?;
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| format!("Font error: {}", e))?;
    
    // Title
    current_layer.use_text("SECURE WIPE CERTIFICATE", 20.0, Mm(105.0), Mm(270.0), &font);
    current_layer.use_text("=======================", 16.0, Mm(105.0), Mm(260.0), &font);
    
    // Certificate details
    current_layer.use_text(&format!("Drive: {}", drive), 12.0, Mm(20.0), Mm(230.0), &font_regular);
    current_layer.use_text(&format!("Wipe Mode: {}", wipe_mode), 12.0, Mm(20.0), Mm(220.0), &font_regular);
    current_layer.use_text(&format!("Device ID: {}", device_id), 12.0, Mm(20.0), Mm(210.0), &font_regular);
    current_layer.use_text(&format!("Timestamp: {}", timestamp), 12.0, Mm(20.0), Mm(200.0), &font_regular);
    current_layer.use_text(&format!("Verification Hash: {}", hash), 10.0, Mm(20.0), Mm(180.0), &font_regular);
    
    // Footer
    current_layer.use_text("This certificate verifies the secure wipe operation.", 10.0, Mm(20.0), Mm(50.0), &font_regular);
    current_layer.use_text(&format!("Generated on: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")), 8.0, Mm(20.0), Mm(30.0), &font_regular);
    
    doc.save(&mut std::io::BufWriter::new(std::fs::File::create(&save_path).map_err(|e| format!("File creation error: {}", e))?))
        .map_err(|e| format!("PDF save error: {}", e))?;
    
    Ok(())
}

#[command]
async fn verify_certificate_pdf(
    pdf_data: Vec<u8>,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    use pdf_extract::extract_text_from_mem;
    
    let text = extract_text_from_mem(&pdf_data)
        .map_err(|e| format!("Failed to extract text from PDF: {}", e))?;
    
    let lines: Vec<&str> = text.lines().collect();
    
    let drive = lines.iter()
        .find(|l| l.contains("Drive:"))
        .and_then(|l| l.split("Drive:").nth(1))
        .map(|s| s.trim())
        .ok_or("Drive not found in PDF")?;
    
    let timestamp_str = lines.iter()
        .find(|l| l.contains("Timestamp:"))
        .and_then(|l| l.split("Timestamp:").nth(1))
        .map(|s| s.trim())
        .ok_or("Timestamp not found in PDF")?;
    
    let hash = lines.iter()
        .find(|l| l.contains("Verification Hash:"))
        .and_then(|l| l.split("Verification Hash:").nth(1))
        .map(|s| s.trim())
        .ok_or("Verification Hash not found in PDF")?;
    
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
        .map_err(|_| format!("Invalid timestamp format: '{}'", timestamp_str))?
        .with_timezone(&chrono::Utc);
    
    let row = sqlx::query!(
        "SELECT hash FROM certificates WHERE drive = $1 AND timestamp = $2",
        drive,
        timestamp
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;
    
    Ok(match row {
        Some(record) => record.hash == hash,
        None => false,
    })
}

#[command]
async fn select_file() -> Result<String, String> {
    let file = rfd::FileDialog::new()
        .pick_file()
        .ok_or("No file selected")?;
    
    Ok(file.to_string_lossy().to_string())
}

#[command]
async fn select_folder() -> Result<String, String> {
    let folder = rfd::FileDialog::new()
        .pick_folder()
        .ok_or("No folder selected")?;
    
    Ok(folder.to_string_lossy().to_string())
}

#[command]
async fn lock_sensitive_files(
    file_paths: Vec<String>,
    _user_id: i32,
) -> Result<(), String> {
    use std::path::Path;
    
    for file_path in &file_paths {
        let path = Path::new(file_path);
        
        if OS == "windows" {
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
                
                // 6. Set read-only + system + hidden attributes
                let _ = Command::new("attrib")
                    .args(&["+R", "+S", "+H", file_path])
                    .output();
            }
        } else {
            // Linux/Unix: Change permissions to 000
            Command::new("chmod")
                .args(&["-R", "000", file_path])
                .status()
                .map_err(|e| format!("Failed to lock file {}: {}", file_path, e))?;
        }
    }
    
    Ok(())
}

#[command]
async fn unlock_sensitive_files(
    file_paths: Vec<String>,
    _user_id: i32,
) -> Result<(), String> {
    for file_path in &file_paths {
        let _path = std::path::Path::new(file_path);
        
        if OS == "windows" {
            // Windows: Restore full control permissions
            Command::new("icacls")
                .args(&[file_path, "/grant", "Everyone:F"])
                .status()
                .map_err(|e| format!("Failed to unlock file {}: {}", file_path, e))?;
        } else {
            // Linux/Unix: Restore read/write permissions
            Command::new("chmod")
                .args(&["644", file_path])
                .status()
                .map_err(|e| format!("Failed to unlock file {}: {}", file_path, e))?;
        }
    }
    
    Ok(())
}

#[command]
async fn change_user_password(
    user_id: i32,
    current_password: String,
    new_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let user = sqlx::query!("SELECT password FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| "User not found".to_string())?;
    
    if !verify(current_password, &user.password)
        .map_err(|e| format!("Password verification failed: {}", e))? {
        return Err("Current password is incorrect".to_string());
    }
    
    let hashed_password = hash(new_password, DEFAULT_COST)
        .map_err(|e| format!("Password hashing failed: {}", e))?;
    
    sqlx::query!("UPDATE users SET password = $1 WHERE id = $2", hashed_password, user_id)
        .execute(&state.db)
        .await
        .map_err(|e| format!("Failed to update password: {}", e))?;
    
    Ok(())
}

#[command]
async fn change_user_pin(
    user_id: i32,
    password: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let user = sqlx::query!("SELECT password FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| "User not found".to_string())?;
    
    if !verify(password, &user.password)
        .map_err(|e| format!("Password verification failed: {}", e))? {
        return Err("Password is incorrect".to_string());
    }
    
    let mut rng = StdRng::from_entropy();
    let new_pin = format!("{:06}", rng.next_u32() % 1_000_000);
    
    sqlx::query!("UPDATE users SET confirmation_pin = $1 WHERE id = $2", &new_pin, user_id)
        .execute(&state.db)
        .await
        .map_err(|e| format!("Failed to update PIN: {}", e))?;
    
    Ok(new_pin)
}

#[command]
async fn refresh_token(
    token: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|_| "Invalid token".to_string())?;

    let user = sqlx::query!(
        "SELECT id, username, email FROM users WHERE id = $1",
        token_data.claims.sub
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| "User not found".to_string())?;

    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id,
        exp: expiration,
        email: user.email,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| format!("JWT creation failed: {}", e))
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
    .manage(state)
 .invoke_handler(tauri::generate_handler![
    register_user,
    login_user,
    verify_token,
    update_profile,
    list_drives,
    drive_info,
    list_files,
    list_all_files,
    generate_certificate,
    verify_certificate,
    verify_user_pin,
    list_certificates,
    verify_user_password,
    download_certificate,
    download_certificate_pdf,
    verify_certificate_pdf,
    lock_sensitive_files,
    unlock_sensitive_files,
    change_user_password,
    change_user_pin,
    refresh_token,
    bootable::create_bootable_usb,
    bootable::list_usb_drives,
    iso_builder::create_iso,
    iso_builder::build_bootable_environment,
    pxe_server::start_pxe_server,
    pxe_server::stop_pxe_server,
    pxe_server::get_client_statuses,
    pxe_server::validate_pxe_config,
    geofence::scan_wifi_networks,
    geofence::setup_geofence,
    geofence::start_geofence_monitoring,
    geofence::stop_geofence_monitoring,
    geofence::get_geofence_status,
    geofence::unlock_with_pin,
    geofence::lock_all_system_files,
    select_file,
    select_folder,


])


    .run(tauri::generate_context!())
    .expect("error while running tauri application");

}

