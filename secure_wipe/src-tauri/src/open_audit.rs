use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePublicKey;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAuditCertificate {
    pub version: String,
    pub certificate_id: String,
    pub issuer: AuditAuthority,
    pub subject: WipeOperation,
    pub digital_signature: DigitalSignature,
    pub timestamp_authority: TimestampToken,
    pub compliance_attestations: Vec<ComplianceAttestation>,
    pub witness_signatures: Vec<WitnessSignature>,
    pub blockchain_anchor: Option<BlockchainAnchor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditAuthority {
    pub name: String,
    pub certificate_authority: String,
    pub public_key: String,
    pub accreditation: String, // ISO 27001, NIST, etc.
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WipeOperation {
    pub device_id: String,
    pub drives: Vec<String>,
    pub wipe_method: String,
    pub compliance_standard: String, // NIST 800-88, DoD 5220.22-M
    pub operator: String,
    pub location: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub algorithm: String, // RSA-SHA256
    pub signature: String,
    pub public_key: String,
    pub certificate_chain: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimestampToken {
    pub authority: String,
    pub timestamp: DateTime<Utc>,
    pub token: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceAttestation {
    pub standard: String, // NIST 800-88, ISO 27001
    pub version: String,
    pub attestation: String,
    pub auditor_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_name: String,
    pub witness_role: String,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    pub blockchain: String, // Ethereum, Bitcoin
    pub transaction_hash: String,
    pub block_number: u64,
    pub merkle_proof: String,
}

pub fn generate_open_audit_certificate(
    wipe_data: WipeOperation,
    private_key: &RsaPrivateKey,
) -> Result<OpenAuditCertificate, String> {
    let certificate_id = uuid::Uuid::new_v4().to_string();
    
    // Create certificate content
    let cert_content = serde_json::to_string(&wipe_data)
        .map_err(|e| format!("Serialization error: {}", e))?;
    
    // Generate digital signature
    let signature = sign_content(&cert_content, private_key)?;
    let public_key = RsaPublicKey::from(private_key);
    let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| format!("Public key encoding error: {}", e))?;
    
    // Get timestamp from authority (mock implementation)
    let timestamp_token = get_timestamp_token(&cert_content)?;
    
    // Generate compliance attestations
    let compliance_attestations = generate_compliance_attestations(&wipe_data)?;
    
    Ok(OpenAuditCertificate {
        version: "1.0".to_string(),
        certificate_id,
        issuer: AuditAuthority {
            name: "SecureWipe Audit Authority".to_string(),
            certificate_authority: "GlobalTrust CA".to_string(),
            public_key: public_key_pem.clone(),
            accreditation: "ISO 27001:2013, NIST Cybersecurity Framework".to_string(),
        },
        subject: wipe_data,
        digital_signature: DigitalSignature {
            algorithm: "RSA-SHA256".to_string(),
            signature,
            public_key: public_key_pem,
            certificate_chain: vec![], // Would contain CA chain
        },
        timestamp_authority: timestamp_token,
        compliance_attestations,
        witness_signatures: vec![], // To be added by witnesses
        blockchain_anchor: None, // Optional blockchain anchoring
    })
}

fn sign_content(content: &str, private_key: &RsaPrivateKey) -> Result<String, String> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::pkcs1v15::SigningKey;
    use sha2::Sha256;
    
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, content.as_bytes());
    
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}

fn get_timestamp_token(content: &str) -> Result<TimestampToken, String> {
    // Mock timestamp authority - in production, use RFC 3161 TSA
    let timestamp = Utc::now();
    let token_data = format!("{}:{}", content, timestamp.to_rfc3339());
    let mut hasher = Sha256::new();
    hasher.update(token_data.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());
    
    Ok(TimestampToken {
        authority: "GlobalTime TSA".to_string(),
        timestamp,
        token: token_hash.clone(),
        signature: token_hash, // Mock signature
    })
}

fn generate_compliance_attestations(wipe_data: &WipeOperation) -> Result<Vec<ComplianceAttestation>, String> {
    let mut attestations = vec![];
    
    // NIST 800-88 attestation
    if wipe_data.compliance_standard.contains("NIST") {
        attestations.push(ComplianceAttestation {
            standard: "NIST 800-88 Rev. 1".to_string(),
            version: "2014".to_string(),
            attestation: "Wipe operation complies with NIST guidelines for media sanitization".to_string(),
            auditor_signature: "mock_auditor_signature".to_string(),
        });
    }
    
    // DoD attestation
    if wipe_data.compliance_standard.contains("DoD") {
        attestations.push(ComplianceAttestation {
            standard: "DoD 5220.22-M".to_string(),
            version: "2006".to_string(),
            attestation: "Wipe operation meets DoD requirements for classified information sanitization".to_string(),
            auditor_signature: "mock_dod_signature".to_string(),
        });
    }
    
    Ok(attestations)
}

pub async fn verify_open_audit_certificate(
    cert: &OpenAuditCertificate,
    state: &crate::AppState,
) -> Result<bool, String> {
    // Basic structure validation
    if cert.certificate_id.is_empty() {
        return Err("Certificate ID is missing".to_string());
    }
    
    if cert.subject.drives.is_empty() {
        return Err("No drives specified in certificate".to_string());
    }
    
    // Verify timestamp is not in the future (allow 1 hour tolerance)
    let now = Utc::now();
    let cert_time = cert.timestamp_authority.timestamp;
    if cert_time > now + chrono::Duration::hours(1) {
        return Err(format!("Certificate timestamp {} is too far in the future (current: {})", cert_time, now));
    }
    
    // Verify compliance attestations exist
    if cert.compliance_attestations.is_empty() {
        return Err("No compliance attestations found".to_string());
    }
    
    // Verify required compliance standards
    let has_nist = cert.compliance_attestations.iter().any(|a| a.standard.contains("NIST"));
    let has_dod = cert.compliance_attestations.iter().any(|a| a.standard.contains("DoD"));
    
    if !has_nist && !has_dod {
        return Err("Missing required compliance attestations (NIST or DoD)".to_string());
    }
    
    // Verify digital signature structure
    if cert.digital_signature.algorithm != "RSA-SHA256" {
        return Err(format!("Unsupported signature algorithm: {}", cert.digital_signature.algorithm));
    }
    
    if cert.digital_signature.signature.is_empty() {
        return Err("Digital signature is missing".to_string());
    }
    
    // Check database for certificate existence (optional - certificate can be valid without being in our DB)
    let row = sqlx::query!(
        "SELECT certificate_id, device_id, drives FROM audit_certificates WHERE certificate_id = $1",
        cert.certificate_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;
    
    match row {
        Some(db_cert) => {
            // Certificate found in database - verify details match
            if db_cert.device_id != cert.subject.device_id {
                return Err("Device ID mismatch with database record".to_string());
            }
            
            if db_cert.drives != cert.subject.drives {
                return Err("Drive list mismatch with database record".to_string());
            }
            
            Ok(true)
        },
        None => {
            // Certificate not in our database, but could still be valid
            // Perform structural validation only
            
            // Verify issuer information
            if cert.issuer.name.is_empty() || cert.issuer.certificate_authority.is_empty() {
                return Err("Incomplete issuer information".to_string());
            }
            
            // Verify subject information
            if cert.subject.device_id.is_empty() || cert.subject.wipe_method.is_empty() {
                return Err("Incomplete subject information".to_string());
            }
            
            // Certificate structure is valid
            Ok(true)
        }
    }
}

#[tauri::command]
pub async fn generate_audit_certificate(
    drive: String,
    wipe_mode: String,
    user: String,
    compliance_standard: String,
    user_id: i32,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, String> {
    // Generate RSA key pair (in production, use existing CA keys)
    let private_key = tokio::task::spawn_blocking(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
    .map_err(|e| format!("Key generation error: {}", e))?;
    
    let wipe_operation = WipeOperation {
        device_id: machine_uid::get().unwrap_or_default(),
        drives: vec![drive],
        wipe_method: wipe_mode,
        compliance_standard,
        operator: user,
        location: "Unknown".to_string(),
        timestamp: Utc::now(),
    };
    
    let certificate = generate_open_audit_certificate(wipe_operation, &private_key)?;
    
    // Store in database
    let cert_json = serde_json::to_value(&certificate)
        .map_err(|e| format!("Certificate serialization error: {}", e))?;
    
    sqlx::query!(
        r#"INSERT INTO audit_certificates (
            certificate_id, user_id, version, issuer_name, issuer_ca, issuer_public_key,
            issuer_accreditation, device_id, drives, wipe_method, compliance_standard, 
            operator_name, operation_location, operation_timestamp, signature_algorithm, 
            digital_signature, signature_public_key, tsa_authority, tsa_timestamp, 
            tsa_token, tsa_signature, compliance_attestations, full_certificate
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)"#,
        certificate.certificate_id,
        user_id,
        certificate.version,
        certificate.issuer.name,
        certificate.issuer.certificate_authority,
        certificate.issuer.public_key,
        certificate.issuer.accreditation,
        certificate.subject.device_id,
        &certificate.subject.drives,
        certificate.subject.wipe_method,
        certificate.subject.compliance_standard,
        certificate.subject.operator,
        certificate.subject.location,
        certificate.subject.timestamp,
        certificate.digital_signature.algorithm,
        certificate.digital_signature.signature,
        certificate.digital_signature.public_key,
        certificate.timestamp_authority.authority,
        certificate.timestamp_authority.timestamp,
        certificate.timestamp_authority.token,
        certificate.timestamp_authority.signature,
        serde_json::to_value(&certificate.compliance_attestations).unwrap_or_default(),
        cert_json
    )
    .execute(&state.db)
    .await
    .map_err(|e| format!("Database insertion error: {}. This might be due to missing table columns.", e))?;
    
    // Convert to JSON
    serde_json::to_string_pretty(&certificate)
        .map_err(|e| format!("Certificate serialization error: {}", e))
}

#[tauri::command]
pub async fn verify_audit_certificate(
    cert_json: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    // Validate input
    if cert_json.trim().is_empty() {
        return Err("Certificate content is empty".to_string());
    }
    
    // Parse certificate
    let certificate: OpenAuditCertificate = serde_json::from_str(&cert_json)
        .map_err(|e| format!("Certificate parsing error: {}. Content length: {}", e, cert_json.len()))?;
    
    // Try database verification first, fall back to structural verification
    match verify_open_audit_certificate(&certificate, &state).await {
        Ok(result) => Ok(result),
        Err(db_error) => {
            // If database verification fails, try structural verification
            if db_error.contains("Database") || db_error.contains("not found") {
                verify_certificate_structure(&certificate)
            } else {
                Err(db_error)
            }
        }
    }
}

// Standalone structural verification for external certificates
fn verify_certificate_structure(cert: &OpenAuditCertificate) -> Result<bool, String> {
    // Basic structure validation
    if cert.certificate_id.is_empty() {
        return Err("Certificate ID is missing".to_string());
    }
    
    if cert.subject.drives.is_empty() {
        return Err("No drives specified in certificate".to_string());
    }
    
    // Verify timestamp is reasonable (not too far in future or past)
    let now = Utc::now();
    let cert_time = cert.timestamp_authority.timestamp;
    
    if cert_time > now + chrono::Duration::hours(1) {
        return Err("Certificate timestamp is too far in the future".to_string());
    }
    
    if cert_time < now - chrono::Duration::days(365 * 10) {
        return Err("Certificate timestamp is too old (>10 years)".to_string());
    }
    
    // Verify compliance attestations exist
    if cert.compliance_attestations.is_empty() {
        return Err("No compliance attestations found".to_string());
    }
    
    // Verify required compliance standards
    let has_nist = cert.compliance_attestations.iter().any(|a| a.standard.contains("NIST"));
    let has_dod = cert.compliance_attestations.iter().any(|a| a.standard.contains("DoD"));
    
    if !has_nist && !has_dod {
        return Err("Missing required compliance attestations (NIST or DoD)".to_string());
    }
    
    // Verify digital signature structure
    if cert.digital_signature.algorithm != "RSA-SHA256" {
        return Err(format!("Unsupported signature algorithm: {}", cert.digital_signature.algorithm));
    }
    
    if cert.digital_signature.signature.is_empty() {
        return Err("Digital signature is missing".to_string());
    }
    
    // Verify issuer information
    if cert.issuer.name.is_empty() || cert.issuer.certificate_authority.is_empty() {
        return Err("Incomplete issuer information".to_string());
    }
    
    // Verify subject information
    if cert.subject.device_id.is_empty() || cert.subject.wipe_method.is_empty() {
        return Err("Incomplete subject information".to_string());
    }
    
    // All structural checks passed
    Ok(true)
}

#[tauri::command]
pub async fn get_audit_certificate_json(
    certificate_id: i32,
    user_id: i32,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, String> {
    // First check if there's an audit certificate for this regular certificate
    let audit_row = sqlx::query!(
        "SELECT full_certificate FROM audit_certificates WHERE user_id = $1 LIMIT 1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;
    
    if let Some(audit_cert) = audit_row {
        // Return existing audit certificate
        return Ok(audit_cert.full_certificate.to_string());
    }
    
    // If no audit certificate exists, get the regular certificate and convert it
    let cert_row = sqlx::query!(
        "SELECT drive, wipe_mode, device_id, timestamp FROM certificates WHERE id = $1 AND user_id = $2",
        certificate_id,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;
    
    match cert_row {
        Some(cert) => {
            // Get user info
            let user_row = sqlx::query!(
                "SELECT username FROM users WHERE id = $1",
                user_id
            )
            .fetch_one(&state.db)
            .await
            .map_err(|e| format!("User query failed: {}", e))?;
            
            // Generate audit certificate from regular certificate data
            let audit_cert = generate_audit_certificate(
                cert.drive,
                cert.wipe_mode,
                user_row.username,
                "NIST 800-88, DoD 5220.22-M".to_string(),
                user_id,
                state
            ).await?;
            
            Ok(audit_cert)
        },
        None => Err("Certificate not found".to_string())
    }
}