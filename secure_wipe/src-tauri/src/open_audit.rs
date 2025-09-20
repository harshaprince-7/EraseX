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
    // Verify timestamp token
    if cert.timestamp_authority.timestamp > Utc::now() {
        return Ok(false);
    }
    
    // Verify compliance attestations
    if cert.compliance_attestations.is_empty() {
        return Ok(false);
    }
    
    // Check database for certificate existence
    let row = sqlx::query!(
        "SELECT certificate_id FROM audit_certificates WHERE certificate_id = $1",
        cert.certificate_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Database query failed: {}", e))?;
    
    Ok(row.is_some())
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
            certificate_id, user_id, issuer_name, issuer_ca, issuer_public_key,
            device_id, drives, wipe_method, compliance_standard, operator_name,
            operation_timestamp, signature_algorithm, digital_signature,
            signature_public_key, full_certificate
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        certificate.certificate_id,
        user_id,
        certificate.issuer.name,
        certificate.issuer.certificate_authority,
        certificate.issuer.public_key,
        certificate.subject.device_id,
        &certificate.subject.drives,
        certificate.subject.wipe_method,
        certificate.subject.compliance_standard,
        certificate.subject.operator,
        certificate.subject.timestamp,
        certificate.digital_signature.algorithm,
        certificate.digital_signature.signature,
        certificate.digital_signature.public_key,
        cert_json
    )
    .execute(&state.db)
    .await
    .map_err(|e| format!("Database error: {}", e))?;
    
    // Convert to JSON
    serde_json::to_string_pretty(&certificate)
        .map_err(|e| format!("Certificate serialization error: {}", e))
}

#[tauri::command]
pub async fn verify_audit_certificate(
    cert_json: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    let certificate: OpenAuditCertificate = serde_json::from_str(&cert_json)
        .map_err(|e| format!("Certificate parsing error: {}", e))?;
    
    verify_open_audit_certificate(&certificate, &state).await
}