use std::collections::{BTreeMap, HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::de::from_slice;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("invalid digest format: {0}")]
    InvalidDigestFormat(String),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("missing public key for signer: {0}")]
    MissingPublicKey(String),
    #[error("signature set is empty")]
    EmptySignatureSet,
    #[error("base64 decode failed")]
    Base64Decode,
    #[error("invalid signature bytes")]
    SignatureBytes,
    #[error("signature verification failed for signer: {0}")]
    SignatureVerify(String),
    #[error("canonical JSON serialization failed")]
    CanonicalJson,
    #[error("invalid manifest JSON")]
    ManifestJson,
    #[error("invalid signatures JSON")]
    SignaturesJson,
    #[error("invalid provenance JSON")]
    ProvenanceJson,
    #[error("invalid registry snapshot JSON")]
    SnapshotJson,
    #[error("invalid execution receipt JSON")]
    ReceiptJson,
    #[error("invalid policy document")]
    PolicyDocument,
    #[error("unsupported policy version: {0}")]
    UnsupportedPolicyVersion(u64),
    #[error("policy.trusted_signers must be non-empty")]
    EmptyTrustedSigners,
    #[error("no trusted signer declared in manifest.signers")]
    UntrustedManifestSigners,
    #[error("no trusted signer present in signatures.json")]
    UntrustedSignatureSet,
    #[error("signature signer is not declared in manifest.signers: {0}")]
    SignatureSignerNotDeclared(String),
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("policy constraint violation: {0}")]
    PolicyConstraint(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub artifact: String,
    pub capabilities: Vec<Capability>,
    pub signers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    pub artifact: String,
    pub manifest_hash: String,
    pub signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    pub commit: String,
    pub build_system: String,
    pub build_recipe_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub snapshot_hash: String,
    pub timestamp: u64,
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub artifact: String,
    pub inputs_hash: String,
    pub outputs_hash: String,
    pub caps_used: Vec<String>,
    pub timestamp: u64,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub trusted_signers: Vec<String>,
    pub capability_ceiling: CapabilityCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCeiling {
    pub fs: Option<PolicyFs>,
    pub net: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub exec: Option<bool>,
    pub time: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFs {
    pub read: Option<Vec<String>>,
    pub write: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotHashPayload<'a> {
    timestamp: u64,
    entries: &'a BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptHashPayload<'a> {
    artifact: &'a str,
    inputs_hash: &'a str,
    outputs_hash: &'a str,
    caps_used: &'a [String],
    timestamp: u64,
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

pub fn parse_manifest_json(bytes: &[u8]) -> Result<Manifest, VerifyError> {
    let manifest: Manifest = from_slice(bytes).map_err(|_| VerifyError::ManifestJson)?;
    validate_sha256_prefixed(&manifest.artifact)?;
    Ok(manifest)
}

pub fn parse_signatures_json(bytes: &[u8]) -> Result<Signatures, VerifyError> {
    let signatures: Signatures = from_slice(bytes).map_err(|_| VerifyError::SignaturesJson)?;
    validate_sha256_prefixed(&signatures.artifact)?;
    validate_sha256_prefixed(&signatures.manifest_hash)?;
    Ok(signatures)
}

pub fn compute_manifest_hash(manifest: &Manifest) -> Result<String, VerifyError> {
    let bytes = to_jcs_bytes(manifest)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn parse_provenance_json(bytes: &[u8]) -> Result<Provenance, VerifyError> {
    let provenance: Provenance = from_slice(bytes).map_err(|_| VerifyError::ProvenanceJson)?;
    validate_sha256_prefixed(&provenance.build_recipe_hash)?;
    Ok(provenance)
}

pub fn parse_snapshot_json(bytes: &[u8]) -> Result<RegistrySnapshot, VerifyError> {
    let snapshot: RegistrySnapshot = from_slice(bytes).map_err(|_| VerifyError::SnapshotJson)?;
    validate_sha256_prefixed(&snapshot.snapshot_hash)?;
    for digest in snapshot.entries.values() {
        validate_sha256_prefixed(digest)?;
    }
    Ok(snapshot)
}

pub fn parse_receipt_json(bytes: &[u8]) -> Result<ExecutionReceipt, VerifyError> {
    let receipt: ExecutionReceipt = from_slice(bytes).map_err(|_| VerifyError::ReceiptJson)?;
    validate_sha256_prefixed(&receipt.artifact)?;
    validate_sha256_prefixed(&receipt.inputs_hash)?;
    validate_sha256_prefixed(&receipt.outputs_hash)?;
    validate_sha256_prefixed(&receipt.receipt_hash)?;
    Ok(receipt)
}

pub fn parse_policy_document(bytes: &[u8]) -> Result<Policy, VerifyError> {
    let policy: Policy = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => serde_yaml::from_slice(bytes).map_err(|_| VerifyError::PolicyDocument)?,
    };
    if policy.version != 1 {
        return Err(VerifyError::UnsupportedPolicyVersion(policy.version));
    }
    if policy.trusted_signers.is_empty() {
        return Err(VerifyError::EmptyTrustedSigners);
    }
    validate_policy_constraints(&policy)?;
    Ok(policy)
}

pub fn verify_artifact_hash(skill_wasm: &[u8], expected_artifact: &str) -> Result<(), VerifyError> {
    validate_sha256_prefixed(expected_artifact)?;
    let actual = sha256_prefixed(skill_wasm);
    if actual != expected_artifact {
        return Err(VerifyError::DigestMismatch {
            expected: expected_artifact.to_string(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_snapshot_hash(snapshot: &RegistrySnapshot) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&snapshot.snapshot_hash)?;
    let payload = SnapshotHashPayload {
        timestamp: snapshot.timestamp,
        entries: &snapshot.entries,
    };
    let bytes = to_jcs_bytes(&payload)?;
    let actual = sha256_prefixed(&bytes);
    if actual != snapshot.snapshot_hash {
        return Err(VerifyError::DigestMismatch {
            expected: snapshot.snapshot_hash.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_receipt_hash(receipt: &ExecutionReceipt) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&receipt.artifact)?;
    validate_sha256_prefixed(&receipt.inputs_hash)?;
    validate_sha256_prefixed(&receipt.outputs_hash)?;
    validate_sha256_prefixed(&receipt.receipt_hash)?;

    let actual = compute_receipt_hash(
        &receipt.artifact,
        &receipt.inputs_hash,
        &receipt.outputs_hash,
        &receipt.caps_used,
        receipt.timestamp,
    )?;
    if actual != receipt.receipt_hash {
        return Err(VerifyError::DigestMismatch {
            expected: receipt.receipt_hash.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn compute_receipt_hash(
    artifact: &str,
    inputs_hash: &str,
    outputs_hash: &str,
    caps_used: &[String],
    timestamp: u64,
) -> Result<String, VerifyError> {
    let payload = ReceiptHashPayload {
        artifact,
        inputs_hash,
        outputs_hash,
        caps_used,
        timestamp,
    };
    let bytes = to_jcs_bytes(&payload)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn verify_signatures(
    signatures: &Signatures,
    public_keys: &HashMap<String, VerifyingKey>,
) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&signatures.artifact)?;
    validate_sha256_prefixed(&signatures.manifest_hash)?;
    if signatures.signatures.is_empty() {
        return Err(VerifyError::EmptySignatureSet);
    }
    for entry in &signatures.signatures {
        if entry.algorithm != "ed25519" {
            return Err(VerifyError::UnsupportedSignatureAlgorithm(
                entry.algorithm.clone(),
            ));
        }
        let key = public_keys
            .get(&entry.signer)
            .ok_or_else(|| VerifyError::MissingPublicKey(entry.signer.clone()))?;
        let raw = STANDARD
            .decode(entry.signature.as_bytes())
            .map_err(|_| VerifyError::Base64Decode)?;
        let signature = Signature::from_slice(&raw).map_err(|_| VerifyError::SignatureBytes)?;
        key.verify(signatures.manifest_hash.as_bytes(), &signature)
            .map_err(|_| VerifyError::SignatureVerify(entry.signer.clone()))?;
    }
    Ok(())
}

pub fn verify_trusted_signers(
    manifest: &Manifest,
    signatures: &Signatures,
    policy: &Policy,
) -> Result<(), VerifyError> {
    let trusted = &policy.trusted_signers;
    let manifest_signers = manifest
        .signers
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let trusted_signers = trusted.iter().map(String::as_str).collect::<HashSet<_>>();

    if manifest_signers.is_disjoint(&trusted_signers) {
        return Err(VerifyError::UntrustedManifestSigners);
    }

    for entry in &signatures.signatures {
        if !manifest_signers.contains(entry.signer.as_str()) {
            return Err(VerifyError::SignatureSignerNotDeclared(
                entry.signer.clone(),
            ));
        }
    }

    if !signatures.signatures.iter().any(|entry| {
        manifest_signers.contains(entry.signer.as_str())
            && trusted_signers.contains(entry.signer.as_str())
    }) {
        return Err(VerifyError::UntrustedSignatureSet);
    }
    Ok(())
}

pub fn enforce_capability_ceiling(
    capabilities: &[Capability],
    policy: &Policy,
) -> Result<(), VerifyError> {
    for capability in capabilities {
        if !is_capability_allowed(capability, &policy.capability_ceiling) {
            return Err(VerifyError::CapabilityDenied(format!(
                "{}:{}",
                capability.kind, capability.value
            )));
        }
    }
    Ok(())
}

fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, VerifyError> {
    serde_jcs::to_vec(value).map_err(|_| VerifyError::CanonicalJson)
}

fn validate_sha256_prefixed(value: &str) -> Result<(), VerifyError> {
    if value.len() != 71 || !value.starts_with("sha256:") {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    if !value[7..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    Ok(())
}

fn is_capability_allowed(capability: &Capability, ceiling: &CapabilityCeiling) -> bool {
    match capability.kind.as_str() {
        "fs.read" => {
            let Some(path) = normalize_abs_path(&capability.value) else {
                return false;
            };
            let Some(fs) = &ceiling.fs else {
                return false;
            };
            let Some(prefixes) = &fs.read else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                normalize_abs_path(prefix)
                    .map(|normalized| path_within_prefix(&path, &normalized))
                    .unwrap_or(false)
            })
        }
        "fs.write" => {
            let Some(path) = normalize_abs_path(&capability.value) else {
                return false;
            };
            let Some(fs) = &ceiling.fs else {
                return false;
            };
            let Some(prefixes) = &fs.write else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                normalize_abs_path(prefix)
                    .map(|normalized| path_within_prefix(&path, &normalized))
                    .unwrap_or(false)
            })
        }
        "net" => {
            let Ok(requested) = Url::parse(&capability.value) else {
                return false;
            };
            let Some(prefixes) = &ceiling.net else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                Url::parse(prefix)
                    .ok()
                    .map(|allowed| net_uri_within_prefix(&requested, &allowed))
                    .unwrap_or(false)
            })
        }
        "env" => {
            if !is_valid_env_name(&capability.value) {
                return false;
            }
            let Some(allowed) = &ceiling.env else {
                return false;
            };
            allowed.iter().any(|name| name == &capability.value)
        }
        "exec" => capability.value == "true" && ceiling.exec.unwrap_or(false),
        "time" => capability.value == "true" && ceiling.time.unwrap_or(false),
        _ => false,
    }
}

fn normalize_abs_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut normalized = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return None;
        }
        normalized.push(part);
    }
    if normalized.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", normalized.join("/")))
    }
}

fn path_within_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn normalize_uri_path(path: &str) -> Option<String> {
    let raw = if path.is_empty() { "/" } else { path };
    normalize_abs_path(raw)
}

fn net_uri_within_prefix(requested: &Url, allowed: &Url) -> bool {
    if !requested.has_authority() || !allowed.has_authority() {
        return false;
    }
    if requested.scheme() != allowed.scheme() {
        return false;
    }
    if requested.host_str() != allowed.host_str() {
        return false;
    }
    if requested.port_or_known_default() != allowed.port_or_known_default() {
        return false;
    }
    if requested.username() != allowed.username() || requested.password() != allowed.password() {
        return false;
    }
    if requested.fragment().is_some() || allowed.query().is_some() || allowed.fragment().is_some() {
        return false;
    }
    let Some(requested_path) = normalize_uri_path(requested.path()) else {
        return false;
    };
    let Some(allowed_path) = normalize_uri_path(allowed.path()) else {
        return false;
    };
    path_within_prefix(&requested_path, &allowed_path)
}

fn is_valid_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn validate_policy_constraints(policy: &Policy) -> Result<(), VerifyError> {
    if has_duplicates(&policy.trusted_signers) {
        return Err(VerifyError::PolicyConstraint(
            "trusted_signers must be unique".to_string(),
        ));
    }
    let ceiling = &policy.capability_ceiling;
    if let Some(fs) = &ceiling.fs {
        if let Some(read) = &fs.read {
            if read.iter().any(|path| !path.starts_with('/')) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.read items must start with '/'".to_string(),
                ));
            }
            if has_duplicates(read) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.read items must be unique".to_string(),
                ));
            }
        }
        if let Some(write) = &fs.write {
            if write.iter().any(|path| !path.starts_with('/')) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.write items must start with '/'".to_string(),
                ));
            }
            if has_duplicates(write) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.write items must be unique".to_string(),
                ));
            }
        }
    }
    if let Some(net) = &ceiling.net {
        if net.iter().any(|uri| {
            let Ok(parsed) = Url::parse(uri) else {
                return true;
            };
            if !parsed.has_authority() || parsed.query().is_some() || parsed.fragment().is_some() {
                return true;
            }
            normalize_uri_path(parsed.path()).is_none()
        }) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.net items must be absolute authority URIs without query/fragment and with normalized paths".to_string(),
            ));
        }
        if has_duplicates(net) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.net items must be unique".to_string(),
            ));
        }
    }
    if let Some(env) = &ceiling.env {
        if env.iter().any(|name| !is_valid_env_name(name)) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.env items must match ^[A-Z_][A-Z0-9_]*$".to_string(),
            ));
        }
        if has_duplicates(env) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.env items must be unique".to_string(),
            ));
        }
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        if !seen.insert(value) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn parses_manifest_json() {
        let raw = br#"{
            "name":"echo",
            "version":"1.0.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[{"kind":"net","value":"https://example.com"}],
            "signers":["alice.dev"]
        }"#;
        let manifest = parse_manifest_json(raw).expect("manifest should parse");
        assert_eq!(manifest.name, "echo");
    }

    #[test]
    fn rejects_manifest_json_with_unknown_field() {
        let raw = br#"{
            "name":"echo",
            "version":"1.0.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[],
            "signers":[],
            "unexpected":"x"
        }"#;
        assert!(matches!(
            parse_manifest_json(raw),
            Err(VerifyError::ManifestJson)
        ));
    }

    #[test]
    fn parses_signatures_json() {
        let raw = br#"{
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "signatures":[{"signer":"alice.dev","algorithm":"ed25519","signature":"AA=="}]
        }"#;
        let signatures = parse_signatures_json(raw).expect("signatures should parse");
        assert_eq!(signatures.signatures.len(), 1);
    }

    #[test]
    fn parses_provenance_json() {
        let raw = br#"{
            "source":"https://example.com/repo",
            "commit":"abc123",
            "build_system":"cargo",
            "build_recipe_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;
        let provenance = parse_provenance_json(raw).expect("provenance should parse");
        assert_eq!(provenance.build_system, "cargo");
    }

    #[test]
    fn rejects_provenance_json_with_unknown_field() {
        let raw = br#"{
            "source":"https://example.com/repo",
            "commit":"abc123",
            "build_system":"cargo",
            "build_recipe_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unexpected":"x"
        }"#;
        assert!(matches!(
            parse_provenance_json(raw),
            Err(VerifyError::ProvenanceJson)
        ));
    }

    #[test]
    fn parses_snapshot_json() {
        let raw = br#"{
            "snapshot_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp":1,
            "entries":{"echo@1.0.0":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        }"#;
        let snapshot = parse_snapshot_json(raw).expect("snapshot should parse");
        assert_eq!(snapshot.entries.len(), 1);
    }

    #[test]
    fn parses_receipt_json() {
        let raw = br#"{
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "caps_used":["net:https://example.com"],
            "timestamp":1,
            "receipt_hash":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }"#;
        let receipt = parse_receipt_json(raw).expect("receipt should parse");
        assert_eq!(receipt.caps_used.len(), 1);
    }

    #[test]
    fn verifies_artifact_hash() {
        let wasm = b"\0asm";
        let digest = sha256_prefixed(wasm);
        assert!(verify_artifact_hash(wasm, &digest).is_ok());
    }

    #[test]
    fn rejects_bad_artifact_hash() {
        let wasm = b"\0asm";
        let bad = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(matches!(
            verify_artifact_hash(wasm, bad),
            Err(VerifyError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verifies_snapshot_hash_using_payload_without_snapshot_hash_field() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "echo@1.0.0".to_string(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );

        let payload = SnapshotHashPayload {
            timestamp: 1234,
            entries: &entries,
        };
        let expected = sha256_prefixed(&to_jcs_bytes(&payload).unwrap());

        let snapshot = RegistrySnapshot {
            snapshot_hash: expected,
            timestamp: 1234,
            entries,
        };
        assert!(verify_snapshot_hash(&snapshot).is_ok());
    }

    #[test]
    fn verifies_receipt_hash_using_payload_without_receipt_hash_field() {
        let payload = ReceiptHashPayload {
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            inputs_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            outputs_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            caps_used: &["net:https://example.com".to_string()],
            timestamp: 42,
        };
        let expected = sha256_prefixed(&to_jcs_bytes(&payload).unwrap());
        let receipt = ExecutionReceipt {
            artifact: payload.artifact.to_string(),
            inputs_hash: payload.inputs_hash.to_string(),
            outputs_hash: payload.outputs_hash.to_string(),
            caps_used: payload.caps_used.to_vec(),
            timestamp: payload.timestamp,
            receipt_hash: expected,
        };
        assert!(verify_receipt_hash(&receipt).is_ok());
    }

    #[test]
    fn verifies_ed25519_signature_over_manifest_hash_string_bytes() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let artifact = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let sig = signing_key.sign(manifest_hash.as_bytes());
        let signatures = Signatures {
            artifact: artifact.to_string(),
            manifest_hash: manifest_hash.to_string(),
            signatures: vec![SignatureEntry {
                signer: "alice.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: STANDARD.encode(sig.to_bytes()),
            }],
        };
        let mut keys = HashMap::new();
        keys.insert("alice.dev".to_string(), verifying_key);

        assert!(verify_signatures(&signatures, &keys).is_ok());
    }

    #[test]
    fn rejects_empty_signature_set() {
        let signatures = Signatures {
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: Vec::new(),
        };
        let keys = HashMap::new();
        assert!(matches!(
            verify_signatures(&signatures, &keys),
            Err(VerifyError::EmptySignatureSet)
        ));
    }

    #[test]
    fn parses_policy_document_from_yaml() {
        let raw = br#"
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  env: ["HOME"]
  exec: false
  time: false
"#;
        let policy = parse_policy_document(raw).expect("policy should parse");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.trusted_signers, vec!["alice.dev".to_string()]);
    }

    #[test]
    fn verifies_trusted_signer_intersection() {
        let manifest = Manifest {
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "alice.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                env: None,
                exec: Some(false),
                time: Some(false),
            },
        };
        assert!(verify_trusted_signers(&manifest, &signatures, &policy).is_ok());
    }

    #[test]
    fn rejects_signature_signer_not_declared_in_manifest() {
        let manifest = Manifest {
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "mallory.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string(), "mallory.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                env: None,
                exec: Some(false),
                time: Some(false),
            },
        };
        assert!(matches!(
            verify_trusted_signers(&manifest, &signatures, &policy),
            Err(VerifyError::SignatureSignerNotDeclared(_))
        ));
    }

    #[test]
    fn rejects_split_trust_between_manifest_and_signatures() {
        let manifest = Manifest {
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string(), "bob.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "bob.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                env: None,
                exec: Some(false),
                time: Some(false),
            },
        };
        assert!(matches!(
            verify_trusted_signers(&manifest, &signatures, &policy),
            Err(VerifyError::UntrustedSignatureSet)
        ));
    }

    #[test]
    fn denies_capability_outside_policy_ceiling() {
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: Some(vec!["https://api.example.com".to_string()]),
                env: None,
                exec: Some(false),
                time: Some(false),
            },
        };
        let requested = vec![Capability {
            kind: "net".to_string(),
            value: "https://evil.example.com/path".to_string(),
        }];
        assert!(matches!(
            enforce_capability_ceiling(&requested, &policy),
            Err(VerifyError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn denies_net_capability_with_host_prefix_confusion() {
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: Some(vec!["https://api.example.com".to_string()]),
                env: None,
                exec: Some(false),
                time: Some(false),
            },
        };
        let requested = vec![Capability {
            kind: "net".to_string(),
            value: "https://api.example.com.evil.tld/v1".to_string(),
        }];
        assert!(matches!(
            enforce_capability_ceiling(&requested, &policy),
            Err(VerifyError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn denies_policy_net_prefix_with_query_or_fragment() {
        let raw = br#"{
          "version": 1,
          "trusted_signers": ["alice.dev"],
          "capability_ceiling": {
            "net": ["https://api.example.com/v1?token=abc"]
          }
        }"#;
        assert!(matches!(
            parse_policy_document(raw),
            Err(VerifyError::PolicyConstraint(_))
        ));
    }
}
