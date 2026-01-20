//! OIDC-Loki Rust Client Example
//!
//! This example demonstrates how to test a Rust OIDC client against
//! OIDC-Loki's malicious tokens.
//!
//! Run: cargo run
//! Prerequisites: OIDC-Loki running on http://localhost:9000

use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{decode_header, Algorithm};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const LOKI_URL: &str = "http://localhost:9000";
const CLIENT_ID: &str = "test-client";
const CLIENT_SECRET: &str = "test-secret";

#[derive(Debug, Serialize)]
struct SessionRequest {
    name: String,
    mode: String,
    mischief: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct Claims {
    exp: Option<u64>,
    iss: Option<String>,
}

#[derive(Debug)]
struct TestResult {
    name: &'static str,
    passed: bool,
    message: String,
}

fn create_session(client: &Client, name: &str, mischief: Vec<&str>) -> Option<String> {
    let request = SessionRequest {
        name: name.to_string(),
        mode: "explicit".to_string(),
        mischief: mischief.into_iter().map(String::from).collect(),
    };

    match client
        .post(format!("{}/admin/sessions", LOKI_URL))
        .json(&request)
        .send()
    {
        Ok(response) if response.status().is_success() => {
            response.json::<SessionResponse>().ok().map(|s| s.session_id)
        }
        Ok(response) => {
            println!("  SKIP: Session creation failed: {}", response.status());
            None
        }
        Err(e) => {
            println!("  SKIP: Could not create session: {}", e);
            None
        }
    }
}

fn get_token(client: &Client, session_id: Option<&str>) -> Option<String> {
    let auth = STANDARD.encode(format!("{}:{}", CLIENT_ID, CLIENT_SECRET));

    let mut request = client
        .post(format!("{}/token", LOKI_URL))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {}", auth))
        .body("grant_type=client_credentials");

    if let Some(sid) = session_id {
        request = request.header("X-Loki-Session", sid);
    }

    match request.send() {
        Ok(response) if response.status().is_success() => {
            response.json::<TokenResponse>().ok().map(|t| t.access_token)
        }
        Ok(response) => {
            println!("  SKIP: Token request failed: {}", response.status());
            None
        }
        Err(e) => {
            println!("  SKIP: Could not get token: {}", e);
            None
        }
    }
}

/// Validate a token with security checks.
///
/// In production, use a proper OIDC library.
/// This example demonstrates the security checks your client should perform.
fn validate_token(token: &str) -> Result<(), String> {
    // Parse the header
    let header = decode_header(token).map_err(|e| format!("Invalid token format: {}", e))?;

    // Security Check 1: Reject alg:none
    if header.alg == Algorithm::HS256 && token.ends_with('.') {
        // Check for unsigned tokens
        return Err(
            "SECURITY: token uses alg:none - unsigned tokens not allowed".to_string(),
        );
    }

    // Handle "none" algorithm explicitly
    let alg_str = format!("{:?}", header.alg);
    if alg_str.to_lowercase() == "none" {
        return Err(
            "SECURITY: token uses alg:none - unsigned tokens not allowed".to_string(),
        );
    }

    // Security Check 2: Reject symmetric algorithms (key confusion defense)
    match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            return Err(format!(
                "SECURITY: symmetric algorithm {:?} not allowed - possible key confusion attack",
                header.alg
            ));
        }
        _ => {}
    }

    // Decode claims without verification (for demo purposes)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid token structure".to_string());
    }

    let claims_json = STANDARD
        .decode(parts[1])
        .or_else(|_| {
            // Try URL-safe base64
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
        })
        .map_err(|e| format!("Invalid claims encoding: {}", e))?;

    let claims: Claims =
        serde_json::from_slice(&claims_json).map_err(|e| format!("Invalid claims JSON: {}", e))?;

    // Security Check 3: Validate expiration
    if let Some(exp) = claims.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if exp < now {
            return Err("SECURITY: token is expired".to_string());
        }
    }

    // Security Check 4: Validate issuer
    if let Some(iss) = &claims.iss {
        if iss != LOKI_URL {
            return Err(format!("SECURITY: unexpected issuer: {}", iss));
        }
    }

    Ok(())
}

fn test_alg_none(client: &Client) -> TestResult {
    println!("\nTest 1: Algorithm None Attack");
    println!("{}", "-".repeat(40));

    let session_id = match create_session(client, "rust-alg-none-test", vec!["alg-none"]) {
        Some(id) => id,
        None => {
            return TestResult {
                name: "alg-none",
                passed: false,
                message: "Could not create session".to_string(),
            }
        }
    };

    let token = match get_token(client, Some(&session_id)) {
        Some(t) => t,
        None => {
            return TestResult {
                name: "alg-none",
                passed: false,
                message: "Could not get token".to_string(),
            }
        }
    };

    match validate_token(&token) {
        Ok(_) => {
            println!("  FAIL: Client accepted alg:none token!");
            TestResult {
                name: "alg-none",
                passed: false,
                message: "Client accepted unsigned token".to_string(),
            }
        }
        Err(e) if e.contains("alg:none") || e.contains("symmetric") => {
            println!("  PASS: Client correctly rejected alg:none token");
            println!("  Error: {}", e);
            TestResult {
                name: "alg-none",
                passed: true,
                message: e,
            }
        }
        Err(e) => {
            println!("  PASS: Client rejected token: {}", e);
            TestResult {
                name: "alg-none",
                passed: true,
                message: e,
            }
        }
    }
}

fn test_key_confusion(client: &Client) -> TestResult {
    println!("\nTest 2: Key Confusion Attack");
    println!("{}", "-".repeat(40));

    let session_id = match create_session(client, "rust-key-confusion-test", vec!["key-confusion"]) {
        Some(id) => id,
        None => {
            return TestResult {
                name: "key-confusion",
                passed: false,
                message: "Could not create session".to_string(),
            }
        }
    };

    let token = match get_token(client, Some(&session_id)) {
        Some(t) => t,
        None => {
            return TestResult {
                name: "key-confusion",
                passed: false,
                message: "Could not get token".to_string(),
            }
        }
    };

    match validate_token(&token) {
        Ok(_) => {
            println!("  FAIL: Client accepted key confusion token!");
            TestResult {
                name: "key-confusion",
                passed: false,
                message: "Client accepted HS256 token".to_string(),
            }
        }
        Err(e) if e.to_lowercase().contains("key confusion") || e.contains("symmetric") => {
            println!("  PASS: Client correctly rejected HS256 token");
            println!("  Error: {}", e);
            TestResult {
                name: "key-confusion",
                passed: true,
                message: e,
            }
        }
        Err(e) => {
            println!("  PASS: Client rejected token: {}", e);
            TestResult {
                name: "key-confusion",
                passed: true,
                message: e,
            }
        }
    }
}

fn test_temporal_tampering(client: &Client) -> TestResult {
    println!("\nTest 3: Temporal Tampering (Expired Token)");
    println!("{}", "-".repeat(40));

    let session_id = match create_session(client, "rust-temporal-test", vec!["temporal-tampering"]) {
        Some(id) => id,
        None => {
            return TestResult {
                name: "temporal-tampering",
                passed: false,
                message: "Could not create session".to_string(),
            }
        }
    };

    let token = match get_token(client, Some(&session_id)) {
        Some(t) => t,
        None => {
            return TestResult {
                name: "temporal-tampering",
                passed: false,
                message: "Could not get token".to_string(),
            }
        }
    };

    match validate_token(&token) {
        Ok(_) => {
            println!("  FAIL: Client accepted expired token!");
            TestResult {
                name: "temporal-tampering",
                passed: false,
                message: "Client accepted expired token".to_string(),
            }
        }
        Err(e) if e.to_lowercase().contains("expired") => {
            println!("  PASS: Client correctly rejected expired token");
            println!("  Error: {}", e);
            TestResult {
                name: "temporal-tampering",
                passed: true,
                message: e,
            }
        }
        Err(e) => {
            println!("  PASS: Client rejected token: {}", e);
            TestResult {
                name: "temporal-tampering",
                passed: true,
                message: e,
            }
        }
    }
}

fn test_valid_token(client: &Client) -> TestResult {
    println!("\nTest 4: Valid Token (No Mischief)");
    println!("{}", "-".repeat(40));

    // No session ID = no mischief
    let token = match get_token(client, None) {
        Some(t) => t,
        None => {
            return TestResult {
                name: "valid-token",
                passed: false,
                message: "Could not get token".to_string(),
            }
        }
    };

    match decode_header(&token) {
        Ok(header) => {
            let alg = format!("{:?}", header.alg);
            if alg == "RS256" || alg == "ES256" {
                println!("  PASS: Token uses proper algorithm: {}", alg);
                TestResult {
                    name: "valid-token",
                    passed: true,
                    message: format!("Algorithm: {}", alg),
                }
            } else {
                println!("  INFO: Token uses algorithm: {}", alg);
                TestResult {
                    name: "valid-token",
                    passed: true,
                    message: format!("Algorithm: {}", alg),
                }
            }
        }
        Err(e) => {
            println!("  FAIL: Could not parse token: {}", e);
            TestResult {
                name: "valid-token",
                passed: false,
                message: e.to_string(),
            }
        }
    }
}

fn main() {
    println!("{}", "=".repeat(50));
    println!("OIDC-Loki Rust Client Security Tests");
    println!("{}", "=".repeat(50));

    let client = Client::new();

    let results = vec![
        test_alg_none(&client),
        test_key_confusion(&client),
        test_temporal_tampering(&client),
        test_valid_token(&client),
    ];

    // Summary
    println!("\n{}", "=".repeat(50));
    println!("Summary");
    println!("{}", "=".repeat(50));

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    println!("Passed: {}/{}", passed, total);

    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("  [{}] {}: {}", status, result.name, result.message);
    }

    std::process::exit(if passed == total { 0 } else { 1 });
}
