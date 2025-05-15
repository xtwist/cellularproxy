use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{decode as b64decode, encode as b64encode};
use quick_xml::{events::Event, Reader};
use reqwest::header::{COOKIE};
use std::{error::Error, time::Duration};

// We'll use openssl instead of the problematic rsa crate
use crate::modem::Modem;
use openssl::{
    bn::BigNum,
    rsa::{Padding, Rsa},
};

pub struct HuaweiE337 {
    host: String,
    session_token: Option<String>,
    verification_token: Option<String>,
    timeout_secs: u64,
}

impl HuaweiE337 {
    /// Create a new instance with host and timeout
    pub fn new(host: String, timeout_secs: u64) -> Self {
        HuaweiE337 {
            host,
            session_token: None,
            verification_token: None,
            timeout_secs,
        }
    }

    /// Initialize the session by refreshing tokens - must be called before reconnect
    pub async fn init(&mut self) -> Result<()> {
        self.refresh_session_token().await
    }

    /// Refresh the session and verification tokens
    async fn refresh_session_token(&mut self) -> Result<()> {
        let url = format!("http://{}/api/webserver/SesTokInfo", self.host);

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .timeout(Duration::from_secs(self.timeout_secs))
            .send()
            .await?
            .text()
            .await?;

        self.session_token = Some(self.get_value_from_tag(&response, "SesInfo").await?);
        self.verification_token = Some(self.get_value_from_tag(&response, "TokInfo").await?);

        Ok(())
    }

    /// Parse XML to extract value from specified tag
    async fn get_value_from_tag(&self, xml: &str, tag: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);
        let mut txt = Vec::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event(&mut buf) {
                Ok(Event::Start(ref e)) if e.name() == tag.as_bytes() => {
                    txt.push(
                        reader
                            .read_text(tag.as_bytes(), &mut Vec::new())
                            .expect("Cannot decode text value"),
                    );
                    return Ok(txt[0].clone());
                }
                Ok(Event::Eof) => return Err(anyhow!("Expected tag {} not found", tag)),
                Err(e) => {
                    return Err(anyhow!(
                        "Error at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    ))
                }
                _ => (), // Ignore other events
            }
            buf.clear();
        }
    }

    /// Fetch public key and encrypt payload using OpenSSL
    async fn encrypt_with_public_key(&mut self, payload: &str) -> Result<String> {
        // 1) Fetch the modem's public key
        let url = format!("http://{}/api/webserver/publickey", self.host);

        let client = reqwest::Client::new();
        let resp = match (&self.session_token, &self.verification_token) {
            (Some(token), Some(verif_token)) => {
                client
                    .get(&url)
                    .header(COOKIE, format!("SessionId={}", token))
                    .header("__RequestVerificationToken", verif_token)
                    .timeout(Duration::from_secs(self.timeout_secs))
                    .send()
                    .await?
            }
            _ => return Err(anyhow!("Missing session or verification token")),
        };

        // Update verification token if present in response
        if let Some(new_token) = resp.headers().get("__requestverificationtoken") {
            self.verification_token = Some(new_token.to_str()?.to_owned());
        }

        let pubkey_xml = resp.text().await?;

        // 2) Parse XML to get modulus and exponent
        let modulus = self.get_value_from_tag(&pubkey_xml, "encpubkeyn").await?;
        let exponent = self.get_value_from_tag(&pubkey_xml, "encpubkeye").await?;

        // 3) Decode modulus and exponent
        let modulus_bytes = b64decode(&modulus).or_else(|_| {
            // Try hex if base64 fails
            hex::decode(&modulus)
        })?;

        let exponent_bytes = hex::decode(&exponent).or_else(|_| {
            // Try base64 if hex fails
            b64decode(&exponent)
        })?;

        // 4) Create RSA public key using OpenSSL
        let n = BigNum::from_slice(&modulus_bytes)?;
        let e = BigNum::from_slice(&exponent_bytes)?;

        let rsa = Rsa::from_public_components(n, e)?;

        // 5) Encrypt the payload with PKCS#1 padding
        let mut encrypted = vec![0; rsa.size() as usize];
        let enc_len = rsa.public_encrypt(payload.as_bytes(), &mut encrypted, Padding::PKCS1)?;

        encrypted.truncate(enc_len);

        // 6) Return base64-encoded ciphertext
        Ok(b64encode(&encrypted))
    }
}

#[async_trait]
impl Modem for HuaweiE337 {
    /// Reconnect the modem - main functionality
    async fn reboot(&mut self) -> Result<(), Box<dyn Error>> {
        // Ensure we have valid tokens
        if self.session_token.is_none() || self.verification_token.is_none() {
            return Err(Box::from(anyhow!(
                "Session not initialized, call init() first"
            )));
        }

        // Prepare reconnect XML payload
        let xml =
            r#"<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"#;

        // Send the reconnect request
        let url = format!("http://{}/api/device/control", self.host);
        let client = reqwest::Client::new();

        let resp = match (&self.session_token, &self.verification_token) {
            (Some(token), Some(verif_token)) => {
                client
                    .post(&url)
                    .header(COOKIE, format!("SessionId={}", token))
                    .header("__requestverificationtoken", verif_token)
                    .body(xml)
                    .timeout(Duration::from_secs(self.timeout_secs))
                    .send()
                    .await?
            }
            _ => return Err(Box::from(anyhow!("Missing session or verification token"))),
        };

        // Update verification token if present in response
        if let Some(new_token) = resp.headers().get("__requestverificationtoken") {
            self.verification_token = Some(new_token.to_str()?.to_owned());
        }

        let response_text = resp.text().await?;

        // Check if response contains "OK"
        if !response_text.contains("<response>OK</response>") {
            return Err(Box::from(anyhow!("Reconnect failed: {}", response_text)));
        }

        Ok(())
    }
}
