use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::{
    Client,
    header::{HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

use super::{
    model::{AiAnalysis, AiSettings},
    privacy::scan_outbound_payload,
};

const MAX_AI_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_FINDINGS: usize = 20;
const MAX_POLICY_SUGGESTIONS: usize = 20;
const MAX_TEXT_BYTES: usize = 4096;

const SYSTEM_PROMPT: &str = r#"You are reviewing a privacy-sanitized Router Hub security analytics summary. Return only a JSON object with keys: summary, findings, policy_suggestions. findings must be an array of objects with severity (info|warning|critical), category, title, evidence (array of short strings), recommendation, and confidence (0..1). Be conservative. Treat the data as aggregated telemetry, not proof of attacker identity or intent. Never request raw logs, real IP addresses, hostnames, usernames, credentials, tokens, or other identifying data. Recommendations are advisory only and must not assume they will be applied automatically."#;

#[derive(Debug)]
pub struct AiCallResult {
    pub analysis: AiAnalysis,
    pub request_bytes: usize,
    pub response_bytes: usize,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: Value,
}

pub fn request_json(settings: &AiSettings, payload: &Value) -> Result<Value> {
    let sanitized_payload = serde_json::to_string(payload)
        .context("failed to serialize privacy-sanitized AI payload")?;
    serde_json::to_value(ChatRequest {
        model: &settings.model,
        messages: vec![
            ChatMessage {
                role: "system",
                content: SYSTEM_PROMPT.to_owned(),
            },
            ChatMessage {
                role: "user",
                content: sanitized_payload,
            },
        ],
        max_tokens: settings.max_output_tokens,
        temperature: 0.1,
    })
    .context("failed to serialize OpenAI-compatible request")
}

pub fn validate_request_body(
    settings: &AiSettings,
    request: &Value,
    router_auth_token: &str,
) -> Result<Vec<u8>> {
    let request_bytes =
        serde_json::to_vec(request).context("failed to serialize OpenAI-compatible request")?;
    if request_bytes.len() > settings.max_payload_bytes || request_bytes.len() > 65_536 {
        bail!("AI request exceeds the configured privacy/performance limit");
    }
    scan_outbound_payload(
        &request_bytes,
        &[router_auth_token, settings.api_key.as_str()],
    )?;
    Ok(request_bytes)
}

pub async fn analyze(
    settings: &AiSettings,
    payload: &Value,
    router_auth_token: &str,
    test_mode: bool,
) -> Result<AiCallResult> {
    validate_ai_settings(settings, test_mode)?;
    let request = request_json(settings, payload)?;
    let request_bytes = validate_request_body(settings, &request, router_auth_token)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(settings.timeout_seconds))
        .redirect(Policy::none())
        .user_agent(concat!("router-hub/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build AI HTTP client")?;

    let mut builder = client
        .post(settings.endpoint.trim())
        .bearer_auth(settings.api_key.trim())
        .json(&request);
    for (name, value) in &settings.additional_headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid AI header name `{name}`"))?;
        let header_value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid AI header value for `{name}`"))?;
        builder = builder.header(header_name, header_value);
    }

    let response = builder
        .send()
        .await
        .context("AI endpoint request failed")?
        .error_for_status()
        .context("AI endpoint returned an error status")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AI_RESPONSE_BYTES as u64)
    {
        bail!("AI response exceeds the hard response-size limit");
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("failed while reading AI response")?;
        if body.len().saturating_add(chunk.len()) > MAX_AI_RESPONSE_BYTES {
            bail!("AI response exceeds the hard response-size limit");
        }
        body.extend_from_slice(&chunk);
    }

    let outer: ChatResponse = serde_json::from_slice(&body)
        .context("AI endpoint returned invalid chat-completions JSON")?;
    let content = outer
        .choices
        .into_iter()
        .next()
        .context("AI endpoint returned no choices")?
        .message
        .content;
    let analysis = match content {
        Value::String(text) => serde_json::from_str::<AiAnalysis>(&text)
            .context("AI response content was not the required JSON object")?,
        Value::Object(_) => serde_json::from_value::<AiAnalysis>(content)
            .context("AI response content was not the required JSON object")?,
        _ => bail!("AI response content had an unsupported shape"),
    };
    validate_analysis(&analysis)?;

    Ok(AiCallResult {
        analysis,
        request_bytes: request_bytes.len(),
        response_bytes: body.len(),
    })
}

pub fn validate_ai_settings(settings: &AiSettings, test_mode: bool) -> Result<()> {
    if settings.privacy_mode != "strict" {
        bail!("only strict AI privacy mode is supported");
    }
    if settings.max_payload_bytes == 0 || settings.max_payload_bytes > 65_536 {
        bail!("AI max_payload_bytes must be between 1 and 65536");
    }
    if settings.max_samples > 100 {
        bail!("AI max_samples must not exceed 100");
    }
    if settings.max_output_tokens == 0 || settings.max_output_tokens > 4096 {
        bail!("AI max_output_tokens must be between 1 and 4096");
    }
    if settings.timeout_seconds < 5 || settings.timeout_seconds > 60 {
        bail!("AI timeout_seconds must be between 5 and 60");
    }
    if settings.interval_hours < 24 {
        bail!("automatic AI interval must be at least 24 hours");
    }
    if settings.additional_headers.len() > 16 {
        bail!("AI additional_headers must contain at most 16 headers");
    }
    for (name, value) in &settings.additional_headers {
        if name.len() > 128 || value.len() > 2048 || value.contains(['\r', '\n']) {
            bail!("AI additional header is too large or contains a newline");
        }
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                | "host"
                | "content-type"
        ) || ["auth", "key", "token", "secret", "cookie"]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            bail!("AI additional_headers cannot contain or override sensitive transport headers");
        }
        HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid AI header name `{name}`"))?;
        HeaderValue::from_str(value)
            .with_context(|| format!("invalid AI header value for `{name}`"))?;
    }

    if !settings.enabled {
        return Ok(());
    }
    if settings.endpoint.trim().is_empty() {
        bail!("AI endpoint is required when AI analysis is enabled");
    }
    if settings.model.trim().is_empty() {
        bail!("AI model is required when AI analysis is enabled");
    }
    if settings.api_key.trim().is_empty() {
        bail!("AI API key is required when AI analysis is enabled");
    }

    let endpoint =
        Url::parse(settings.endpoint.trim()).context("AI endpoint is not a valid URL")?;
    match endpoint.scheme() {
        "https" => {}
        "http" if test_mode || endpoint_is_private(&endpoint) => {}
        _ => bail!("AI endpoint must use HTTPS unless it is a local/private test endpoint"),
    }
    if endpoint.username() != "" || endpoint.password().is_some() {
        bail!("AI endpoint URL must not embed credentials");
    }
    Ok(())
}

fn endpoint_is_private(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Some(Host::Ipv6(ip)) => {
            let addr = IpAddr::V6(ip);
            ip.is_loopback()
                || ip.is_unspecified()
                || matches!(addr, IpAddr::V6(value) if (value.segments()[0] & 0xfe00) == 0xfc00)
        }
        None => false,
    }
}

fn validate_analysis(analysis: &AiAnalysis) -> Result<()> {
    validate_text("AI summary", &analysis.summary)?;
    if analysis.findings.len() > MAX_FINDINGS {
        bail!("AI response contains too many findings");
    }
    if analysis.policy_suggestions.len() > MAX_POLICY_SUGGESTIONS {
        bail!("AI response contains too many policy suggestions");
    }
    for suggestion in &analysis.policy_suggestions {
        validate_text("AI policy suggestion", suggestion)?;
    }
    for finding in &analysis.findings {
        if !matches!(finding.severity.as_str(), "info" | "warning" | "critical") {
            bail!("AI finding has an invalid severity");
        }
        if !(0.0..=1.0).contains(&finding.confidence) || !finding.confidence.is_finite() {
            bail!("AI finding confidence must be between 0 and 1");
        }
        validate_text("AI finding category", &finding.category)?;
        validate_text("AI finding title", &finding.title)?;
        validate_text("AI finding recommendation", &finding.recommendation)?;
        if finding.evidence.len() > 20 {
            bail!("AI finding contains too many evidence entries");
        }
        for evidence in &finding.evidence {
            validate_text("AI finding evidence", evidence)?;
        }
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.len() > MAX_TEXT_BYTES {
        bail!("{field} exceeds the maximum length");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_http_endpoint_is_rejected() {
        let settings = AiSettings {
            enabled: true,
            endpoint: "http://203.0.113.10/v1/chat/completions".into(),
            api_key: "test-key".into(),
            model: "test".into(),
            ..AiSettings::default()
        };
        assert!(validate_ai_settings(&settings, false).is_err());
    }

    #[test]
    fn private_http_endpoint_is_allowed() {
        let settings = AiSettings {
            enabled: true,
            endpoint: "http://192.168.1.10/v1/chat/completions".into(),
            api_key: "test-key".into(),
            model: "test".into(),
            ..AiSettings::default()
        };
        assert!(validate_ai_settings(&settings, false).is_ok());
    }

    #[test]
    fn sensitive_custom_headers_are_rejected() {
        let mut settings = AiSettings::default();
        settings
            .additional_headers
            .insert("X-Api-Key".into(), "secret".into());
        assert!(validate_ai_settings(&settings, false).is_err());
    }

    #[test]
    fn final_request_body_is_size_and_secret_gated() {
        let settings = AiSettings {
            model: "test-model".into(),
            api_key: "provider-secret".into(),
            ..AiSettings::default()
        };
        let request = request_json(&settings, &serde_json::json!({"source":"SRC_1234"})).unwrap();
        assert!(validate_request_body(&settings, &request, "router-secret").is_ok());

        let leaked = request_json(
            &settings,
            &serde_json::json!({"unexpected":"router-secret"}),
        )
        .unwrap();
        assert!(validate_request_body(&settings, &leaked, "router-secret").is_err());

        let mut tiny = settings;
        tiny.max_payload_bytes = 32;
        assert!(validate_request_body(&tiny, &request, "router-secret").is_err());
    }
}
