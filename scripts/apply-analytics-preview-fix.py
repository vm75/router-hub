#!/usr/bin/env python3
from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    file = Path(path)
    text = file.read_text()
    actual = text.count(old)
    if actual != count:
        raise SystemExit(
            f"{path}: expected {count} occurrence(s), found {actual}: {old[:100]!r}"
        )
    file.write_text(text.replace(old, new, count))


replace(
    "src/analytics/mod.rs",
    """        let payload = self.build_ai_payload(&settings).await?;
        let bytes = serde_json::to_vec(&payload)?;
        if bytes.len() > settings.ai.max_payload_bytes || bytes.len() > 65_536 {
            bail!("AI payload exceeds the configured privacy/performance limit");
        }
        scan_outbound_payload(
            &bytes,
            &[
                self.config.server.auth_token.as_str(),
                settings.ai.api_key.as_str(),
            ],
        )?;
        Ok(AiPreview {
            privacy_mode: settings.ai.privacy_mode,
            bytes: bytes.len(),
            payload,
        })""",
    """        let payload = self.build_ai_payload(&settings).await?;
        let request = ai::request_json(&settings.ai, &payload)?;
        let bytes = ai::validate_request_body(
            &settings.ai,
            &request,
            &self.config.server.auth_token,
        )?;
        Ok(AiPreview {
            privacy_mode: settings.ai.privacy_mode,
            bytes: bytes.len(),
            payload: request,
        })""",
)

replace(
    "src/analytics/mod.rs",
    """fn counter_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        0
    }
}""",
    """fn counter_delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}""",
)

replace(
    "src/analytics/mod.rs",
    """        assert_eq!(counter_delta(100, 90), 10);
        assert_eq!(counter_delta(3, 100), 0);""",
    """        assert_eq!(counter_delta(100, 90), 10);
        assert_eq!(counter_delta(3, 100), 0);""",
)
