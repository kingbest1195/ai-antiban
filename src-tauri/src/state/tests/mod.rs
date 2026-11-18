/// state.json exactly as written by v1.3.1 (no schema_version, single upstream_proxy).
const V131_STATE_JSON: &str = r#"{
  "pinned_ip": "185.10.10.1",
  "strict_pinning_enabled": false,
  "ip_history": {"anthropic": [{"ip":"185.10.10.1","country_code":"NL","asn":20473,"timestamp":1730745600}], "openai": [], "gemini": []},
  "session_allowed_providers": ["anthropic"],
  "blocked_providers": [],
  "upstream_proxy": {
"enabled": true,
"raw_key": "socks5://alice:s3cret@185.10.10.2:1080#NL Gate",
"protocol": "socks5",
"host": "185.10.10.2",
"port": 1080,
"username": "alice",
"password": "s3cret",
"label": "NL Gate"
  },
  "warmup_started_at": null,
  "synced_ai_timezone": "Europe/Amsterdam",
  "auto_update_enabled": true,
  "interception_behavior": "ask_popup",
  "popup_position": "top_right",
  "custom_ai_domains": []
}"#;

mod persistence;
mod routing_and_isolation;
