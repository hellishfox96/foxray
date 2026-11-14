//! Подписки: ссылка, по которой панель (3x-ui, Marzban, Remnawave…) отдаёт список серверов.

use crate::link::{parse_many, Profile};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subscription {
    pub name: String,
    pub url: String,
}

impl Subscription {
    pub fn from_url(url: &str) -> Self {
        let name = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "Подписка".into());
        Self { name, url: url.trim().to_string() }
    }
}

pub fn is_subscription_url(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    s.starts_with("https://") || s.starts_with("http://")
}

/// Скачать и разобрать подписку. Профили помечаются url подписки.
pub fn fetch(sub: &Subscription) -> Result<(Vec<Profile>, usize), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build();
    let body = agent
        .get(&sub.url)
        // Многие панели по User-Agent выбирают формат; с "v2rayN" отдают обычный список ссылок.
        .set("User-Agent", "foxray/0.3 (compatible; v2rayN/7.0)")
        .call()
        .map_err(|e| format!("не удалось скачать: {e}"))?
        .into_string()
        .map_err(|e| format!("не удалось прочитать ответ: {e}"))?;
    let text = decode_body(&body);
    let (mut list, errors) = parse_many(&text);
    if list.is_empty() {
        return Err(if errors.is_empty() {
            "в подписке нет серверов".into()
        } else {
            format!("ни одна ссылка не подошла (первая ошибка: {})", errors[0].1)
        });
    }
    for p in &mut list {
        p.sub = Some(sub.url.clone());
    }
    Ok((list, errors.len()))
}

/// Тело подписки — либо ссылки построчно, либо они же в base64.
pub fn decode_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for e in engines {
        if let Ok(bytes) = e.decode(&compact) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.contains("://") {
                    return s;
                }
            }
        }
    }
    trimmed.to_string()
}
