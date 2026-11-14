//! Подписки: ссылка, по которой панель (3x-ui, Marzban, Remnawave…) отдаёт список серверов.

use crate::link::{parse_many, Profile};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subscription {
    pub name: String,
    pub url: String,
    /// Когда последний раз обновилась (секунды Unix, 0 — ещё ни разу).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated: u64,
    /// До какого числа действует (секунды Unix) — если панель сообщает.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<u64>,
}

fn is_zero(x: &u64) -> bool {
    *x == 0
}

/// Что ещё сообщила панель вместе с серверами (заголовки ответа).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meta {
    /// Название подписки (profile-title), например «ASB Studio».
    pub title: Option<String>,
    /// Срок действия (subscription-userinfo: expire=…).
    pub expire: Option<u64>,
}

/// Результат обновления подписки: серверы, сколько ссылок пропущено, сведения панели.
pub type Fetched = (Vec<Profile>, usize, Meta);

impl Subscription {
    pub fn from_url(url: &str) -> Self {
        let name = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| "Подписка".into());
        Self { name, url: url.trim().to_string(), updated: 0, expire: None }
    }
}

pub fn is_subscription_url(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    s.starts_with("https://") || s.starts_with("http://")
}

/// Как представляемся панели. Панели (Remnawave, Marzban…) по User-Agent выбирают формат,
/// а незнакомым программам отдают заглушку («Приложение не поддерживается!», адрес 0.0.0.0).
/// Пробуем по очереди, пока не придут настоящие серверы.
const AGENTS: [&str; 4] = ["v2rayN/7.13.8", "Happ/2.7.0", "v2rayNG/1.10.16", "Streisand/1.6.40"];

/// Сервер-заглушка: адрес 0.0.0.0 / 127.0.0.1 / пустой.
fn is_stub(p: &Profile) -> bool {
    let h = p.server.trim();
    h.is_empty() || h == "0.0.0.0" || h == "127.0.0.1" || h == "::" || h == "localhost"
}

/// Устройство — для панелей с ограничением числа устройств (HWID, как в Remnawave/Happ).
/// Без этих заголовков такие панели отдают заглушку вместо серверов.
#[derive(Debug, Clone, Default)]
pub struct Device {
    /// Постоянный номер этого компьютера (хранится в настройках).
    pub hwid: String,
}

impl Device {
    fn os() -> &'static str {
        match std::env::consts::OS {
            "windows" => "Windows",
            "linux" => "Linux",
            "macos" => "macOS",
            o => o,
        }
    }

    fn os_version() -> String {
        #[cfg(target_os = "linux")]
        if let Ok(t) = std::fs::read_to_string("/etc/os-release") {
            for l in t.lines() {
                if let Some(v) = l.strip_prefix("VERSION_ID=") {
                    return v.trim_matches('"').to_string();
                }
            }
        }
        if cfg!(windows) { "10".into() } else { String::new() }
    }

    fn model() -> String {
        let name = std::env::var("COMPUTERNAME")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .unwrap_or_default();
        let name = name.trim();
        if name.is_empty() { "PC".into() } else { name.to_string() }
    }
}

/// Новый номер устройства: 16 случайных шестнадцатеричных знаков.
pub fn new_hwid() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    while out.len() < 16 {
        // RandomState каждый раз берёт новые случайные ключи от системы.
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        out += &format!("{:016x}", h.finish());
    }
    out.truncate(16);
    out
}

/// Скачать и разобрать подписку. Профили помечаются url подписки.
pub fn fetch(sub: &Subscription, dev: &Device) -> Result<Fetched, String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build();
    let mut last: Option<Result<Fetched, String>> = None;
    for ua in AGENTS {
        let res = fetch_as(&agent, sub, ua, dev);
        match &res {
            // Хотя бы один настоящий сервер — берём (заглушки выбрасываем).
            Ok((list, _, _)) if list.iter().any(|p| !is_stub(p)) => {
                let (list, errors, meta) = res.unwrap();
                return Ok((list.into_iter().filter(|p| !is_stub(p)).collect(), errors, meta));
            }
            // Нет связи — другой User-Agent не поможет (а отказ панели по коду ответа — может).
            Err(e) if e.starts_with("не удалось скачать") && !e.contains("status code") => return res,
            _ => {}
        }
        if last.is_none() {
            last = Some(res);
        }
    }
    match last.unwrap() {
        Ok((list, _, _)) if list.iter().all(is_stub) => Err(format!(
            "панель не отдала серверы — вместо них заглушка «{}». Возможно, подписка привязана к устройствам (HWID) или к определённому приложению",
            list.first().map(|p| p.name.trim().to_string()).unwrap_or_default()
        )),
        other => other,
    }
}

fn fetch_as(agent: &ureq::Agent, sub: &Subscription, ua: &str, dev: &Device) -> Result<Fetched, String> {
    let mut req = agent.get(&sub.url).set("User-Agent", ua).set("Accept", "*/*");
    if !dev.hwid.is_empty() {
        req = req
            .set("x-hwid", &dev.hwid)
            .set("x-device-os", Device::os())
            .set("x-ver-os", &Device::os_version())
            .set("x-device-model", &Device::model());
    }
    let resp = req.call().map_err(|e| format!("не удалось скачать: {e}"))?;
    let meta = Meta {
        title: resp.header("profile-title").and_then(profile_title),
        expire: resp.header("subscription-userinfo").and_then(userinfo_expire),
    };
    let body = resp
        .into_string()
        .map_err(|e| format!("не удалось прочитать ответ: {e}"))?;
    // Remnawave и др. часто отдают не ссылки, а готовые конфиги Xray (JSON) — берём из них серверы.
    let t = body.trim_start();
    let text = if t.starts_with('[') || t.starts_with('{') {
        xray_json_links(t).ok_or("в подписке конфиг Xray (JSON), но серверов VLESS в нём нет")?
    } else {
        decode_body(&body)
    };
    let (mut list, errors) = parse_many(&text);
    if list.is_empty() {
        return Err(if errors.is_empty() {
            "в подписке нет серверов".into()
        } else {
            // Коротко: в ошибке может оказаться кусок подписки (ключи) — в журнал его целиком не пишем.
            let e = errors[0].1.to_string();
            let short: String = e.chars().take(80).collect();
            format!("ни одна ссылка не подошла (первая ошибка: {short}{})", if e.chars().count() > 80 { "…" } else { "" })
        });
    }
    for p in &mut list {
        p.sub = Some(sub.url.clone());
    }
    Ok((list, errors.len(), meta))
}

/// profile-title: «ASB Studio» или «base64:QVNCIFN0dWRpbw==».
fn profile_title(h: &str) -> Option<String> {
    let h = h.trim();
    let t = match h.strip_prefix("base64:") {
        Some(b) => String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b.trim()).ok()?).ok()?,
        None => h.to_string(),
    };
    let t = t.trim().to_string();
    (!t.is_empty() && t.chars().count() <= 40).then_some(t)
}

/// subscription-userinfo: «upload=0; download=123; total=0; expire=1765238400» → expire.
fn userinfo_expire(h: &str) -> Option<u64> {
    h.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("expire"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .filter(|&t: &u64| t > 0)
}

/// Дата из секунд Unix: «09.12» (или «09.12.2027», если не в этом году).
pub fn short_date(unix: u64, now: u64) -> String {
    let civil = |t: u64| {
        // Алгоритм Говарда Хиннанта: дни от 1970-01-01 → год, месяц, день (UTC + 3 ч — для России сойдёт).
        let z = ((t + 3 * 3600) / 86400) as i64 + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        (y, m, d)
    };
    let (y, m, d) = civil(unix);
    let (ny, _, _) = civil(now);
    if y == ny { format!("{d:02}.{m:02}") } else { format!("{d:02}.{m:02}.{y}") }
}

/// Поле JSON без учёта регистра (в конфигах встречаются и streamSettings, и streamsettings).
fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    static NULL: serde_json::Value = serde_json::Value::Null;
    match v.as_object() {
        Some(o) => o.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v).unwrap_or(&NULL),
        None => &NULL,
    }
}

fn text(v: &serde_json::Value, key: &str) -> Option<String> {
    match field(v, key) {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Конфиги Xray (один объект или массив) → ссылки vless:// построчно.
/// Имя сервера — remarks конфига; запасные серверы того же конфига (балансировщик) — «имя · 2» и т. д.
pub fn xray_json_links(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let configs: Vec<&serde_json::Value> = match &v {
        serde_json::Value::Array(a) => a.iter().collect(),
        o => vec![o],
    };
    let mut lines: Vec<String> = Vec::new();
    for (ci, cfg) in configs.iter().enumerate() {
        let remarks = text(cfg, "remarks").unwrap_or_else(|| format!("Сервер {}", ci + 1));
        let mut n = 0;
        for ob in field(cfg, "outbounds").as_array().into_iter().flatten() {
            if !text(ob, "protocol").is_some_and(|p| p.eq_ignore_ascii_case("vless")) {
                continue;
            }
            let Some(link) = vless_link(ob) else { continue };
            n += 1;
            let name = if n == 1 { remarks.clone() } else { format!("{remarks} · {n}") };
            let line = format!("{link}#{}", url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>().replace('+', "%20"));
            if !lines.iter().any(|l| l.split('#').next() == line.split('#').next()) {
                lines.push(line);
            }
        }
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// Outbound VLESS из конфига Xray → ссылка vless:// (без имени).
fn vless_link(ob: &serde_json::Value) -> Option<String> {
    let settings = field(ob, "settings");
    let vnext = field(settings, "vnext").as_array()?.first()?;
    let addr = text(vnext, "address")?;
    let port = text(vnext, "port")?;
    let user = field(vnext, "users").as_array()?.first()?;
    let id = text(user, "id")?;
    let ss = field(ob, "streamSettings");
    let network = text(ss, "network").unwrap_or_else(|| "tcp".into());
    let security = text(ss, "security").unwrap_or_else(|| "none".into());
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    q.append_pair("encryption", "none");
    q.append_pair("type", &network);
    q.append_pair("security", &security);
    if let Some(f) = text(user, "flow") {
        q.append_pair("flow", &f);
    }
    match security.as_str() {
        "reality" => {
            let r = field(ss, "realitySettings");
            for (from, to) in [("serverName", "sni"), ("publicKey", "pbk"), ("shortId", "sid"), ("fingerprint", "fp"), ("spiderX", "spx")] {
                if let Some(x) = text(r, from) {
                    q.append_pair(to, &x);
                }
            }
        }
        "tls" => {
            let t = field(ss, "tlsSettings");
            for (from, to) in [("serverName", "sni"), ("fingerprint", "fp")] {
                if let Some(x) = text(t, from) {
                    q.append_pair(to, &x);
                }
            }
            if let Some(a) = field(t, "alpn").as_array() {
                let a: Vec<&str> = a.iter().filter_map(|x| x.as_str()).collect();
                if !a.is_empty() {
                    q.append_pair("alpn", &a.join(","));
                }
            }
            if field(t, "allowInsecure").as_bool() == Some(true) {
                q.append_pair("allowInsecure", "1");
            }
        }
        _ => {}
    }
    match network.as_str() {
        "ws" | "httpupgrade" => {
            let w = field(ss, if network == "ws" { "wsSettings" } else { "httpupgradeSettings" });
            if let Some(p) = text(w, "path") {
                q.append_pair("path", &p);
            }
            let host = text(w, "host").or_else(|| text(field(w, "headers"), "Host"));
            if let Some(h) = host {
                q.append_pair("host", &h);
            }
        }
        "grpc" => {
            if let Some(s) = text(field(ss, "grpcSettings"), "serviceName") {
                q.append_pair("serviceName", &s);
            }
        }
        _ => {}
    }
    let host = if addr.contains(':') { format!("[{addr}]") } else { addr };
    Some(format!("vless://{id}@{host}:{port}?{}", q.finish()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_json_subscription() {
        let body = r#"[{"remarks":"🇳🇱 Нидерланды","outbounds":[
            {"tag":"cand","protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,
              "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},
             "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example.com",
              "publicKey":"pubkeyAAA","shortId":"abcd","fingerprint":"edge"}}},
            {"tag":"cand-2","protocol":"vless","settings":{"vnext":[{"address":"5.6.7.8","port":443,
              "users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
             "streamsettings":{"network":"ws","security":"tls","tlssettings":{"servername":"b.example.com"},
              "wssettings":{"path":"/ws","headers":{"Host":"b.example.com"}}}},
            {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}]"#;
        let text = xray_json_links(body).unwrap();
        let (list, errs) = parse_many(&text);
        assert!(errs.is_empty(), "{errs:?}\n{text}");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "🇳🇱 Нидерланды");
        assert_eq!(list[0].server, "1.2.3.4");
        assert_eq!(list[1].name, "🇳🇱 Нидерланды · 2");
        assert_eq!(list[1].server, "5.6.7.8");
        match &list[0].proto {
            crate::link::Proto::Vless(v) => {
                assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
                assert!(matches!(&v.security, crate::link::Security::Reality { public_key, .. } if public_key == "pubkeyAAA"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn stub_detected() {
        let (list, _) = parse_many("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#x");
        assert!(list.iter().all(is_stub));
    }

    #[test]
    fn panel_headers() {
        assert_eq!(profile_title("base64:QVNCIFN0dWRpbw==").as_deref(), Some("ASB Studio"));
        assert_eq!(profile_title("My VPN").as_deref(), Some("My VPN"));
        assert_eq!(userinfo_expire("upload=0; download=861; total=0; expire=1765238400"), Some(1765238400));
        assert_eq!(userinfo_expire("upload=0; total=0"), None);
        // 2025-12-09 00:00 UTC
        assert_eq!(short_date(1765238400, 1765238400), "09.12");
        assert_eq!(short_date(1765238400, 1700000000), "09.12.2025");
    }
}
