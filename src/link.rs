//! Разбор ссылок-профилей: vless:// (Reality / TLS) и hysteria2:// / hy2://.

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq)]
pub enum LinkError {
    #[error("не удалось разобрать ссылку: {0}")]
    BadUrl(String),
    #[error("неподдерживаемая схема: {0}")]
    UnsupportedScheme(String),
    #[error("в ссылке не хватает поля: {0}")]
    Missing(&'static str),
    #[error("неподдерживаемый транспорт «{0}» (sing-box его не умеет)")]
    UnsupportedTransport(String),
    #[error("неверное значение {0}: {1}")]
    Invalid(&'static str, String),
}

/// Один сервер из списка.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(flatten)]
    pub proto: Proto,
    /// Из какой подписки пришёл сервер (None — добавлен вручную).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum Proto {
    Vless(Vless),
    Hysteria2(Hysteria2),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vless {
    pub uuid: String,
    pub flow: Option<String>,
    pub security: Security,
    pub transport: Transport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Security {
    None,
    Tls {
        sni: Option<String>,
        fingerprint: Option<String>,
        alpn: Vec<String>,
        insecure: bool,
    },
    Reality {
        sni: Option<String>,
        fingerprint: String,
        public_key: String,
        short_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Grpc { service_name: String },
    Ws { path: String, host: Option<String> },
    HttpUpgrade { path: String, host: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2 {
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub obfs_password: Option<String>,
    /// Диапазоны портов для port hopping в формате sing-box: "20000:30000".
    pub port_hopping: Vec<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
}

/// Разобрать одну ссылку.
pub fn parse(link: &str) -> Result<Profile, LinkError> {
    let link = link.trim();
    let scheme = link.split("://").next().unwrap_or("").to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => parse_vless(link),
        "hysteria2" | "hy2" => parse_hy2(link),
        "" => Err(LinkError::BadUrl(link.into())),
        other => Err(LinkError::UnsupportedScheme(other.into())),
    }
}

/// Разобрать текст с несколькими ссылками (по одной на строку).
/// Возвращает успешные профили и ошибки с номерами строк.
pub fn parse_many(text: &str) -> (Vec<Profile>, Vec<(usize, LinkError)>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse(line) {
            Ok(p) => ok.push(p),
            Err(e) => errs.push((i + 1, e)),
        }
    }
    (ok, errs)
}

// ---------- общее ----------

struct Parts {
    userinfo: String,
    host: String,
    port: Option<u16>,
    query: HashMap<String, String>,
    name: Option<String>,
}

fn decode(s: &str) -> String {
    // В query '+' иногда означает пробел, но в ключах/паролях он легален — не трогаем.
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn split(link: &str) -> Result<Parts, LinkError> {
    // Заменяем схему на нейтральную, чтобы url не применял особых правил.
    let rest = link.split_once("://").map(|x| x.1).unwrap_or("");
    let u = Url::parse(&format!("foxray://{rest}")).map_err(|e| LinkError::BadUrl(e.to_string()))?;

    let mut userinfo = decode(u.username());
    if let Some(pw) = u.password() {
        userinfo.push(':');
        userinfo.push_str(&decode(pw));
    }
    let host = u
        .host_str()
        .ok_or(LinkError::Missing("адрес сервера"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let query = u
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();
    let name = u.fragment().map(decode).filter(|s| !s.is_empty());

    Ok(Parts { userinfo, host, port: u.port(), query, name })
}

fn q<'a>(p: &'a Parts, key: &str) -> Option<&'a str> {
    p.query.get(key).map(|s| s.as_str()).filter(|s| !s.is_empty())
}

fn q_bool(p: &Parts, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|k| q(p, k))
        .any(|v| matches!(v, "1" | "true" | "yes"))
}

fn default_name(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

// ---------- VLESS ----------

fn parse_vless(link: &str) -> Result<Profile, LinkError> {
    let p = split(link)?;
    if p.userinfo.is_empty() {
        return Err(LinkError::Missing("uuid"));
    }
    let port = p.port.ok_or(LinkError::Missing("порт"))?;

    let sni = q(&p, "sni").or(q(&p, "servername")).map(String::from);
    let fp = q(&p, "fp").map(String::from);

    let security = match q(&p, "security").unwrap_or("none") {
        "reality" => Security::Reality {
            sni,
            fingerprint: fp.unwrap_or_else(|| "chrome".into()),
            public_key: q(&p, "pbk").ok_or(LinkError::Missing("pbk (публичный ключ Reality)"))?.into(),
            short_id: q(&p, "sid").map(String::from),
        },
        "tls" => Security::Tls {
            sni,
            fingerprint: fp,
            alpn: q(&p, "alpn")
                .map(|a| a.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
            insecure: q_bool(&p, &["allowinsecure", "insecure"]),
        },
        "none" | "" => Security::None,
        other => return Err(LinkError::Invalid("security", other.into())),
    };

    let path = q(&p, "path").unwrap_or("/").to_string();
    let host = q(&p, "host").map(String::from);
    let transport = match q(&p, "type").unwrap_or("tcp") {
        "tcp" | "raw" => Transport::Tcp,
        "grpc" => Transport::Grpc {
            service_name: q(&p, "servicename").unwrap_or("").into(),
        },
        "ws" => Transport::Ws { path, host },
        "httpupgrade" => Transport::HttpUpgrade { path, host },
        other => return Err(LinkError::UnsupportedTransport(other.into())),
    };

    let flow = q(&p, "flow").map(String::from);

    Ok(Profile {
        name: p.name.clone().unwrap_or_else(|| default_name(&p.host, port)),
        server: p.host,
        port,
        proto: Proto::Vless(Vless { uuid: p.userinfo, flow, security, transport }),
        sub: None,
    })
}

// ---------- Hysteria2 ----------

fn parse_hy2(link: &str) -> Result<Profile, LinkError> {
    // Port hopping в ссылке бывает прямо в адресе: host:443,20000-30000 — url такое не съест.
    let (link, inline_ports) = extract_inline_ports(link);
    let p = split(&link)?;
    if p.userinfo.is_empty() {
        return Err(LinkError::Missing("пароль"));
    }
    let port = p.port.or(inline_ports.first_port).unwrap_or(443);

    let mut hopping: Vec<String> = inline_ports.ranges;
    if let Some(m) = q(&p, "mport") {
        hopping.extend(parse_port_ranges(m)?);
    }

    let obfs_password = match q(&p, "obfs") {
        None | Some("none") => None,
        Some("salamander") => Some(
            q(&p, "obfs-password")
                .ok_or(LinkError::Missing("obfs-password"))?
                .to_string(),
        ),
        Some(other) => return Err(LinkError::Invalid("obfs", other.into())),
    };

    let mbps = |k: &'static str| -> Result<Option<u32>, LinkError> {
        q(&p, k)
            .map(|v| {
                v.trim_end_matches(|c: char| c.is_alphabetic() || c == ' ')
                    .parse()
                    .map_err(|_| LinkError::Invalid(k, v.into()))
            })
            .transpose()
    };

    Ok(Profile {
        name: p.name.clone().unwrap_or_else(|| default_name(&p.host, port)),
        server: p.host.clone(),
        port,
        proto: Proto::Hysteria2(Hysteria2 {
            password: p.userinfo.clone(),
            sni: q(&p, "sni").map(String::from),
            insecure: q_bool(&p, &["insecure", "allowinsecure"]),
            obfs_password,
            port_hopping: hopping,
            up_mbps: mbps("upmbps")?,
            down_mbps: mbps("downmbps")?,
        }),
        sub: None,
    })
}

#[derive(Default)]
struct InlinePorts {
    first_port: Option<u16>,
    ranges: Vec<String>,
}

/// "hy2://pw@host:443,20000-30000/?..." → ("hy2://pw@host:443/?...", ranges)
fn extract_inline_ports(link: &str) -> (String, InlinePorts) {
    let Some((scheme, rest)) = link.split_once("://") else {
        return (link.to_string(), InlinePorts::default());
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (user, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    // Порт — после последнего ':' вне квадратных скобок IPv6.
    let colon = hostport.rfind(':').filter(|&i| !hostport[i..].contains(']'));
    let Some(ci) = colon else {
        return (link.to_string(), InlinePorts::default());
    };
    let ports = &hostport[ci + 1..];
    if !ports.contains([',', '-']) {
        return (link.to_string(), InlinePorts::default());
    }
    let mut out = InlinePorts::default();
    if let Ok(ranges) = parse_port_ranges(ports) {
        out.first_port = ports
            .split(',')
            .next()
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.trim().parse().ok());
        out.ranges = ranges;
    }
    let host = &hostport[..ci];
    let port = out.first_port.map(|p| format!(":{p}")).unwrap_or_default();
    let user = user.map(|u| format!("{u}@")).unwrap_or_default();
    (format!("{scheme}://{user}{host}{port}{tail}"), out)
}

/// "443,20000-30000" → ["443:443", "20000:30000"]
fn parse_port_ranges(s: &str) -> Result<Vec<String>, LinkError> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|part| {
            let (a, b) = part.split_once('-').unwrap_or((part, part));
            let a: u16 = a.trim().parse().map_err(|_| LinkError::Invalid("mport", s.into()))?;
            let b: u16 = b.trim().parse().map_err(|_| LinkError::Invalid("mport", s.into()))?;
            if a > b {
                return Err(LinkError::Invalid("mport", s.into()));
            }
            Ok(format!("{a}:{b}"))
        })
        .collect()
}

// ---------- Обратно в ссылку (для «Копировать ссылку») ----------

fn enc(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
    const KEEP: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    utf8_percent_encode(s, KEEP).to_string()
}

fn host_for_url(h: &str) -> String {
    if h.contains(':') {
        format!("[{h}]")
    } else {
        h.to_string()
    }
}

impl Profile {
    pub fn to_link(&self) -> String {
        let mut q: Vec<(String, String)> = Vec::new();
        let mut add = |k: &str, v: &str| q.push((k.to_string(), v.to_string()));
        let (scheme, user) = match &self.proto {
            Proto::Vless(v) => {
                add("encryption", "none");
                if let Some(f) = &v.flow {
                    add("flow", f);
                }
                match &v.security {
                    Security::None => add("security", "none"),
                    Security::Tls { sni, fingerprint, alpn, insecure } => {
                        add("security", "tls");
                        if let Some(s) = sni {
                            add("sni", s);
                        }
                        if let Some(fp) = fingerprint {
                            add("fp", fp);
                        }
                        if !alpn.is_empty() {
                            add("alpn", &alpn.join(","));
                        }
                        if *insecure {
                            add("allowInsecure", "1");
                        }
                    }
                    Security::Reality { sni, fingerprint, public_key, short_id } => {
                        add("security", "reality");
                        if let Some(s) = sni {
                            add("sni", s);
                        }
                        add("fp", fingerprint);
                        add("pbk", public_key);
                        if let Some(sid) = short_id {
                            add("sid", sid);
                        }
                    }
                }
                match &v.transport {
                    Transport::Tcp => add("type", "tcp"),
                    Transport::Grpc { service_name } => {
                        add("type", "grpc");
                        add("serviceName", service_name);
                    }
                    Transport::Ws { path, host } | Transport::HttpUpgrade { path, host } => {
                        add("type", if matches!(v.transport, Transport::Ws { .. }) { "ws" } else { "httpupgrade" });
                        add("path", path);
                        if let Some(h) = host {
                            add("host", h);
                        }
                    }
                }
                ("vless", enc(&v.uuid))
            }
            Proto::Hysteria2(h) => {
                if let Some(s) = &h.sni {
                    add("sni", s);
                }
                if h.insecure {
                    add("insecure", "1");
                }
                if let Some(pw) = &h.obfs_password {
                    add("obfs", "salamander");
                    add("obfs-password", pw);
                }
                if !h.port_hopping.is_empty() {
                    let m: Vec<String> = h
                        .port_hopping
                        .iter()
                        .map(|r| match r.split_once(':') {
                            Some((a, b)) if a == b => a.to_string(),
                            Some((a, b)) => format!("{a}-{b}"),
                            None => r.clone(),
                        })
                        .collect();
                    add("mport", &m.join(","));
                }
                if let Some(u) = h.up_mbps {
                    add("upmbps", &u.to_string());
                }
                if let Some(d) = h.down_mbps {
                    add("downmbps", &d.to_string());
                }
                ("hysteria2", enc(&h.password))
            }
        };
        let query: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect();
        format!(
            "{scheme}://{user}@{}:{}{}?{}#{}",
            host_for_url(&self.server),
            self.port,
            if scheme == "hysteria2" { "/" } else { "" },
            query.join("&"),
            enc(&self.name)
        )
    }
}
