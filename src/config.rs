//! Сборка config.json для sing-box (формат 1.12+): TUN + обход локальной сети.

use crate::link::{Hysteria2, Profile, Proto, Security, Transport, Vless};
use crate::rules::{self, Action, Rules};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Частные и служебные сети, которые по умолчанию не заходят в туннель.
pub const LAN_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16", // link-local (APIPA)
    "100.64.0.0/10",  // CGNAT / Tailscale
    "224.0.0.0/4",    // мультикаст (mDNS, SSDP, DLNA)
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// Домены, которые резолвятся системным (локальным) DNS.
pub const LOCAL_SUFFIXES: &[&str] = &["lan", "local", "home.arpa", "localdomain", "internal"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Не пускать локальную сеть в туннель.
    pub lan_bypass: bool,
    /// Дополнительные подсети в обход туннеля (например, рабочий VPN).
    pub extra_bypass: Vec<String>,
    /// DNS через VPN (DoH).
    pub remote_dns: String,
    /// Имя адаптера в Windows.
    pub tun_name: String,
    /// Стек TUN: "system", "gvisor" или "mixed".
    pub tun_stack: String,
    pub ipv6: bool,
    pub log_level: String,
    /// Порт Clash API для статистики в UI (0 — выключено).
    pub api_port: u16,
    /// Папка со скачанными наборами .srs (None — готовые наборы не подключаем).
    pub rule_set_dir: Option<std::path::PathBuf>,
    /// IP-адреса сервера, если в профиле домен (см. `resolve_server`). Они идут мимо туннеля —
    /// иначе пинг до сервера при подключении отвечает сам TUN (вечные 1 мс).
    #[serde(default)]
    pub server_ips: Vec<std::net::IpAddr>,
    /// Свой DNS-сервер ("192.168.1.10", "192.168.1.10:5353"). Домашний адрес — запросы идут
    /// к нему напрямую по локальной сети, внешний — через VPN. None — DoH на remote_dns.
    #[serde(default)]
    pub custom_dns: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lan_bypass: true,
            extra_bypass: Vec::new(),
            remote_dns: "1.1.1.1".into(),
            tun_name: "foxray".into(),
            tun_stack: "mixed".into(),
            ipv6: false,
            log_level: "warn".into(),
            api_port: 9090,
            rule_set_dir: None,
            server_ips: Vec::new(),
            custom_dns: None,
        }
    }
}

/// Конфиг + ошибки в записях списков (конфиг собирается и без ошибочных записей).
pub fn build(profile: &Profile, s: &Settings, user_rules: &Rules) -> (Value, Vec<String>) {
    // Наборы доступны, только если скачаны в rule_set_dir.
    let compiled = rules::compile_with(user_rules, |tag| {
        s.rule_set_dir.as_deref().map_or(false, |d| crate::geo::is_ready(d, tag))
    });
    let mut bypass: Vec<String> = Vec::new();
    if s.lan_bypass {
        bypass.extend(LAN_RANGES.iter().map(|x| x.to_string()));
    }
    bypass.extend(s.extra_bypass.iter().cloned());
    // Трафик до самого VPN-сервера вообще не заходит в туннель (если адрес — IP).
    if let Ok(ip) = profile.server.parse::<std::net::IpAddr>() {
        bypass.push(host_cidr(ip));
    }
    let server_cidrs: Vec<String> = s.server_ips.iter().map(|ip| host_cidr(*ip)).collect();
    bypass.extend(server_cidrs.iter().cloned());

    let mut tun_addr = vec!["172.19.0.1/30".to_string()];
    if s.ipv6 {
        tun_addr.push("fdfe:dcba:9876::1/126".into());
    }

    let mut tun = json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": s.tun_name,
        "address": tun_addr,
        "mtu": 9000,
        "auto_route": true,
        "strict_route": true,
        "stack": s.tun_stack,
    });
    if !bypass.is_empty() {
        tun["route_exclude_address"] = json!(bypass);
    }

    // --- маршрутизация ---
    let mut rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    if s.lan_bypass {
        rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    }
    if !s.extra_bypass.is_empty() {
        rules.push(json!({ "ip_cidr": s.extra_bypass, "outbound": "direct" }));
    }
    // Чтобы трафик до самого VPN-сервера не уходил в петлю — его адрес идёт напрямую
    // (auto_detect_interface тоже это обеспечивает, это страховка).
    rules.push(server_direct_rule(&profile.server));
    if !server_cidrs.is_empty() {
        rules.push(json!({ "ip_cidr": server_cidrs, "outbound": "direct" }));
    }
    // Пользовательские списки (наборы — внутри них).
    rules.extend(compiled.route);
    let mut errors = compiled.errors;
    let final_out = if user_rules.final_action == Action::Direct { "direct" } else { "proxy" };

    // --- DNS ---
    let custom = match s.custom_dns.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
        Some(raw) => match parse_dns(raw) {
            Ok(v) => Some(v),
            Err(e) => {
                errors.push(format!("DNS: {e} — использую 1.1.1.1"));
                None
            }
        },
        None => None,
    };
    let home_dns = custom.map_or(false, |(ip, _)| is_local_ip(ip));
    let remote_server = match custom {
        Some((ip, port)) => {
            let mut v = json!({ "type": "udp", "tag": "dns-remote", "server": ip.to_string(), "server_port": port });
            // Без detour sing-box ходит к DNS напрямую; "direct" явно он не принимает при запуске.
            if !home_dns {
                v["detour"] = json!("proxy");
            }
            v
        }
        None => json!({ "type": "https", "tag": "dns-remote", "server": s.remote_dns, "detour": "proxy" }),
    };

    let mut dns_rules = Vec::new();
    if s.lan_bypass {
        dns_rules.push(json!({ "domain_suffix": LOCAL_SUFFIXES, "server": "dns-local" }));
    }
    dns_rules.push(json!({ "domain": [profile.server], "server": "dns-local" }));
    dns_rules.extend(compiled.dns);
    // Домашний DNS (AdGuard Home, Pi-hole) знает свои домены и режет рекламу —
    // ему отдаём всё, кроме адреса самого VPN-сервера.
    if home_dns {
        let server_rule = usize::from(s.lan_bypass);
        for (i, r) in dns_rules.iter_mut().enumerate() {
            if i != server_rule && r["server"] == "dns-local" {
                r["server"] = json!("dns-remote");
            }
        }
    }
    let dns_final = if home_dns || final_out != "direct" { "dns-remote" } else { "dns-local" };

    let mut cfg = json!({
        "log": { "level": s.log_level, "timestamp": true },
        "dns": {
            "servers": [ remote_server, { "type": "local", "tag": "dns-local" } ],
            "rules": dns_rules,
            "final": dns_final,
            "strategy": if s.ipv6 { "prefer_ipv4" } else { "ipv4_only" },
        },
        "inbounds": [ tun ],
        "outbounds": [
            outbound(profile),
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "rules": rules,
            "final": final_out,
            "auto_detect_interface": true,
            // Имя программы у каждого соединения — для страницы «Соединения».
            "find_process": true,
            "default_domain_resolver": "dns-local"
        }
    });

    if let (Some(dir), false) = (s.rule_set_dir.as_deref(), compiled.sets.is_empty()) {
        let defs: Vec<Value> = compiled
            .sets
            .iter()
            .map(|t| {
                json!({
                    "tag": t,
                    "type": "local",
                    "format": "binary",
                    "path": crate::geo::set_path(dir, t).to_string_lossy(),
                })
            })
            .collect();
        cfg["route"]["rule_set"] = json!(defs);
    }

    if s.api_port != 0 {
        cfg["experimental"] = json!({
            "clash_api": { "external_controller": format!("127.0.0.1:{}", s.api_port) }
        });
    }
    (cfg, errors)
}

/// "192.168.1.10", "192.168.1.10:5353", "fd00::1", "[fd00::1]:53" → (IP, порт).
pub fn parse_dns(raw: &str) -> Result<(std::net::IpAddr, u16), String> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Ok((ip, 53));
    }
    if let Ok(sa) = raw.parse::<std::net::SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }
    Err(format!("«{raw}» — нужен IP-адрес, например 192.168.1.10"))
}

/// Адрес в домашней/локальной сети (включая CGNAT — Tailscale DNS 100.100.100.100).
pub fn is_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private() || v.is_link_local() || v.is_loopback() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

fn host_cidr(ip: std::net::IpAddr) -> String {
    if ip.is_ipv4() { format!("{ip}/32") } else { format!("{ip}/128") }
}

/// Адреса сервера через системный DNS (до запуска туннеля). Пусто, если в профиле уже IP
/// или DNS сейчас недоступен.
pub fn resolve_server(host: &str, port: u16) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let mut ips: Vec<std::net::IpAddr> = (host, port)
        .to_socket_addrs()
        .map(|a| a.map(|a| a.ip()).collect())
        .unwrap_or_default();
    ips.sort();
    ips.dedup();
    ips
}

fn server_direct_rule(server: &str) -> Value {
    if server.parse::<std::net::IpAddr>().is_ok() {
        let cidr = if server.contains(':') { format!("{server}/128") } else { format!("{server}/32") };
        json!({ "ip_cidr": [cidr], "outbound": "direct" })
    } else {
        json!({ "domain": [server], "outbound": "direct" })
    }
}

pub fn outbound(p: &Profile) -> Value {
    match &p.proto {
        Proto::Vless(v) => vless(p, v),
        Proto::Hysteria2(h) => hy2(p, h),
    }
}

fn vless(p: &Profile, v: &Vless) -> Value {
    let mut o = json!({
        "type": "vless",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "uuid": v.uuid,
        "packet_encoding": "xudp",
    });
    if let Some(flow) = &v.flow {
        o["flow"] = json!(flow);
    }

    match &v.security {
        Security::None => {}
        Security::Tls { sni, fingerprint, alpn, insecure } => {
            let mut tls = json!({ "enabled": true, "insecure": insecure });
            if let Some(sni) = sni {
                tls["server_name"] = json!(sni);
            }
            if !alpn.is_empty() {
                tls["alpn"] = json!(alpn);
            }
            if let Some(fp) = fingerprint {
                tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
            }
            o["tls"] = tls;
        }
        Security::Reality { sni, fingerprint, public_key, short_id } => {
            let mut reality = json!({ "enabled": true, "public_key": public_key });
            if let Some(sid) = short_id {
                reality["short_id"] = json!(sid);
            }
            let mut tls = json!({
                "enabled": true,
                "utls": { "enabled": true, "fingerprint": fingerprint },
                "reality": reality,
            });
            if let Some(sni) = sni {
                tls["server_name"] = json!(sni);
            }
            o["tls"] = tls;
        }
    }

    match &v.transport {
        Transport::Tcp => {}
        Transport::Grpc { service_name } => {
            o["transport"] = json!({ "type": "grpc", "service_name": service_name });
        }
        Transport::Ws { path, host } | Transport::HttpUpgrade { path, host } => {
            let kind = if matches!(v.transport, Transport::Ws { .. }) { "ws" } else { "httpupgrade" };
            let mut t = json!({ "type": kind, "path": path });
            if let Some(h) = host {
                if kind == "ws" {
                    t["headers"] = json!({ "Host": h });
                } else {
                    t["host"] = json!(h);
                }
            }
            o["transport"] = t;
        }
    }
    o
}

fn hy2(p: &Profile, h: &Hysteria2) -> Value {
    let mut tls = json!({ "enabled": true, "insecure": h.insecure, "alpn": ["h3"] });
    if let Some(sni) = &h.sni {
        tls["server_name"] = json!(sni);
    }
    let mut o = json!({
        "type": "hysteria2",
        "tag": "proxy",
        "server": p.server,
        "server_port": p.port,
        "password": h.password,
        "tls": tls,
    });
    if let Some(pw) = &h.obfs_password {
        o["obfs"] = json!({ "type": "salamander", "password": pw });
    }
    if !h.port_hopping.is_empty() {
        o["server_ports"] = json!(h.port_hopping);
        o["hop_interval"] = json!("30s");
    }
    if let Some(up) = h.up_mbps {
        o["up_mbps"] = json!(up);
    }
    if let Some(down) = h.down_mbps {
        o["down_mbps"] = json!(down);
    }
    o
}
