//! Настраиваемые списки маршрутизации (rules.json).
//!
//! Записи в списке — обычные строки, тип определяется автоматически:
//!   youtube.com          → домен и все его поддомены
//!   qbittorrent.exe      → программа по имени
//!   C:\Games\game.exe    → программа по полному пути
//!   /usr/bin/firefox     → программа по полному пути (Linux)
//!   process:firefox      → программа по имени (Linux, где у программ нет .exe)
//!   1.2.3.4 / 10.8.0.0/24 → IP или подсеть
//! Можно указать тип явно префиксом:
//!   full:example.com     → только этот домен, без поддоменов
//!   keyword:google       → домен содержит слово
//!   domain: ip: process: path:
//! Готовые наборы (см. geo.rs):
//!   geosite:youtube      → все домены сервиса
//!   geoip:telegram       → все IP-адреса сервиса, geoip:ru — страны

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Через VPN
    Proxy,
    /// Напрямую
    Direct,
    /// Заблокировать
    Block,
}

impl Action {
    fn outbound(self) -> Option<&'static str> {
        match self {
            Action::Proxy => Some("proxy"),
            Action::Direct => Some("direct"),
            Action::Block => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleList {
    pub name: String,
    /// Базовый список: нельзя удалить и сменить тип.
    #[serde(default, skip_serializing_if = "is_false")]
    pub builtin: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub entries: Vec<String>,
}

fn yes() -> bool {
    true
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rules {
    /// Куда идёт всё, что не попало ни в один список: "proxy" или "direct".
    #[serde(rename = "final", default = "default_final")]
    pub final_action: Action,
    #[serde(default)]
    pub lists: Vec<RuleList>,
    /// Включённые готовые наборы (см. geo.rs), например "ru-direct".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<String>,
}

fn default_final() -> Action {
    Action::Proxy
}

impl Default for Rules {
    fn default() -> Self {
        let mut r = Self { final_action: Action::Proxy, lists: Vec::new(), presets: Vec::new() };
        r.ensure_builtin();
        r
    }
}

impl Rules {
    /// Три базовых списка — «Напрямую», «Через VPN», «Блок» — есть всегда.
    /// Если в файле уже есть список с таким именем и типом, он становится базовым.
    pub fn ensure_builtin(&mut self) {
        const BASE: [(&str, Action); 3] =
            [("Напрямую", Action::Direct), ("Через VPN", Action::Proxy), ("Блок", Action::Block)];
        for (pos, (name, action)) in BASE.iter().enumerate() {
            let idx = self
                .lists
                .iter()
                .position(|l| l.builtin && l.action == *action)
                .or_else(|| self.lists.iter().position(|l| l.name == *name && l.action == *action));
            let list = match idx {
                Some(i) => {
                    let mut l = self.lists.remove(i);
                    l.builtin = true;
                    l
                }
                None => RuleList {
                    name: name.to_string(),
                    builtin: true,
                    enabled: true,
                    action: *action,
                    entries: Vec::new(),
                },
            };
            self.lists.insert(pos.min(self.lists.len()), list);
        }
    }

    /// Пример для `foxray rules init`.
    pub fn example() -> Self {
        Self {
            final_action: Action::Proxy,
            presets: Vec::new(),
            lists: vec![
                RuleList {
                    name: "Напрямую".into(),
                    builtin: true,
                    enabled: true,
                    action: Action::Direct,
                    entries: vec!["qbittorrent.exe".into(), "utorrent.exe".into()],
                },
                RuleList {
                    name: "Через VPN".into(),
                    builtin: true,
                    enabled: true,
                    action: Action::Proxy,
                    entries: vec!["youtube.com".into(), "googlevideo.com".into(), "Telegram.exe".into()],
                },
                RuleList {
                    name: "Блок".into(),
                    builtin: true,
                    enabled: false,
                    action: Action::Block,
                    entries: vec!["doubleclick.net".into()],
                },
            ],
        }
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let mut r: Self = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
        r.ensure_builtin();
        if r.migrate_presets() {
            let _ = r.save(path); // пересохраняем уже в новом виде
        }
        Ok(r)
    }

    /// Старые переключатели «Готовые наборы» → записи в базовых списках.
    /// Возвращает true, если что-то перенесли (файл стоит пересохранить).
    pub fn migrate_presets(&mut self) -> bool {
        if self.presets.is_empty() {
            return false;
        }
        for id in std::mem::take(&mut self.presets) {
            let (action, entries): (Action, &[&str]) = match id.as_str() {
                "ru-direct" => (Action::Direct, &["geosite:category-ru", "geoip:ru"]),
                "ads-block" => (Action::Block, &["geosite:category-ads-all"]),
                _ => continue,
            };
            if let Some(l) = self.lists.iter_mut().find(|l| l.builtin && l.action == action) {
                for e in entries {
                    if !l.entries.iter().any(|x| x.eq_ignore_ascii_case(e)) {
                        l.entries.push(e.to_string());
                    }
                }
            }
        }
        true
    }

    /// Теги всех наборов (geosite-…, geoip-…) из всех списков — что нужно скачать.
    pub fn set_tags(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in &self.lists {
            for e in &l.entries {
                if let Ok(Entry::Geosite(t) | Entry::Geoip(t)) = parse_entry(e) {
                    if !out.contains(&t) {
                        out.push(t);
                    }
                }
            }
        }
        out
    }
}

/// Разобранная запись.
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    DomainSuffix(String),
    Domain(String),
    Keyword(String),
    Cidr(String),
    Process(String),
    ProcessPath(String),
    /// Тег набора доменов: geosite-youtube
    Geosite(String),
    /// Тег набора адресов: geoip-telegram
    Geoip(String),
}

pub fn parse_entry(raw: &str) -> Result<Entry, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("пустая запись".into());
    }
    if let Some((prefix, value)) = s.split_once(':') {
        let v = value.trim().to_string();
        match prefix.to_ascii_lowercase().as_str() {
            "domain" => return Ok(Entry::DomainSuffix(v.to_ascii_lowercase())),
            "full" => return Ok(Entry::Domain(v.to_ascii_lowercase())),
            "keyword" => return Ok(Entry::Keyword(v.to_ascii_lowercase())),
            "ip" => return cidr(&v).map(Entry::Cidr),
            "process" => return Ok(Entry::Process(v)),
            "path" => return Ok(Entry::ProcessPath(v)),
            "geosite" | "geoip" => {
                let kind = prefix.to_ascii_lowercase();
                if !crate::geo::valid_name(&v) {
                    return Err(format!("«{s}» — после {kind}: нужно имя набора латиницей"));
                }
                let t = crate::geo::tag(&kind, &v);
                return Ok(if kind == "geosite" { Entry::Geosite(t) } else { Entry::Geoip(t) });
            }
            _ => {} // например, "C:\..." или IPv6 — разбираем ниже
        }
    }
    // Путь к программе: C:\... или \\server\...
    if s.contains('\\') {
        return Ok(Entry::ProcessPath(s.to_string()));
    }
    // Путь к программе в Linux: /usr/bin/firefox
    if s.starts_with('/') && !s.ends_with('/') {
        return Ok(Entry::ProcessPath(s.to_string()));
    }
    if s.to_ascii_lowercase().ends_with(".exe") {
        return Ok(Entry::Process(s.to_string()));
    }
    if let Ok(c) = cidr(s) {
        return Ok(Entry::Cidr(c));
    }
    let d = s.trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase();
    if d.contains('.') && d.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return Ok(Entry::DomainSuffix(d));
    }
    Err(format!("не понял запись «{s}»"))
}

fn cidr(s: &str) -> Result<String, String> {
    let (ip, mask) = match s.split_once('/') {
        Some((ip, m)) => (ip, Some(m)),
        None => (s, None),
    };
    let ip: IpAddr = ip.parse().map_err(|_| format!("«{s}» — не IP-адрес"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let mask: u8 = match mask {
        Some(m) => m.parse().ok().filter(|&m| m <= max).ok_or(format!("неверная маска в «{s}»"))?,
        None => max,
    };
    Ok(format!("{ip}/{mask}"))
}

/// Записи списка, сгруппированные по типам — то, что идёт в одно правило sing-box.
#[derive(Default)]
struct Grouped {
    domain_suffix: Vec<String>,
    domain: Vec<String>,
    keyword: Vec<String>,
    cidr: Vec<String>,
    process: Vec<String>,
    path: Vec<String>,
    /// Наборы: (тег, доменный ли)
    sets: Vec<(String, bool)>,
}

impl Grouped {
    fn from(list: &RuleList, errors: &mut Vec<String>) -> Self {
        let mut g = Grouped::default();
        for raw in &list.entries {
            match parse_entry(raw) {
                Ok(Entry::DomainSuffix(x)) => g.domain_suffix.push(x),
                Ok(Entry::Domain(x)) => g.domain.push(x),
                Ok(Entry::Keyword(x)) => g.keyword.push(x),
                Ok(Entry::Cidr(x)) => g.cidr.push(x),
                Ok(Entry::Process(x)) => g.process.push(x),
                Ok(Entry::ProcessPath(x)) => g.path.push(x),
                Ok(Entry::Geosite(t)) => g.sets.push((t, true)),
                Ok(Entry::Geoip(t)) => g.sets.push((t, false)),
                Err(e) => errors.push(format!("список «{}»: {e}", list.name)),
            }
        }
        g
    }

    fn has_domains(&self) -> bool {
        !(self.domain_suffix.is_empty() && self.domain.is_empty() && self.keyword.is_empty())
    }

    /// Отдельные правила на каждый тип (в одном правиле sing-box поля объединяются через И/ИЛИ
    /// по своим законам — так проще и предсказуемее).
    fn matchers(&self) -> Vec<Value> {
        let mut out = Vec::new();
        let mut push = |key: &str, v: &Vec<String>| {
            if !v.is_empty() {
                out.push(json!({ key: v }));
            }
        };
        push("domain_suffix", &self.domain_suffix);
        push("domain", &self.domain);
        push("domain_keyword", &self.keyword);
        push("ip_cidr", &self.cidr);
        push("process_name", &self.process);
        push("process_path", &self.path);
        out
    }

    fn domain_matchers(&self) -> Vec<Value> {
        let mut out = Vec::new();
        if !self.domain_suffix.is_empty() {
            out.push(json!({ "domain_suffix": self.domain_suffix }));
        }
        if !self.domain.is_empty() {
            out.push(json!({ "domain": self.domain }));
        }
        if !self.keyword.is_empty() {
            out.push(json!({ "domain_keyword": self.keyword }));
        }
        out
    }
}

/// Результат: правила для route.rules и dns.rules + список ошибок в записях.
pub struct Compiled {
    pub route: Vec<Value>,
    pub dns: Vec<Value>,
    pub errors: Vec<String>,
    /// Теги наборов, которые попали в правила (для route.rule_set).
    pub sets: Vec<String>,
}

/// Без проверки наборов: все считаются доступными.
pub fn compile(rules: &Rules) -> Compiled {
    compile_with(rules, |_| true)
}

/// available(тег) — скачан ли набор; нескачанные пропускаем с ошибкой
/// (ссылка на отсутствующий набор не даст sing-box запуститься).
pub fn compile_with(rules: &Rules, available: impl Fn(&str) -> bool) -> Compiled {
    let mut route = Vec::new();
    let mut dns = Vec::new();
    let mut errors = Vec::new();
    let mut sets_used: Vec<String> = Vec::new();
    // Правила наборов идут после всех обычных записей: конкретный домен в любом
    // списке важнее огромного набора (например, сайт .ru «через VPN» при «Российских сайтах напрямую»).
    let mut set_route = Vec::new();
    let mut set_dns = Vec::new();

    // Блок-списки — первыми, чтобы перебить всё остальное.
    let mut ordered: Vec<&RuleList> = rules.lists.iter().filter(|l| l.enabled).collect();
    ordered.sort_by_key(|l| l.action != Action::Block);

    for list in ordered {
        let g = Grouped::from(list, &mut errors);
        for m in g.matchers() {
            let mut r = m;
            match list.action.outbound() {
                Some(out) => r["outbound"] = json!(out),
                None => r["action"] = json!("reject"),
            }
            route.push(r);
        }
        // DNS: домены «напрямую» резолвим локально (CDN отдаст ближние сервера),
        // «через VPN» — удалённо, блок — отказ.
        if g.has_domains() {
            for m in g.domain_matchers() {
                let mut r = m;
                match list.action {
                    Action::Direct => r["server"] = json!("dns-local"),
                    Action::Proxy => r["server"] = json!("dns-remote"),
                    Action::Block => r["action"] = json!("predefined"),
                }
                if list.action == Action::Block {
                    r["rcode"] = json!("NXDOMAIN");
                }
                dns.push(r);
            }
        }
        // Наборы — одним правилом на список.
        let mut site_tags = Vec::new();
        let mut all_tags = Vec::new();
        for (t, is_site) in &g.sets {
            if !available(t) {
                errors.push(format!("список «{}»: набор {} ещё не скачан — пропущен", list.name, entry_name(t)));
                continue;
            }
            all_tags.push(t.clone());
            if *is_site {
                site_tags.push(t.clone());
            }
            if !sets_used.contains(t) {
                sets_used.push(t.clone());
            }
        }
        if !all_tags.is_empty() {
            let mut r = json!({ "rule_set": all_tags });
            match list.action.outbound() {
                Some(out) => r["outbound"] = json!(out),
                None => r["action"] = json!("reject"),
            }
            set_route.push(r);
        }
        if !site_tags.is_empty() {
            let mut d = json!({ "rule_set": site_tags });
            match list.action {
                Action::Direct => d["server"] = json!("dns-local"),
                Action::Proxy => d["server"] = json!("dns-remote"),
                Action::Block => {
                    d["action"] = json!("predefined");
                    d["rcode"] = json!("NXDOMAIN");
                }
            }
            set_dns.push(d);
        }
    }
    route.extend(set_route);
    dns.extend(set_dns);

    Compiled { route, dns, errors, sets: sets_used }
}

/// geosite-youtube → geosite:youtube
pub fn entry_name(tag: &str) -> String {
    tag.replacen('-', ":", 1)
}

/// Что означает запись — для подсказки в интерфейсе.
pub fn describe(raw: &str) -> Result<String, String> {
    Ok(match parse_entry(raw)? {
        Entry::DomainSuffix(_) => "домен + поддомены".into(),
        Entry::Domain(_) => "только домен".into(),
        Entry::Keyword(_) => "слово в домене".into(),
        Entry::Cidr(c) => format!("IP {c}"),
        Entry::Process(_) => "программа".into(),
        Entry::ProcessPath(_) => "программа (путь)".into(),
        Entry::Geosite(_) => "набор доменов".into(),
        Entry::Geoip(_) => "набор IP-адресов".into(),
    })
}

impl Rules {
    pub fn save(&self, path: &str) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))
    }
}
