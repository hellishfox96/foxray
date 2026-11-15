use foxray::rules::{compile, parse_entry, Action, Entry, RuleList, Rules};

#[test]
fn entry_detection() {
    assert_eq!(parse_entry("YouTube.com").unwrap(), Entry::DomainSuffix("youtube.com".into()));
    assert_eq!(parse_entry("*.ru.example").unwrap(), Entry::DomainSuffix("ru.example".into()));
    assert_eq!(parse_entry("full:a.b.c").unwrap(), Entry::Domain("a.b.c".into()));
    assert_eq!(parse_entry("keyword:google").unwrap(), Entry::Keyword("google".into()));
    assert_eq!(parse_entry("qBittorrent.exe").unwrap(), Entry::Process("qBittorrent.exe".into()));
    assert_eq!(
        parse_entry(r"C:\Games\Steam\steam.exe").unwrap(),
        Entry::ProcessPath(r"C:\Games\Steam\steam.exe".into())
    );
    assert_eq!(parse_entry("1.2.3.4").unwrap(), Entry::Cidr("1.2.3.4/32".into()));
    assert_eq!(parse_entry("10.8.0.0/24").unwrap(), Entry::Cidr("10.8.0.0/24".into()));
    assert_eq!(parse_entry("2001:db8::/32").unwrap(), Entry::Cidr("2001:db8::/32".into()));
    assert!(parse_entry("10.0.0.0/40").is_err());
    assert!(parse_entry("просто текст").is_err());
}

#[test]
fn compile_order_and_errors() {
    let rules = Rules {
        final_action: Action::Proxy,
        presets: vec![],
        lists: vec![
            RuleList { name: "D".into(), builtin: false, enabled: true, action: Action::Direct,
                       entries: vec!["qbittorrent.exe".into(), "vk.com".into(), "мусор".into()] },
            RuleList { name: "Off".into(), builtin: false, enabled: false, action: Action::Proxy, entries: vec!["x.com".into()] },
            RuleList { name: "B".into(), builtin: false, enabled: true, action: Action::Block, entries: vec!["ads.example".into()] },
        ],
    };
    let c = compile(&rules);
    // Блок первым
    assert_eq!(c.route[0]["action"], "reject");
    assert_eq!(c.route.len(), 3);
    assert!(c.route.iter().any(|r| r["process_name"][0] == "qbittorrent.exe" && r["outbound"] == "direct"));
    assert_eq!(c.errors.len(), 1);
    assert!(c.dns.iter().any(|r| r["domain_suffix"][0] == "vk.com" && r["server"] == "dns-local"));
}

#[test]
fn builtin_lists_always_present() {
    let mut r: Rules = serde_json::from_str(r#"{"lists":[{"name":"Мой","action":"direct","entries":["a.com"]},
        {"name":"Напрямую","action":"direct","entries":["b.com"]}]}"#).unwrap();
    r.ensure_builtin();
    let names: Vec<_> = r.lists.iter().map(|l| (l.name.as_str(), l.builtin)).collect();
    assert_eq!(names, vec![("Напрямую", true), ("Через zapret", true), ("Через VPN", true), ("Блок", true), ("Мой", false)]);
    assert_eq!(r.lists[0].entries, vec!["b.com"]); // существующий список стал базовым, записи на месте
    r.ensure_builtin();
    assert_eq!(r.lists.len(), 5); // повторный вызов ничего не дублирует
}

#[test]
fn sets_as_entries() {
    assert_eq!(parse_entry("geosite:YouTube").unwrap(), Entry::Geosite("geosite-youtube".into()));
    assert_eq!(parse_entry("geoip:telegram").unwrap(), Entry::Geoip("geoip-telegram".into()));
    assert!(parse_entry("geosite:ютуб").is_err());

    let rules = Rules {
        final_action: Action::Proxy,
        presets: vec![],
        lists: vec![
            RuleList { name: "D".into(), builtin: true, enabled: true, action: Action::Direct,
                       entries: vec!["geosite:category-ru".into(), "geoip:ru".into()] },
            RuleList { name: "V".into(), builtin: true, enabled: true, action: Action::Proxy,
                       entries: vec!["kinopoisk.ru".into(), "geosite:youtube".into()] },
        ],
    };
    // youtube не скачан
    let c = foxray::rules::compile_with(&rules, |t| t != "geosite-youtube");
    assert_eq!(c.sets, vec!["geosite-category-ru", "geoip-ru"]);
    assert_eq!(c.errors.len(), 1, "{:?}", c.errors);
    // свой домен «через VPN» стоит раньше набора «напрямую»
    let pos_domain = c.route.iter().position(|r| r["domain_suffix"][0] == "kinopoisk.ru").unwrap();
    let pos_set = c.route.iter().position(|r| r.get("rule_set").is_some()).unwrap();
    assert!(pos_domain < pos_set);
    assert_eq!(c.route[pos_set]["outbound"], "direct");
    // DNS по наборам — только доменные
    let d = c.dns.iter().find(|r| r.get("rule_set").is_some()).unwrap();
    assert_eq!(d["rule_set"], serde_json::json!(["geosite-category-ru"]));
}

#[test]
fn old_presets_migrate_into_lists() {
    let mut r: Rules = serde_json::from_str(r#"{"lists":[],"presets":["ru-direct","ads-block"]}"#).unwrap();
    r.ensure_builtin();
    assert!(r.migrate_presets());
    assert!(r.presets.is_empty());
    assert_eq!(r.lists[0].entries, vec!["geosite:category-ru", "geoip:ru"]);
    assert_eq!(r.lists[3].entries, vec!["geosite:category-ads-all"]);
    assert_eq!(r.set_tags(), vec!["geosite-category-ru", "geoip-ru", "geosite-category-ads-all"]);
}

#[test]
fn linux_programs() {
    assert_eq!(parse_entry("/usr/bin/firefox").unwrap(), Entry::ProcessPath("/usr/bin/firefox".into()));
    assert_eq!(parse_entry("process:python3.12").unwrap(), Entry::Process("python3.12".into()));
    // подсеть — не путь
    assert_eq!(parse_entry("10.0.0.0/8").unwrap(), Entry::Cidr("10.0.0.0/8".into()));
}

#[test]
fn zapret_list_not_in_config() {
    // «Через zapret» в конфиг не попадает сам — его добавляет окно, когда zapret включён.
    let mut r: Rules = serde_json::from_str(r#"{"lists":[{"name":"Через zapret","action":"zapret","entries":["rutracker.org"]}]}"#).unwrap();
    r.ensure_builtin();
    assert_eq!(r.lists[1].action, Action::Zapret);
    assert!(r.lists[1].builtin);
    let c = foxray::rules::compile(&r);
    assert!(c.route.is_empty(), "{:?}", c.route);
    assert!(c.dns.is_empty());
}

#[test]
fn port_entry() {
    assert_eq!(parse_entry("port:19960").unwrap(), Entry::Port(19960));
    assert!(parse_entry("port:abc").is_err());
}
