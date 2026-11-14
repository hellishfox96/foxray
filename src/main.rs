//! Этап 1: консольная утилита. Позже сюда придёт окно на Slint.
//!
//!   foxray parse "<ссылка>"                       — показать, что распозналось
//!   foxray gen "<ссылка>" [-o config.json] [опции] — собрать конфиг sing-box
//!   foxray gen -f links.txt -n 2 ...              — взять 2-ю ссылку из файла
//!
//! Опции gen:
//!   --no-lan-bypass       пускать локальную сеть в туннель
//!   --bypass <CIDR>       ещё одна подсеть напрямую (можно несколько раз)
//!   --dns <адрес>         DNS через VPN (по умолчанию 1.1.1.1)
//!   --dns-server <IP>     свой DNS (домашний — напрямую, внешний — через VPN)
//!   --ipv6                включить IPv6 в туннеле
//!   --rules <файл>        списки маршрутизации (по умолчанию rules.json, если он есть)
//!   --verbose             подробный лог sing-box
//!
//!   foxray rules init     создать пример rules.json
//!   foxray rules check    показать, как распознались записи в rules.json

use foxray::rules::{parse_entry, Entry};
use foxray::{build_config, parse, parse_many, Profile, Rules, Settings};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        print_help();
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "parse" => {
            for p in profiles(rest)? {
                println!("{}", serde_json::to_string_pretty(&p).unwrap());
            }
            Ok(())
        }
        "gen" => gen(rest),
        "rules" => rules_cmd(rest),
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("неизвестная команда «{other}»")),
    }
}

/// Ссылка из аргумента или из файла (-f), с выбором по номеру (-n).
fn profiles(args: &[String]) -> Result<Vec<Profile>, String> {
    if let Some(i) = args.iter().position(|a| a == "-f") {
        let path = args.get(i + 1).ok_or("после -f нужен путь к файлу")?;
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let (list, errs) = parse_many(&text);
        for (line, e) in errs {
            eprintln!("строка {line}: {e}");
        }
        if let Some(n) = flag_value(args, "-n") {
            let n: usize = n.parse().map_err(|_| "после -n нужен номер")?;
            let p = list.get(n.wrapping_sub(1)).ok_or(format!("в файле нет профиля №{n}"))?;
            return Ok(vec![p.clone()]);
        }
        return Ok(list);
    }
    let link = args.iter().find(|a| a.contains("://")).ok_or("не передана ссылка")?;
    Ok(vec![parse(link).map_err(|e| e.to_string())?])
}

fn gen(args: &[String]) -> Result<(), String> {
    let list = profiles(args)?;
    let profile = match list.as_slice() {
        [p] => p,
        [] => return Err("не найдено ни одного профиля".into()),
        _ => return Err("в файле несколько профилей — выбери один через -n <номер>".into()),
    };

    let mut s = Settings::default();
    if args.iter().any(|a| a == "--no-lan-bypass") {
        s.lan_bypass = false;
    }
    if args.iter().any(|a| a == "--ipv6") {
        s.ipv6 = true;
    }
    if args.iter().any(|a| a == "--verbose") {
        s.log_level = "info".into();
    }
    if let Some(dns) = flag_value(args, "--dns-server") {
        s.custom_dns = Some(dns.into());
    }
    if let Some(dns) = flag_value(args, "--dns") {
        s.remote_dns = dns.into();
    }
    s.extra_bypass = args
        .windows(2)
        .filter(|w| w[0] == "--bypass")
        .map(|w| w[1].clone())
        .collect();

    // Скачанные наборы (geosite:/geoip:) — из папки программы, как у Foxray с окном.
    s.rule_set_dir = Some(foxray::store::app_dir().join("rulesets"));
    s.server_ips = foxray::config::resolve_server(&profile.server, profile.port);
    let rules = load_rules(args)?;
    let (cfg, errors) = build_config(profile, &s, &rules);
    for e in &errors {
        eprintln!("Пропущено: {e}");
    }
    let cfg = serde_json::to_string_pretty(&cfg).unwrap();
    match flag_value(args, "-o") {
        Some(path) => {
            std::fs::write(path, cfg).map_err(|e| format!("{path}: {e}"))?;
            eprintln!("Готово: «{}» → {path}", profile.name);
        }
        None => println!("{cfg}"),
    }
    Ok(())
}

fn load_rules(args: &[String]) -> Result<Rules, String> {
    match flag_value(args, "--rules") {
        Some(path) => Rules::load(path),
        None if std::path::Path::new("rules.json").exists() => {
            eprintln!("Списки: rules.json");
            Rules::load("rules.json")
        }
        None => Ok(Rules::default()),
    }
}

fn rules_cmd(args: &[String]) -> Result<(), String> {
    let path = flag_value(args, "--rules").unwrap_or("rules.json");
    match args.first().map(|s| s.as_str()) {
        Some("init") => {
            if std::path::Path::new(path).exists() {
                return Err(format!("{path} уже есть — не перезаписываю"));
            }
            let text = serde_json::to_string_pretty(&Rules::example()).unwrap();
            std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))?;
            println!("Создан {path} — открой в блокноте и поправь списки.");
            Ok(())
        }
        Some("check") => {
            let rules = Rules::load(path)?;
            let fin = if rules.final_action == foxray::rules::Action::Direct { "напрямую" } else { "через VPN" };
            println!("Всё остальное: {fin}\n");
            for l in &rules.lists {
                let state = if l.enabled { "" } else { "  (выключен)" };
                println!("[{}] → {:?}{state}", l.name, l.action);
                for raw in &l.entries {
                    let kind = match parse_entry(raw) {
                        Ok(Entry::DomainSuffix(_)) => "домен + поддомены".to_string(),
                        Ok(Entry::Domain(_)) => "только этот домен".into(),
                        Ok(Entry::Keyword(_)) => "слово в домене".into(),
                        Ok(Entry::Cidr(c)) => format!("IP/подсеть {c}"),
                        Ok(Entry::Process(_)) => "программа".into(),
                        Ok(Entry::ProcessPath(_)) => "программа по пути".into(),
                        Ok(Entry::Geosite(_)) => "набор доменов".into(),
                        Ok(Entry::Geoip(_)) => "набор IP-адресов".into(),
                        Err(e) => format!("ОШИБКА: {e}"),
                    };
                    println!("    {raw:<30} {kind}");
                }
            }
            Ok(())
        }
        _ => Err("используй: foxray rules init | foxray rules check".into()),
    }
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

fn print_help() {
    println!(
        "foxray — свой клиент поверх sing-box\n\n\
         foxray parse \"<ссылка>\"\n\
         foxray parse -f links.txt\n\
         foxray gen \"<ссылка>\" [-o config.json] [--no-lan-bypass] [--bypass CIDR]... [--dns IP] [--dns-server IP] [--ipv6]\n\
         foxray gen -f links.txt -n 1 -o config.json\n\n\
         foxray rules init | foxray rules check\n\n\
         Запуск: sing-box run -c config.json (из консоли администратора — нужен для TUN)"
    );
}
