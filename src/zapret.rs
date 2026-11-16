//! Zapret (сборка Flowseal/zapret-discord-youtube) — Discord (и голос) и YouTube без VPN.
//!
//! Foxray не переписывает zapret, а использует его готовую папку как есть:
//!   zapret/bin/winws.exe, WinDivert, *.bin   — сама программа обхода DPI
//!   zapret/lists/*.txt                       — списки доменов
//!   zapret/general*.bat                      — стратегии (наборы параметров winws)
//! Из .bat берём строку запуска winws.exe, подставляем пути и запускаем winws сами —
//! скрыто, вместе с Foxray и с исключением адреса VPN-сервера.
//! Работает только в Windows (winws/WinDivert), Foxray должен быть запущен от администратора.

use std::io::Read;
#[cfg(not(target_os = "linux"))]
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(not(target_os = "linux"))]
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

/// Папка zapret рядом с Foxray.
pub const FOLDER: &str = "zapret";
/// Наш файл исключений (адрес VPN-сервера) — пользовательские файлы zapret не трогаем.
pub const EXCLUDE_FILE: &str = "ipset-exclude-foxray.txt";
/// Свой список Foxray «Через zapret»: домены и IP-адреса. Подключается к стратегии рядом
/// с list-general-user.txt и ipset-all.txt — файлы сборки не трогаем.
pub const USER_HOSTLIST: &str = "list-foxray.txt";
pub const USER_IPSET: &str = "ipset-foxray.txt";
const REPO_RAW: &str = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main";
const REPO_DL: &str = "https://github.com/Flowseal/zapret-discord-youtube/releases/download";

/// Windows — winws.exe из сборки; Linux — nfqws (см. nfq.rs).
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

pub fn dir(app_dir: &Path) -> PathBuf {
    app_dir.join(FOLDER)
}

/// Папка похожа на zapret: есть программа обхода и хотя бы одна стратегия.
pub fn installed(dir: &Path) -> bool {
    let engine = if cfg!(windows) { dir.join("bin").join("winws.exe") } else { dir.join("nfqws") };
    engine.exists() && !strategies(dir).is_empty()
}

/// Linux: версия nfqws («v72.13»).
pub fn engine_version(dir: &Path) -> Option<String> {
    if cfg!(windows) {
        return None;
    }
    std::fs::read_to_string(dir.join("nfqws.version")).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Версия сборки: в архиве релиза она записана в service.bat (set "LOCAL_VERSION=1.10.4"),
/// в git-копии ещё и в .service/version.txt.
pub fn version(dir: &Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(dir.join("service.bat")) {
        for l in text.lines().take(20) {
            if let Some(rest) = l.split("LOCAL_VERSION=").nth(1) {
                let v = rest.trim().trim_end_matches('"').trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    let v = std::fs::read_to_string(dir.join(".service").join("version.txt")).ok()?;
    let v = v.trim().to_string();
    (!v.is_empty()).then_some(v)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Strategy {
    /// Имя файла без .bat: «general (ALT3)» — так стратегия хранится в настройках.
    pub id: String,
    /// Короткое имя для списка: «ALT3», «Основная».
    pub title: String,
    pub file: PathBuf,
}

/// Короткое имя: «general» → «Основная», «general (ALT3)» → «ALT3».
pub fn title_of(id: &str) -> String {
    let inner = id.strip_prefix("general").unwrap_or(id).trim();
    let inner = inner.trim_start_matches('(').trim_end_matches(')').trim();
    if inner.is_empty() {
        "Основная".into()
    } else {
        inner.to_string()
    }
}

/// Порядок как у людей: Основная, ALT, ALT2 … ALT13, потом остальные по алфавиту.
fn sort_key(id: &str) -> (u8, String, u32) {
    let t = title_of(id);
    if t == "Основная" {
        return (0, String::new(), 0);
    }
    let digits: String = t.chars().rev().take_while(|c| c.is_ascii_digit()).collect::<Vec<_>>().into_iter().rev().collect();
    let base = t[..t.len() - digits.len()].trim().to_string();
    let n = digits.parse().unwrap_or(0);
    (if base == "ALT" { 1 } else { 2 }, base, n)
}

pub fn strategies(dir: &Path) -> Vec<Strategy> {
    let mut out: Vec<Strategy> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    let lower = name.to_ascii_lowercase();
                    (lower.starts_with("general") && lower.ends_with(".bat")).then(|| {
                        let id = name[..name.len() - 4].to_string();
                        Strategy { title: title_of(&id), id, file: e.path() }
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|s| sort_key(&s.id));
    out
}

/// Файлы *-user.txt — их создаёт service.bat при первом запуске; без них winws не стартует.
pub fn ensure_user_lists(dir: &Path) {
    let lists = dir.join("lists");
    let files = [
        ("ipset-exclude-user.txt", "203.0.113.113/32\n"),
        ("list-general-user.txt", "# Never leave this file empty\ndomain.example.abc\n"),
        ("list-exclude-user.txt", "domain.example.abc\n"),
    ];
    for (name, text) in files {
        let p = lists.join(name);
        if !p.exists() {
            let _ = std::fs::write(p, text);
        }
    }
}

/// Записать файл исключений: адреса VPN-сервера и локальная сеть (zapret там не нужен,
/// а игровые порты без исключения задели бы игры по локалке, NAS и т. п.).
pub fn write_exclude(dir: &Path, ips: &[IpAddr]) -> PathBuf {
    let p = dir.join("lists").join(EXCLUDE_FILE);
    let mut text: String = ips
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v) => format!("{v}/32\n"),
            IpAddr::V6(v) => format!("{v}/128\n"),
        })
        .collect();
    for r in crate::config::LAN_RANGES {
        text += r;
        text.push('\n');
    }
    let _ = std::fs::write(&p, text);
    p
}

/// Свои файлы Foxray для стратегии: исключения (адрес VPN-сервера) и список «Через zapret».
#[derive(Default, Clone, Copy)]
pub struct Extra<'a> {
    /// Добавляется в каждый профиль (между --new) как --ipset-exclude.
    pub exclude: Option<&'a Path>,
    /// Добавляется к каждому --hostlist=…list-general-user.txt.
    pub hostlist: Option<&'a Path>,
    /// Добавляется к каждому --ipset=…ipset-all.txt.
    pub ipset: Option<&'a Path>,
    /// Игровые порты (Game Filter сборки): 1024–65535 TCP/UDP, на любые адреса (см. `split_games`).
    pub games: bool,
}

/// Порты Game Filter — как в service.bat сборки Flowseal.
pub const GAME_PORTS: &str = "1024-65535";

/// Аргументы winws из .bat-стратегии со своими файлами Foxray (см. Extra).
pub fn parse_bat(text: &str, dir: &Path, extra: Extra) -> Result<Vec<String>, String> {
    // Склеиваем строки, разорванные «^» в конце.
    let mut joined = String::new();
    for line in text.lines() {
        let l = line.trim_end();
        if let Some(head) = l.strip_suffix('^') {
            joined.push_str(head);
            joined.push(' ');
        } else {
            joined.push_str(l);
            joined.push('\n');
        }
    }
    let line = joined
        .lines()
        .find(|l| l.to_ascii_lowercase().contains("winws.exe\""))
        .ok_or("в стратегии нет строки запуска winws.exe")?;
    let pos = line.to_ascii_lowercase().find("winws.exe\"").unwrap() + "winws.exe\"".len();
    let sep = std::path::MAIN_SEPARATOR;
    let bin = format!("{}{sep}", dir.join("bin").display());
    let lists = format!("{}{sep}", dir.join("lists").display());
    let root = format!("{}{sep}", dir.display());
    let mut rest = line[pos..].to_string();
    // Game Filter выключен (как по умолчанию в service.bat): порт-заглушка 12.
    let game = if extra.games { GAME_PORTS } else { "12" };
    for (k, v) in [
        ("%BIN%", bin.as_str()),
        ("%LISTS%", lists.as_str()),
        ("%~dp0", root.as_str()),
        ("%GameFilterTCP%", game),
        ("%GameFilterUDP%", game),
        ("%GameFilter%", game),
    ] {
        rest = rest.replace(k, v);
    }
    if let Some(i) = rest.find('%') {
        let tail: String = rest[i..].chars().take(30).collect();
        return Err(format!("неизвестная переменная в стратегии: {tail}"));
    }
    let mut args = split_args(&rest);
    if args.is_empty() {
        return Err("пустая строка запуска winws".into());
    }
    if extra.games {
        args = split_games(args);
    }
    // Свой список — следом за пользовательским списком сборки: те же профили, те же настройки.
    // ipset-all.txt может быть пустым (режим «any» — все адреса), тогда свой ipset не добавляем:
    // он бы сузил профиль до наших адресов.
    let ipset_all_any = ipset_empty(&dir.join("lists").join("ipset-all.txt"));
    if extra.hostlist.is_some() || extra.ipset.is_some() {
        let mut out = Vec::with_capacity(args.len() + 8);
        for a in args.drain(..) {
            let host = a.starts_with("--hostlist=") && a.ends_with("list-general-user.txt");
            let ip = a.starts_with("--ipset=") && a.ends_with("ipset-all.txt");
            out.push(a);
            match (host, ip, extra.hostlist, extra.ipset) {
                (true, _, Some(h), _) => out.push(format!("--hostlist={}", h.display())),
                (_, true, _, Some(i)) if !ipset_all_any => out.push(format!("--ipset={}", i.display())),
                _ => {}
            }
        }
        args = out;
    }
    if let Some(ex) = extra.exclude {
        let opt = format!("--ipset-exclude={}", ex.display());
        let mut out = Vec::with_capacity(args.len() + 16);
        for a in args.drain(..) {
            if a == "--new" {
                out.push(opt.clone());
            }
            out.push(a);
        }
        out.push(opt);
        args = out;
    }
    Ok(args)
}

/// Игровые порты — на любые адреса. В стратегиях сборки игровые порты стоят в профилях с
/// --ipset=ipset-all.txt, а серверов игр в этом списке обычно нет (поэтому игры «не работают»).
/// Профиль `--filter-udp=443,1024-65535 --ipset=…ipset-all.txt …` делится на два:
/// `--filter-udp=443 --ipset=…ipset-all.txt …` (как был) и `--filter-udp=1024-65535 …` без ipset.
/// Что идёт в zapret, решает маршрутизация Foxray (игры из списка — напрямую), адрес VPN-сервера
/// и локальная сеть исключены (--ipset-exclude).
fn split_games(args: Vec<String>) -> Vec<String> {
    let is_all = |a: &str| a.starts_with("--ipset=") && a.ends_with("ipset-all.txt");
    let mut profiles: Vec<Vec<String>> = vec![Vec::new()];
    for a in args {
        if a == "--new" {
            profiles.push(Vec::new());
        } else {
            profiles.last_mut().unwrap().push(a);
        }
    }
    let mut out_profiles: Vec<Vec<String>> = Vec::new();
    for p in profiles {
        let game_filter = p.iter().position(|a| {
            (a.starts_with("--filter-tcp=") || a.starts_with("--filter-udp="))
                && a.split_once('=').unwrap().1.split(',').any(|x| x == GAME_PORTS)
        });
        let (Some(fi), true) = (game_filter, p.iter().any(|a| is_all(a))) else {
            out_profiles.push(p);
            continue;
        };
        let (key, ports) = p[fi].split_once('=').unwrap();
        let rest: Vec<&str> = ports.split(',').filter(|x| *x != GAME_PORTS).collect();
        let game: Vec<String> = p
            .iter()
            .enumerate()
            .filter(|(i, a)| *i == fi || !is_all(a))
            .map(|(i, a)| if i == fi { format!("{key}={GAME_PORTS}") } else { a.clone() })
            .collect();
        if !rest.is_empty() {
            let mut old = p.clone();
            old[fi] = format!("{key}={}", rest.join(","));
            out_profiles.push(old);
        }
        out_profiles.push(game);
    }
    let mut out = Vec::new();
    for (i, p) in out_profiles.into_iter().enumerate() {
        if i > 0 {
            out.push("--new".to_string());
        }
        out.extend(p);
    }
    out
}

/// Пустой ipset (нет ни одного адреса) — zapret считает, что подходят все адреса.
fn ipset_empty(p: &Path) -> bool {
    match std::fs::read_to_string(p) {
        Ok(t) => !t.lines().any(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#')
        }),
        Err(_) => false, // нет файла — профиль и так не запустится, не наше дело
    }
}

/// Разбор как в cmd: пробелы делят, кавычки склеивают и убираются,
/// «^» вне кавычек экранирует следующий символ (`--dpi-desync-fake-tls=^!` → `=!`).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' if !quoted => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    any = true;
                }
            }
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Домены из списков zapret — их Foxray пускает «напрямую», чтобы ими занимался zapret.
/// «^домен» в zapret — без поддоменов → full:домен.
pub fn domains(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for f in ["list-general.txt", "list-google.txt", "list-general-user.txt"] {
        let Ok(text) = std::fs::read_to_string(dir.join("lists").join(f)) else { continue };
        for l in text.lines() {
            let l = l.trim().trim_start_matches('\u{feff}');
            if l.is_empty() || l.starts_with('#') || l == "domain.example.abc" {
                continue;
            }
            let entry = match l.strip_prefix('^') {
                Some(d) => format!("full:{d}"),
                None => l.to_string(),
            };
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- список «Через zapret»

/// Что из списка «Через zapret» пошло в файлы zapret.
#[derive(Debug, Default, PartialEq)]
pub struct UserLists {
    /// Для --hostlist: «домен» (с поддоменами) или «^домен» (только он).
    pub hosts: Vec<String>,
    /// Для --ipset: адреса и подсети.
    pub ips: Vec<String>,
}

/// Записи списка → домены и адреса для zapret. Наборы (geosite:/geoip:) раскрываются
/// из скачанных файлов .srs (sing-box rule-set decompile, результат кешируется рядом).
/// Программы и «keyword:» zapret не понимает — их пропускаем.
pub fn user_lists(entries: &[String], sets_dir: &Path, singbox: Option<&Path>) -> UserLists {
    use crate::rules::{parse_entry, Entry};
    let mut out = UserLists::default();
    fn push(v: &mut Vec<String>, x: String) {
        if !x.is_empty() && !v.contains(&x) {
            v.push(x);
        }
    }
    for e in entries {
        match parse_entry(e) {
            Ok(Entry::DomainSuffix(d)) => push(&mut out.hosts, d),
            Ok(Entry::Domain(d)) => push(&mut out.hosts, format!("^{d}")),
            Ok(Entry::Cidr(c)) => push(&mut out.ips, c),
            Ok(Entry::Geosite(t) | Entry::Geoip(t)) => {
                let Some(sb) = singbox else { continue };
                if let Ok(set) = set_contents(&crate::geo::set_path(sets_dir, &t), sb) {
                    for d in set.hosts {
                        push(&mut out.hosts, d);
                    }
                    for c in set.ips {
                        push(&mut out.ips, c);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Содержимое набора .srs: домены и адреса (слова и регулярные выражения zapret не понимает).
pub fn set_contents(srs: &Path, singbox: &Path) -> Result<UserLists, String> {
    let json = srs.with_extension("json");
    let fresh = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    if fresh(&json).is_none() || fresh(&json) < fresh(srs) {
        let mut cmd = Command::new(singbox);
        cmd.arg("rule-set").arg("decompile").arg("--output").arg(&json).arg(srs);
        crate::sys::hide_window(&mut cmd);
        let out = cmd.output().map_err(|e| format!("sing-box: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }
    let text = std::fs::read_to_string(&json).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut out = UserLists::default();
    // В JSON sing-box поле — строка или массив строк.
    let strings = |x: &serde_json::Value| -> Vec<String> {
        match x {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(a) => a.iter().filter_map(|s| s.as_str().map(String::from)).collect(),
            _ => Vec::new(),
        }
    };
    for r in v["rules"].as_array().into_iter().flatten() {
        for d in strings(&r["domain_suffix"]) {
            out.hosts.push(d.trim_start_matches('.').to_ascii_lowercase());
        }
        for d in strings(&r["domain"]) {
            out.hosts.push(format!("^{}", d.to_ascii_lowercase()));
        }
        out.ips.extend(strings(&r["ip_cidr"]));
    }
    Ok(out)
}

/// Записать свои файлы zapret. Пустой список winws не любит — тогда заглушка
/// (как в файлах сборки), которая ни с чем не совпадёт.
pub fn write_user_lists(dir: &Path, lists: &UserLists) -> (PathBuf, PathBuf) {
    let host = dir.join("lists").join(USER_HOSTLIST);
    let ip = dir.join("lists").join(USER_IPSET);
    let text = |v: &[String], stub: &str| if v.is_empty() { format!("{stub}\n") } else { v.join("\n") + "\n" };
    let _ = std::fs::write(&host, text(&lists.hosts, "domain.example.abc"));
    let _ = std::fs::write(&ip, text(&lists.ips, "203.0.113.113/32"));
    (host, ip)
}

// ---------------------------------------------------------------- запуск winws

#[cfg(not(target_os = "linux"))]
pub struct Winws {
    child: Child,
}

#[cfg(not(target_os = "linux"))]
impl Winws {
    /// Запустить winws.exe со стратегией. on_log — строки его вывода (ошибки и т. п.).
    pub fn start(dir: &Path, args: &[String], on_log: impl Fn(String) + Send + Sync + 'static) -> Result<Self, String> {
        let bin = dir.join("bin");
        let exe = bin.join("winws.exe");
        if !exe.exists() {
            return Err(format!("нет {}", exe.display()));
        }
        tcp_timestamps();
        let mut cmd = Command::new(&exe);
        cmd.args(args).current_dir(&bin).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        crate::sys::hide_window(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| format!("winws не запустился: {e}"))?;
        // winws умрёт вместе с Foxray, даже при падении.
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            crate::winjob::bind(child.as_raw_handle() as _);
        }
        let on_log = std::sync::Arc::new(on_log);
        let pipes: Vec<Box<dyn Read + Send>> =
            vec![Box::new(child.stdout.take().unwrap()), Box::new(child.stderr.take().unwrap())];
        for pipe in pipes {
            let log = on_log.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let l = line.trim();
                    if !l.is_empty() {
                        log(l.to_string());
                    }
                }
            });
        }
        let mut w = Self { child };
        // Неверные параметры winws видны сразу: процесс завершается.
        std::thread::sleep(Duration::from_millis(300));
        if let Some(code) = w.exited() {
            return Err(format!("winws сразу завершился (код {code}) — подробности в журнале"));
        }
        Ok(w)
    }

    /// Код выхода, если процесс уже завершился.
    pub fn exited(&mut self) -> Option<i32> {
        self.child.try_wait().ok().flatten().map(|s| s.code().unwrap_or(-1))
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Winws {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Linux: тот же интерфейс, но работает nfqws через помощника с правами root (nfq.rs).
/// Помощник должен быть уже запущен (nfq::helper_start).
#[cfg(target_os = "linux")]
pub struct Winws {
    pid: u32,
}

#[cfg(target_os = "linux")]
impl Winws {
    pub fn start(dir: &Path, args: &[String], on_log: impl Fn(String) + Send + Sync + 'static) -> Result<Self, String> {
        let nfqws = dir.join("nfqws");
        if !nfqws.exists() {
            return Err(format!("нет {}", nfqws.display()));
        }
        if !crate::nfq::helper_ready() {
            return Err("нужны права root — подтверди паролем".into());
        }
        let (args, tcp, udp) = crate::nfq::plan(args)?;
        let pid = crate::nfq::start(&nfqws, args, tcp, udp, std::sync::Arc::new(on_log))?;
        std::thread::sleep(Duration::from_millis(300));
        if let Some(code) = crate::nfq::take_exited() {
            return Err(format!("nfqws сразу завершился (код {code}) — подробности в журнале"));
        }
        Ok(Self { pid })
    }

    pub fn exited(&mut self) -> Option<i32> {
        if self.pid == 0 {
            return None;
        }
        let code = crate::nfq::take_exited();
        if code.is_some() {
            self.pid = 0;
        }
        code
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn stop(&mut self) {
        if self.pid != 0 && crate::nfq::running_pid() == self.pid && crate::nfq::helper_ready() {
            crate::nfq::stop();
        }
        self.pid = 0;
    }
}

/// Некоторым стратегиям нужны TCP timestamps — service.bat включает их так же.
#[cfg(not(target_os = "linux"))]
fn tcp_timestamps() {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("netsh");
        cmd.args(["interface", "tcp", "set", "global", "timestamps=enabled"]);
        crate::sys::hide_window(&mut cmd);
        let _ = cmd.output();
    }
}

/// PID чужих winws.exe (запущенных батником или службой zapret) — с ними будет конфликт.
pub fn foreign_winws(ours: &[u32]) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    return crate::nfq::foreign_nfqws().into_iter().filter(|p| !ours.contains(p)).collect();
    #[allow(unreachable_code)]
    if !cfg!(windows) {
        return Vec::new();
    }
    let mut cmd = Command::new("tasklist");
    cmd.args(["/FI", "IMAGENAME eq winws.exe", "/FO", "CSV", "/NH"]);
    crate::sys::hide_window(&mut cmd);
    let Ok(out) = cmd.output() else { return Vec::new() };
    crate::sys::decode_oem(&out.stdout)
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("\"winws.exe\""))
        .filter_map(|l| l.split("\",\"").nth(1)?.trim_matches('"').parse::<u32>().ok())
        .filter(|pid| !ours.contains(pid))
        .collect()
}

// ---------------------------------------------------------------- скачивание

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent("Foxray")
        .build()
}

/// Последняя версия сборки на GitHub.
pub fn latest_version() -> Result<String, String> {
    let v = agent()
        .get(&format!("{REPO_RAW}/.service/version.txt"))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let v = v.trim().to_string();
    if v.is_empty() || v.len() > 20 || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err(format!("странный номер версии: {v:?}"));
    }
    Ok(v)
}

/// Скачать сборку и разложить в dir. Свои списки (*-user.txt, наш файл исключений) сохраняются.
/// winws перед этим нужно остановить — иначе файлы заняты.
pub fn download(dir: &Path, version: &str) -> Result<(), String> {
    let url = format!("{REPO_DL}/{version}/zapret-discord-youtube-{version}.zip");
    let resp = agent().get(&url).call().map_err(|e| format!("не скачалось: {e}"))?;
    let mut data = Vec::new();
    resp.into_reader()
        .take(64 * 1024 * 1024)
        .read_to_end(&mut data)
        .map_err(|e| format!("не скачалось: {e}"))?;

    let parent = dir.parent().ok_or("нет папки программы")?;
    let tmp = parent.join(format!("{FOLDER}.new"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    unpack(&data, &tmp).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp);
    })?;
    // Linux: сама программа обхода — nfqws из bol-van/zapret (в сборке Flowseal только winws.exe).
    #[cfg(target_os = "linux")]
    crate::nfq::download_nfqws(&tmp).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&tmp);
    })?;
    if !installed(&tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("в архиве нет winws.exe или стратегий — формат сборки изменился".into());
    }
    // Переносим свои файлы из старой папки.
    if dir.exists() {
        for name in ["ipset-exclude-user.txt", "list-general-user.txt", "list-exclude-user.txt", EXCLUDE_FILE] {
            let from = dir.join("lists").join(name);
            if from.exists() {
                let _ = std::fs::copy(&from, tmp.join("lists").join(name));
            }
        }
        let old = parent.join(format!("{FOLDER}.old"));
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(dir, &old).map_err(|e| format!("старая папка zapret занята ({e}) — закрой zapret и попробуй снова"))?;
        if let Err(e) = std::fs::rename(&tmp, dir) {
            let _ = std::fs::rename(&old, dir);
            return Err(e.to_string());
        }
        let _ = std::fs::remove_dir_all(&old);
    } else {
        std::fs::rename(&tmp, dir).map_err(|e| e.to_string())?;
    }
    ensure_user_lists(dir);
    Ok(())
}

/// Распаковать zip, убрав верхнюю папку «zapret-discord-youtube-x.y.z/».
fn unpack(data: &[u8], to: &Path) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|e| format!("архив повреждён: {e}"))?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        let Some(path) = f.enclosed_name() else { continue }; // защита от «../» в архиве
        let mut parts = path.components();
        parts.next(); // верхняя папка
        let rel: PathBuf = parts.collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = to.join(&rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        } else {
            if let Some(p) = out.parent() {
                std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
            }
            let mut w = std::fs::File::create(&out).map_err(|e| e.to_string())?;
            std::io::copy(&mut f, &mut w).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- проверка стратегий

/// Что проверяем: сайты Discord и YouTube (все — из списков zapret).
pub const TARGETS: [(&str, &str); 7] = [
    ("discord.com", "https://discord.com/"),
    ("gateway.discord.gg", "https://gateway.discord.gg/"),
    ("cdn.discordapp.com", "https://cdn.discordapp.com/"),
    ("updates.discord.com", "https://updates.discord.com/"),
    ("youtube.com", "https://www.youtube.com/"),
    ("i.ytimg.com", "https://i.ytimg.com/"),
    ("googlevideo.com", "https://redirector.googlevideo.com/"),
];

/// Один запрос: дошёл ли ответ и не «замёрзла» ли загрузка на 16–20 КБ
/// (так провайдеры режут заблокированное). Читаем до 64 КБ или до конца.
pub fn check(url: &str) -> Result<Duration, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .redirects(0)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Foxray")
        .build();
    let t = Instant::now();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r, // 403/404 — тоже ответ: сайт доступен
        Err(ureq::Error::Transport(e)) => return Err(short(&e.to_string())),
    };
    let first = t.elapsed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0usize;
    let mut r = resp.into_reader();
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= 64 * 1024 {
                    break;
                }
            }
            Err(e) => return Err(format!("оборвалось на {} КБ — {}", total / 1024, short(&e.to_string()))),
        }
    }
    Ok(first)
}

fn short(s: &str) -> String {
    let s = s.rsplit(": ").next().unwrap_or(s);
    s.chars().take(60).collect()
}

/// Итог проверки одной стратегии.
#[derive(Debug, Clone)]
pub struct Score {
    pub ok: usize,
    pub total: usize,
    pub avg_ms: u64,
    /// Что не открылось: «youtube.com — timed out».
    pub failed: Vec<String>,
}

impl Score {
    pub fn text(&self) -> String {
        if self.ok == 0 {
            format!("0/{} — не работает", self.total)
        } else {
            format!("{}/{} · {} мс", self.ok, self.total, self.avg_ms)
        }
    }
}

/// Проверить все сайты (параллельно).
pub fn check_all() -> Score {
    let handles: Vec<_> = TARGETS
        .iter()
        .map(|(name, url)| {
            let (name, url) = (name.to_string(), url.to_string());
            std::thread::spawn(move || (name, check(&url)))
        })
        .collect();
    let mut ok = 0;
    let mut sum = 0u128;
    let mut failed = Vec::new();
    for h in handles {
        match h.join() {
            Ok((_, Ok(d))) => {
                ok += 1;
                sum += d.as_millis();
            }
            Ok((name, Err(e))) => failed.push(format!("{name} — {e}")),
            Err(_) => failed.push("ошибка проверки".into()),
        }
    }
    Score { ok, total: TARGETS.len(), avg_ms: if ok > 0 { (sum / ok as u128) as u64 } else { 0 }, failed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_and_order() {
        assert_eq!(title_of("general"), "Основная");
        assert_eq!(title_of("general (ALT3)"), "ALT3");
        let mut ids = vec!["general (ALT10)", "general (SIMPLE FAKE)", "general (ALT2)", "general", "general (ALT)"];
        ids.sort_by_key(|s| sort_key(s));
        assert_eq!(ids, vec!["general", "general (ALT)", "general (ALT2)", "general (ALT10)", "general (SIMPLE FAKE)"]);
    }

    /// Распаковка настоящего архива сборки (путь в ZAPRET_ZIP, иначе пропуск).
    #[test]
    fn unpack_release_zip() {
        let Some(zip) = std::env::var_os("ZAPRET_ZIP") else { return };
        let data = std::fs::read(zip).unwrap();
        let to = std::env::temp_dir().join("foxray-zapret-unpack-test");
        let _ = std::fs::remove_dir_all(&to);
        std::fs::create_dir_all(&to).unwrap();
        unpack(&data, &to).unwrap();
        assert!(installed(&to));
        assert!(version(&to).is_some());
        let _ = std::fs::remove_dir_all(&to);
    }

    #[test]
    fn split_quotes() {
        assert_eq!(
            split_args(r#"--a=1 --hostlist="C:\x y\l.txt" --fake-tls=^! "q^q" --new"#),
            vec!["--a=1", r"--hostlist=C:\x y\l.txt", "--fake-tls=!", "q^q", "--new"]
        );
    }

    #[test]
    fn parse_simple_bat() {
        let bat = "@echo off\r\nset \"BIN=%~dp0bin\\\"\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilterTCP% ^\r\n--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --new ^\r\n--filter-tcp=443 --dpi-desync=fake\r\n";
        let dir = Path::new("Z");
        let ex = Path::new("Z/ex.txt");
        let a = parse_bat(bat, dir, Extra { exclude: Some(ex), ..Default::default() }).unwrap();
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(a[0], "--wf-tcp=80,443,12");
        assert_eq!(a[2], format!("--hostlist=Z{sep}lists{sep}list-general.txt"));
        assert_eq!(a[3], "--ipset-exclude=Z/ex.txt");
        assert_eq!(a[4], "--new");
        assert_eq!(a.last().unwrap(), "--ipset-exclude=Z/ex.txt");
        assert_eq!(a.iter().filter(|x| x.starts_with("--ipset-exclude")).count(), 2);
    }

    #[test]
    fn user_lists_follow_build_lists() {
        let dir = std::env::temp_dir().join("foxray-zapret-user");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        let bat = "\"%BIN%winws.exe\" --filter-tcp=443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" --new --filter-tcp=80 --ipset=\"%LISTS%ipset-all.txt\" --dpi-desync=fake\n";
        let (h, i) = write_user_lists(&dir, &UserLists { hosts: vec!["rutracker.org".into()], ips: vec![] });
        assert_eq!(std::fs::read_to_string(&h).unwrap(), "rutracker.org\n");
        assert_eq!(std::fs::read_to_string(&i).unwrap(), "203.0.113.113/32\n");
        let extra = Extra { exclude: None, hostlist: Some(&h), ipset: Some(&i), games: false };
        // ipset-all.txt — заглушка (режим «none»): свой ipset добавляется
        std::fs::write(dir.join("lists").join("ipset-all.txt"), "203.0.113.113/32\n").unwrap();
        let a = parse_bat(bat, &dir, extra).unwrap();
        let pos = a.iter().position(|x| x.ends_with("list-general-user.txt")).unwrap();
        assert_eq!(a[pos + 1], format!("--hostlist={}", h.display()));
        let pos = a.iter().position(|x| x.ends_with("ipset-all.txt")).unwrap();
        assert_eq!(a[pos + 1], format!("--ipset={}", i.display()));
        // пустой ipset-all.txt (режим «any» — все адреса): свой не добавляем, иначе сузит профиль
        std::fs::write(dir.join("lists").join("ipset-all.txt"), "").unwrap();
        let a = parse_bat(bat, &dir, extra).unwrap();
        assert!(!a.iter().any(|x| x.contains(USER_IPSET)));
        assert_eq!(a.iter().filter(|x| x.contains(USER_HOSTLIST)).count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_entries() {
        let e: Vec<String> = ["rutracker.org", "full:x.com", "1.2.3.4", "keyword:goo", "steam.exe", "*.ya.ru"].map(String::from).to_vec();
        let u = user_lists(&e, Path::new("."), None);
        assert_eq!(u.hosts, vec!["rutracker.org", "^x.com", "ya.ru"]);
        assert_eq!(u.ips, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn game_filter_splits_profiles() {
        let dir = std::env::temp_dir().join("foxray-zap-games");
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        std::fs::write(dir.join("lists").join("ipset-all.txt"), "1.2.3.0/24\n").unwrap();
        let bat = "\"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilter% --wf-udp=443,%GameFilter% ^\n--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --dpi-desync=fake --new ^\n--filter-tcp=443,%GameFilter% --ipset=\"%LISTS%ipset-all.txt\" --dpi-desync=fakedsplit --new ^\n--filter-udp=%GameFilter% --ipset=\"%LISTS%ipset-all.txt\" --dpi-desync=fake --dpi-desync-cutoff=n2\n";
        // Выключено — заглушка 12, ничего не делится.
        let off = parse_bat(bat, &dir, Extra::default()).unwrap();
        assert!(off.contains(&"--wf-tcp=80,443,12".to_string()));
        assert_eq!(off.iter().filter(|a| *a == "--new").count(), 2);
        // Включено: TCP-профиль делится на 443 (с ipset) и игровые порты (без ipset), UDP — без ipset.
        let on = parse_bat(bat, &dir, Extra { games: true, ..Default::default() }).unwrap();
        assert!(on.contains(&"--wf-udp=443,1024-65535".to_string()));
        let profiles: Vec<Vec<String>> = on.split(|a| a == "--new").map(|p| p.to_vec()).collect();
        assert_eq!(profiles.len(), 4, "{on:?}");
        assert!(profiles[1].contains(&"--filter-tcp=443".to_string()));
        assert!(profiles[1].iter().any(|a| a.ends_with("ipset-all.txt")));
        assert!(profiles[2].contains(&"--filter-tcp=1024-65535".to_string()));
        assert!(profiles[2].contains(&"--dpi-desync=fakedsplit".to_string()));
        assert!(!profiles[2].iter().any(|a| a.starts_with("--ipset=")));
        assert!(profiles[3].contains(&"--filter-udp=1024-65535".to_string()));
        assert!(!profiles[3].iter().any(|a| a.starts_with("--ipset=")));
        assert!(profiles[3].contains(&"--dpi-desync-cutoff=n2".to_string()));
    }
}
