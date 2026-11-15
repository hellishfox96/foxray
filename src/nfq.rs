//! Zapret в Linux: вместо winws.exe (WinDivert) — nfqws из проекта bol-van/zapret.
//!
//! Как это устроено:
//!   * Стратегии те же — батники сборки Flowseal. Из аргументов winws убираем
//!     Windows-параметры --wf-tcp/--wf-udp (что перехватывать) — их заменяют правила nftables.
//!   * Правила nftables и сам nfqws требуют root. Поэтому Foxray один раз за запуск
//!     поднимает помощника через pkexec (система спросит пароль): `foxray-gui --zapret-helper`.
//!     Помощник живёт, пока жив Foxray (общается через stdin/stdout), ставит правила,
//!     запускает и перезапускает nfqws, а при выходе Foxray всё убирает за собой.
//!   * Пакеты, которые программы кладут в TUN Foxray (интерфейс «foxray»), не трогаем:
//!     zapret нужен только тому, что уходит наружу через обычную сеть (направление «напрямую»).

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Номер очереди NFQUEUE (свой, чтобы не столкнуться с установленным zapret — у него 200).
pub const QNUM: u16 = 4242;
const TABLE: &str = "foxray_zapret";
/// Имя TUN Foxray (config.rs: tun_name).
const TUN: &str = "foxray";

/// Аргументы winws → (аргументы nfqws, TCP-порты, UDP-порты).
pub fn plan(win_args: &[String]) -> Result<(Vec<String>, String, String), String> {
    let mut tcp = String::new();
    let mut udp = String::new();
    let mut out = Vec::with_capacity(win_args.len() + 4);
    // Сгенерированные nfqws пакеты (фейки, части) уходят с того же интерфейса, что и исходный.
    // Без этого при включённом VPN их подхватывает маршрутизация TUN (sing-box, auto_route) —
    // они уходят в туннель вместо Wi-Fi, и не открывается ничего («Ресурс временно недоступен»).
    out.push("--bind-fix4".to_string());
    out.push("--bind-fix6".to_string());
    for a in win_args {
        if let Some(p) = a.strip_prefix("--wf-tcp=") {
            tcp = p.to_string();
        } else if let Some(p) = a.strip_prefix("--wf-udp=") {
            udp = p.to_string();
        } else if a.starts_with("--wf-") {
            // остальные --wf-* — тоже про WinDivert, в Linux не нужны
        } else {
            out.push(a.clone());
        }
    }
    for p in [&tcp, &udp] {
        if !p.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-') {
            return Err(format!("странный список портов: {p}"));
        }
    }
    if tcp.is_empty() && udp.is_empty() {
        return Err("в стратегии нет --wf-tcp/--wf-udp".into());
    }
    Ok((out, tcp, udp))
}

/// Правила nftables: первые пакеты соединений на нужные порты — в очередь nfqws.
pub fn nft_script(tcp: &str, udp: &str) -> String {
    let set = |p: &str| p.split(',').filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", ");
    let mut post = String::new();
    let mut pre = String::new();
    if !tcp.is_empty() {
        post += &format!("    tcp dport {{ {} }} ct original packets 1-9 queue num {QNUM} bypass\n", set(tcp));
        pre += &format!("    tcp sport {{ {} }} ct reply packets 1-3 queue num {QNUM} bypass\n", set(tcp));
    }
    if !udp.is_empty() {
        post += &format!("    udp dport {{ {} }} ct original packets 1-9 queue num {QNUM} bypass\n", set(udp));
    }
    format!(
        "table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         table inet {TABLE} {{\n\
         \x20 chain post {{\n\
         \x20   type filter hook postrouting priority mangle; policy accept;\n\
         \x20   oifname \"lo\" return\n\
         \x20   oifname \"{TUN}\" return\n\
         \x20   meta mark and 0x40000000 == 0x40000000 return\n\
         {post}\
         \x20 }}\n\
         \x20 chain pre {{\n\
         \x20   type filter hook prerouting priority filter; policy accept;\n\
         \x20   iifname \"lo\" return\n\
         \x20   iifname \"{TUN}\" return\n\
         {pre}\
         \x20 }}\n\
         }}\n"
    )
}

// ================================================================ помощник (root)

/// Куда помощник копирует списки и файлы стратегии для nfqws (tmpfs, доступно root без особых прав).
const STAGE_DIR: &str = "/run/foxray-zapret";

/// Скопировать файлы из аргументов (`--hostlist=/home/…/list.txt`, `--dpi-desync-fake-tls=/…/x.bin`)
/// в `dir` и подставить новые пути. Остальные аргументы — как есть.
fn stage_files(args: &[String], dir: &Path) -> Vec<String> {
    let _ = std::fs::remove_dir_all(dir);
    if std::fs::create_dir_all(dir).is_err() {
        return args.to_vec();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
    let mut copied: Vec<(String, String)> = Vec::new();
    args.iter()
        .map(|a| {
            let Some((k, v)) = a.split_once('=') else { return a.clone() };
            if !v.starts_with('/') || !Path::new(v).is_file() {
                return a.clone();
            }
            if let Some((_, d)) = copied.iter().find(|(src, _)| src == v) {
                return format!("{k}={d}");
            }
            let name = Path::new(v).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let dst = dir.join(format!("{}-{name}", copied.len()));
            if std::fs::copy(v, &dst).is_err() {
                return a.clone();
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644));
            }
            let d = dst.to_string_lossy().to_string();
            copied.push((v.to_string(), d.clone()));
            format!("{k}={d}")
        })
        .collect()
}

fn send(out: &Arc<Mutex<std::io::Stdout>>, v: serde_json::Value) {
    let mut o = out.lock().unwrap();
    let _ = writeln!(o, "{v}");
    let _ = o.flush();
}

fn find_tool(name: &str) -> Option<std::path::PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
}

fn nft(script: &str) -> Result<(), String> {
    let nft = find_tool("nft").ok_or("нет программы nft (пакет nftables)")?;
    let mut c = Command::new(nft)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    c.stdin.take().unwrap().write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    let out = c.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn nft_clear() {
    let _ = nft(&format!("table inet {TABLE}\ndelete table inet {TABLE}\n"));
}

/// `foxray-gui --zapret-helper` под pkexec. Возвращает код выхода.
pub fn helper_main() -> i32 {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    // Хвосты прошлого запуска (Foxray мог упасть).
    nft_clear();
    send(&out, serde_json::json!({"t": "ready"}));

    let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let stop_child = |child: &Arc<Mutex<Option<Child>>>| {
        if let Some(mut c) = child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    };

    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        match cmd["op"].as_str() {
            Some("start") => {
                stop_child(&child);
                let res = (|| -> Result<u32, String> {
                    let nfqws = cmd["nfqws"].as_str().ok_or("нет пути к nfqws")?;
                    if Path::new(nfqws).file_name().and_then(|n| n.to_str()) != Some("nfqws") {
                        return Err("неверный путь к nfqws".into());
                    }
                    let args: Vec<String> = cmd["args"]
                        .as_array()
                        .ok_or("нет аргументов")?
                        .iter()
                        .filter_map(|a| a.as_str().map(String::from))
                        .collect();
                    let tcp = cmd["tcp"].as_str().unwrap_or("");
                    let udp = cmd["udp"].as_str().unwrap_or("");
                    if !(tcp.chars().chain(udp.chars())).all(|c| c.is_ascii_digit() || c == ',' || c == '-') {
                        return Err("неверные порты".into());
                    }
                    nft(&nft_script(tcp, udp))?;
                    // Списки и .bin — в /run: после старта nfqws сбрасывает права и проверяет,
                    // что может перечитать файлы, а домашняя папка (0700/0750) ему уже закрыта
                    // («file_open_test: Permission denied» — и nfqws сразу выходит).
                    let args = stage_files(&args, Path::new(STAGE_DIR));
                    let mut c = Command::new(nfqws)
                        .arg(format!("--qnum={QNUM}"))
                        // Остаёмся root: файлы стратегий лежат в домашней папке, «nobody» их не прочитает.
                        .arg("--uid=0:0")
                        .args(&args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| format!("nfqws не запустился: {e}"))?;
                    let pid = c.id();
                    let pipes: Vec<Box<dyn Read + Send>> =
                        vec![Box::new(c.stdout.take().unwrap()), Box::new(c.stderr.take().unwrap())];
                    for p in pipes {
                        let out = out.clone();
                        std::thread::spawn(move || {
                            for l in BufReader::new(p).lines().map_while(Result::ok) {
                                if !l.trim().is_empty() {
                                    send(&out, serde_json::json!({"t": "log", "msg": l}));
                                }
                            }
                        });
                    }
                    *child.lock().unwrap() = Some(c);
                    // Сторож: nfqws завершился сам — сообщаем.
                    let (child2, out2) = (child.clone(), out.clone());
                    std::thread::spawn(move || loop {
                        std::thread::sleep(Duration::from_millis(300));
                        let mut g = child2.lock().unwrap();
                        match g.as_mut() {
                            Some(c) if c.id() == pid => {
                                if let Ok(Some(st)) = c.try_wait() {
                                    *g = None;
                                    send(&out2, serde_json::json!({"t": "exited", "pid": pid, "code": st.code().unwrap_or(-1)}));
                                    return;
                                }
                            }
                            _ => return, // остановлен нами или заменён новым
                        }
                    });
                    Ok(pid)
                })();
                match res {
                    Ok(pid) => send(&out, serde_json::json!({"t": "ok", "pid": pid})),
                    Err(e) => {
                        nft_clear();
                        send(&out, serde_json::json!({"t": "err", "msg": e}));
                    }
                }
            }
            Some("stop") => {
                stop_child(&child);
                nft_clear();
                send(&out, serde_json::json!({"t": "ok", "pid": 0}));
            }
            _ => {}
        }
    }
    // stdin закрылся — Foxray вышел или упал: убираем всё.
    stop_child(&child);
    nft_clear();
    0
}

// ================================================================ сторона Foxray

struct Client {
    stdin: ChildStdin,
    _child: Child,
    replies: mpsc::Receiver<serde_json::Value>,
}

#[derive(Default)]
struct Shared {
    log: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// PID запущенного nfqws (0 — не запущен).
    pid: u32,
    /// Код выхода, если nfqws завершился сам.
    exited: Option<i32>,
    alive: bool,
}

static CLIENT: Mutex<Option<Client>> = Mutex::new(None);
static SHARED: Mutex<Option<Shared>> = Mutex::new(None);

fn shared<R>(f: impl FnOnce(&mut Shared) -> R) -> R {
    let mut g = SHARED.lock().unwrap();
    f(g.get_or_insert_with(Shared::default))
}

/// Помощник уже запущен (пароль введён).
pub fn helper_ready() -> bool {
    shared(|s| s.alive) && CLIENT.lock().unwrap().is_some()
}

/// Запустить помощника через pkexec. Блокирует, пока пользователь вводит пароль.
pub fn helper_start() -> Result<(), String> {
    if helper_ready() {
        return Ok(());
    }
    let exe = crate::sys::self_exe().map_err(|e| e.to_string())?;
    if !exe.exists() {
        return Err(format!("не найден файл Foxray ({}) — перезапусти Foxray", exe.display()));
    }
    // Одно окно пароля за раз (см. sys::PKEXEC_LOCK) — держим, пока помощник не ответит.
    let _one = crate::sys::PKEXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pkexec = find_tool("pkexec").ok_or("нет pkexec — zapret в Linux нужны права root")?;
    let mut child = Command::new(pkexec)
        .arg(&exe)
        .arg("--zapret-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("pkexec: {e}"))?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    // Что пишет pkexec (почему отказал) — покажем в ошибке.
    let errtext = Arc::new(Mutex::new(String::new()));
    {
        let errtext = errtext.clone();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut e = errtext.lock().unwrap();
                if e.len() < 600 {
                    if !e.is_empty() {
                        e.push_str("; ");
                    }
                    e.push_str(line.trim());
                }
            }
        });
    }
    let (tx, rx) = mpsc::channel::<serde_json::Value>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            match v["t"].as_str() {
                Some("log") => {
                    let log = shared(|s| s.log.clone());
                    if let Some(f) = log {
                        f(v["msg"].as_str().unwrap_or("").to_string());
                    }
                }
                Some("exited") => {
                    let pid = v["pid"].as_u64().unwrap_or(0) as u32;
                    shared(|s| {
                        if s.pid == pid {
                            s.pid = 0;
                            s.exited = Some(v["code"].as_i64().unwrap_or(-1) as i32);
                        }
                    });
                }
                _ => {
                    let _ = tx.send(v);
                }
            }
        }
        // Помощник закрылся (отказ в пароле, ошибка).
        shared(|s| {
            if s.alive && s.pid != 0 {
                s.exited = Some(-1);
            }
            s.alive = false;
            s.pid = 0;
        });
        *CLIENT.lock().unwrap() = None;
    });
    // Ждём «ready» — пока человек вводит пароль.
    match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(v) if v["t"] == "ready" => {
            shared(|s| s.alive = true);
            *CLIENT.lock().unwrap() = Some(Client { stdin, _child: child, replies: rx });
            Ok(())
        }
        Ok(v) => Err(format!("помощник: {v}")),
        // Помощник закрылся сразу: pkexec отказал (отмена, нет агента polkit, ошибка запуска).
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let code = child.wait().ok().and_then(|s| s.code());
            std::thread::sleep(Duration::from_millis(100));
            let err = errtext.lock().unwrap().clone();
            Err(match code {
                Some(126) if err.is_empty() => "пароль не введён (окно закрыли) — без прав root zapret в Linux не работает".into(),
                Some(127) if err.is_empty() => "система не дала права root (polkit отказал)".into(),
                _ if !err.is_empty() => format!("pkexec: {err}"),
                c => format!("помощник zapret не запустился (код {})", c.map_or("?".into(), |c| c.to_string())),
            })
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err("пароль не введён — без прав root zapret в Linux не работает".into())
        }
    }
}

fn request(cmd: serde_json::Value) -> Result<u32, String> {
    let mut g = CLIENT.lock().unwrap();
    let c = g.as_mut().ok_or("помощник zapret не запущен")?;
    // Старые ответы (если были) — выбрасываем.
    while c.replies.try_recv().is_ok() {}
    writeln!(c.stdin, "{cmd}").map_err(|e| format!("помощник не отвечает: {e}"))?;
    let _ = c.stdin.flush();
    match c.replies.recv_timeout(Duration::from_secs(20)) {
        Ok(v) if v["t"] == "ok" => Ok(v["pid"].as_u64().unwrap_or(0) as u32),
        Ok(v) => Err(v["msg"].as_str().unwrap_or("ошибка помощника").to_string()),
        Err(_) => Err("помощник не ответил".into()),
    }
}

/// Запустить nfqws (через помощника). on_log — строки вывода nfqws.
pub fn start(
    nfqws: &Path,
    args: Vec<String>,
    tcp: String,
    udp: String,
    on_log: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<u32, String> {
    shared(|s| {
        s.log = Some(on_log);
        s.exited = None;
        s.pid = 0;
    });
    let pid = request(serde_json::json!({
        "op": "start",
        "nfqws": nfqws.to_string_lossy(),
        "args": args,
        "tcp": tcp,
        "udp": udp,
    }))?;
    shared(|s| s.pid = pid);
    Ok(pid)
}

pub fn stop() {
    shared(|s| {
        s.pid = 0;
        s.log = None;
    });
    let _ = request(serde_json::json!({"op": "stop"}));
}

/// nfqws завершился сам — код выхода (один раз).
pub fn take_exited() -> Option<i32> {
    shared(|s| s.exited.take())
}

pub fn running_pid() -> u32 {
    shared(|s| s.pid)
}

/// Чужие nfqws (например, установленный системно zapret) — будут мешать.
pub fn foreign_nfqws() -> Vec<u32> {
    let ours = running_pid();
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .filter(|pid| *pid != ours)
                .filter(|pid| std::fs::read_to_string(format!("/proc/{pid}/comm")).map(|c| c.trim() == "nfqws").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default()
}

// ================================================================ скачивание nfqws

/// Папка с бинарником под этот процессор в архиве zapret.
fn arch_dir() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("linux-x86_64"),
        "x86" => Some("linux-x86"),
        "aarch64" => Some("linux-arm64"),
        "arm" => Some("linux-arm"),
        _ => None,
    }
}

/// Скачать nfqws последней версии в dir/nfqws. Возвращает версию («v72.13»).
pub fn download_nfqws(dir: &Path) -> Result<String, String> {
    let arch = arch_dir().ok_or_else(|| format!("нет nfqws для процессора {}", std::env::consts::ARCH))?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent("Foxray")
        .build();
    // Последняя версия — по переадресации со страницы latest.
    let resp = agent
        .get("https://github.com/bol-van/zapret/releases/latest")
        .call()
        .map_err(|e| format!("не узнал версию nfqws: {e}"))?;
    let tag = resp.get_url().rsplit('/').next().unwrap_or("").to_string();
    if !tag.starts_with('v') || !tag[1..].chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("не узнал версию nfqws ({})", resp.get_url()));
    }
    drop(resp);
    let url = format!("https://github.com/bol-van/zapret/releases/download/{tag}/zapret-{tag}.tar.gz");
    let resp = agent.get(&url).call().map_err(|e| format!("nfqws не скачался: {e}"))?;
    let gz = flate2::read::GzDecoder::new(resp.into_reader().take(64 * 1024 * 1024));
    let mut ar = tar::Archive::new(gz);
    let want = format!("binaries/{arch}/nfqws");
    for entry in ar.entries().map_err(|e| e.to_string())? {
        let mut e = entry.map_err(|e| e.to_string())?;
        let path = e.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        if path.ends_with(&want) {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let tmp = dir.join("nfqws.new");
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            std::io::copy(&mut e, &mut f).map_err(|e| e.to_string())?;
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, dir.join("nfqws")).map_err(|e| e.to_string())?;
            let _ = std::fs::write(dir.join("nfqws.version"), &tag);
            return Ok(tag);
        }
    }
    Err(format!("в архиве zapret нет {want}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_staged() {
        let src = std::env::temp_dir().join("foxray-stage-src");
        let dst = std::env::temp_dir().join("foxray-stage-dst");
        let _ = std::fs::create_dir_all(&src);
        let f = src.join("list-general.txt");
        std::fs::write(&f, "discord.com\n").unwrap();
        let f = f.to_string_lossy().to_string();
        let a = vec![format!("--hostlist={f}"), "--new".into(), format!("--hostlist-exclude={f}"), "--dpi-desync-fake-tls=^!".into(), "--hostlist=/nope.txt".into()];
        let out = stage_files(&a, &dst);
        let d = dst.join("0-list-general.txt").to_string_lossy().to_string();
        assert_eq!(out[0], format!("--hostlist={d}"));
        assert_eq!(out[2], format!("--hostlist-exclude={d}"));
        assert_eq!(out[1], "--new");
        assert_eq!(out[3], "--dpi-desync-fake-tls=^!");
        assert_eq!(out[4], "--hostlist=/nope.txt");
        assert_eq!(std::fs::read_to_string(dst.join("0-list-general.txt")).unwrap(), "discord.com\n");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn plan_strips_windivert() {
        let a: Vec<String> = ["--wf-tcp=80,443,12", "--wf-udp=443,50000-50100", "--wf-l3=ipv4", "--filter-udp=443", "--new"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (args, tcp, udp) = plan(&a).unwrap();
        assert_eq!(args, vec!["--bind-fix4", "--bind-fix6", "--filter-udp=443", "--new"]);
        assert_eq!(tcp, "80,443,12");
        assert_eq!(udp, "443,50000-50100");
        let s = nft_script(&tcp, &udp);
        assert!(s.contains("tcp dport { 80, 443, 12 } ct original packets 1-9 queue num 4242 bypass"));
        assert!(s.contains("udp dport { 443, 50000-50100 }"));
        assert!(s.contains("oifname \"foxray\" return"));
    }
}
