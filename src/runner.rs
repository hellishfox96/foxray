//! Запуск и остановка sing-box, чтение его лога и скорости через Clash API.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    /// sing-box запустился и отвечает
    Started,
    /// Скорость, байт/с
    Traffic { up: u64, down: u64 },
    /// Итоги сессии: всего байт и число открытых соединений
    Stats { down_total: u64, up_total: u64, conns: u32, list: Vec<Conn> },
    /// Процесс завершился. None — остановлен нами, Some — ошибка.
    Stopped(Option<String>),
}

pub struct Runner {
    child: Arc<Mutex<Child>>,
    stopping: Arc<AtomicBool>,
    /// Linux: файл с PID sing-box — чтобы после падения Foxray найти и закрыть «осиротевший» sing-box.
    #[cfg(unix)]
    pid_file: Option<std::path::PathBuf>,
}

impl Runner {
    pub fn start(
        singbox: &Path,
        config: &Path,
        api_port: u16,
        on_event: impl Fn(Event) + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let mut cmd = Command::new(singbox);
        cmd.arg("run")
            .arg("-c")
            .arg(config)
            .arg("--disable-color")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = config.parent() {
            cmd.current_dir(dir);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        #[cfg(unix)]
        let pid_file = config.parent().map(|d| d.join(PID_FILE));
        #[cfg(unix)]
        if let Some(dir) = config.parent() {
            kill_stale(dir);
        }
        let mut child = cmd.spawn()?;
        #[cfg(unix)]
        if let Some(p) = &pid_file {
            let _ = std::fs::write(p, child.id().to_string());
        }
        // sing-box умрёт вместе с Foxray (даже при падении), а не останется висеть с TUN.
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            crate::winjob::bind(child.as_raw_handle() as _);
        }

        let on_event: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(on_event);
        let last_error = Arc::new(Mutex::new(None::<String>));

        // Читаем stdout и stderr построчно.
        let pipes: Vec<Box<dyn Read + Send>> = vec![
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for pipe in pipes {
            let ev = on_event.clone();
            let last = last_error.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let line = line.trim_end().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if line.contains("FATAL") || line.contains("ERROR") && line.contains("start") {
                        *last.lock().unwrap() = Some(short_error(&line));
                    }
                    ev(Event::Log(line));
                }
            });
        }

        let child = Arc::new(Mutex::new(child));
        let stopping = Arc::new(AtomicBool::new(false));

        // Сторож: ждёт запуска, читает скорость, ловит завершение процесса.
        {
            let child = child.clone();
            let stopping = stopping.clone();
            let ev = on_event.clone();
            std::thread::spawn(move || {
                let exited = |c: &Arc<Mutex<Child>>| c.lock().unwrap().try_wait().ok().flatten();
                // 1. Ждём, пока поднимется API.
                let t0 = Instant::now();
                let mut started = false;
                while !stopping.load(Ordering::SeqCst) && exited(&child).is_none() {
                    if api_alive(api_port) {
                        started = true;
                        ev(Event::Started);
                        break;
                    }
                    if t0.elapsed() > Duration::from_secs(20) {
                        ev(Event::Log("foxray: sing-box не отвечает уже 20 секунд".into()));
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                // 2. Скорость, пока процесс жив (+ отдельный поток для итогов).
                if started {
                    let stopping2 = stopping.clone();
                    let child2 = child.clone();
                    let ev2 = ev.clone();
                    std::thread::spawn(move || {
                        while !stopping2.load(Ordering::SeqCst) && exited(&child2).is_none() {
                            if let Some((d, u, list)) = snapshot(api_port) {
                                ev2(Event::Stats { down_total: d, up_total: u, conns: list.len() as u32, list });
                            }
                            std::thread::sleep(Duration::from_secs(2));
                        }
                    });
                    traffic_loop(api_port, &stopping, || exited(&child).is_some(), &*ev);
                }
                // 3. Дожидаемся конца процесса.
                let status = loop {
                    if let Some(s) = exited(&child) {
                        break s;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                };
                std::thread::sleep(Duration::from_millis(150)); // дать дочитать лог
                if stopping.load(Ordering::SeqCst) {
                    ev(Event::Stopped(None));
                } else {
                    let msg = last_error
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| format!("sing-box завершился (код {})", status.code().unwrap_or(-1)));
                    ev(Event::Stopped(Some(msg)));
                }
            });
        }

        Ok(Self {
            child,
            stopping,
            #[cfg(unix)]
            pid_file,
        })
    }

    pub fn stop(&self) {
        if !self.stopping.swap(true, Ordering::SeqCst) {
            let mut c = self.child.lock().unwrap();
            // Linux: сначала просим вежливо (SIGTERM) — sing-box сам уберёт маршруты
            // и правила; убиваем, только если не закрылся за 3 секунды.
            #[cfg(unix)]
            {
                terminate(c.id());
                let t = Instant::now();
                while t.elapsed() < Duration::from_secs(3) {
                    if matches!(c.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let _ = c.kill();
            let _ = c.wait();
            #[cfg(unix)]
            if let Some(p) = &self.pid_file {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

#[cfg(unix)]
const PID_FILE: &str = "sing-box.pid";

#[cfg(unix)]
fn terminate(pid: u32) {
    let _ = Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
}

/// Linux: если Foxray в прошлый раз упал или его убили, sing-box мог остаться работать
/// (в Windows это решает «задание» winjob, в Linux так нельзя — у sing-box свои права).
/// Находим его по PID-файлу в папке `dir` и закрываем.
#[cfg(unix)]
pub fn kill_stale(dir: &Path) {
    let file = dir.join(PID_FILE);
    let Some(pid) = std::fs::read_to_string(&file).ok().and_then(|s| s.trim().parse::<u32>().ok()) else {
        return;
    };
    let _ = std::fs::remove_file(&file);
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    if comm.trim() != "sing-box" {
        return; // PID уже занят другой программой
    }
    terminate(pid);
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) && Path::new(&format!("/proc/{pid}")).exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = Command::new("kill").arg("-KILL").arg(pid.to_string()).status();
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// "+0300 2026-... FATAL[0000] start service: ..." → "start service: ..."
fn short_error(line: &str) -> String {
    for marker in ["FATAL", "ERROR"] {
        if let Some(i) = line.find(marker) {
            let rest = &line[i + marker.len()..];
            let rest = rest.trim_start_matches(|c: char| c == '[' || c.is_ascii_digit() || c == ']');
            return rest.trim().to_string();
        }
    }
    line.to_string()
}

fn http_get(port: u16, path: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    let addr = ([127, 0, 0, 1], port).into();
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    // HTTP/1.0 — без chunked, тело читается до закрытия соединения.
    write!(s, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
    Ok(s)
}

fn api_alive(port: u16) -> bool {
    let Ok(mut s) = http_get(port, "/version", Duration::from_millis(500)) else {
        return false;
    };
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.contains("version")
}


/// Одно соединение из /connections (Clash API sing-box).
#[derive(Debug, Clone)]
pub struct Conn {
    pub id: String,
    /// Домен (если sing-box его узнал) или IP.
    pub host: String,
    pub port: u16,
    /// "tcp" / "udp"
    pub network: String,
    /// Имя программы («Discord.exe»), пусто — не определилась.
    pub process: String,
    /// Куда ушло: "proxy" (VPN), "direct" …
    pub outbound: String,
    /// Какое правило сработало: "final" — ни одно (ушло по умолчанию).
    pub rule: String,
    pub up: u64,
    pub down: u64,
    /// Сколько секунд открыто (None — время не разобрали).
    pub age_secs: Option<u64>,
}

/// Список открытых соединений. None — sing-box не ответил.
pub fn connections(port: u16) -> Option<Vec<Conn>> {
    snapshot(port).map(|(_, _, l)| l)
}

/// /connections: всего скачано, отправлено (за сессию) и открытые соединения.
fn snapshot(port: u16) -> Option<(u64, u64, Vec<Conn>)> {
    let mut s = http_get(port, "/connections", Duration::from_secs(2)).ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let start = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let v: serde_json::Value = serde_json::from_slice(&buf[start..]).ok()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let list = v["connections"].as_array()?;
    let totals = (v["downloadTotal"].as_u64().unwrap_or(0), v["uploadTotal"].as_u64().unwrap_or(0));
    Some((totals.0, totals.1,
        list.iter()
            .map(|c| {
                let m = &c["metadata"];
                let host = m["host"].as_str().filter(|h| !h.is_empty()).or(m["destinationIP"].as_str()).unwrap_or("?");
                let process = m["processPath"].as_str().unwrap_or("");
                let process = process.rsplit(['\\', '/']).next().unwrap_or(process);
                Conn {
                    id: c["id"].as_str().unwrap_or("").to_string(),
                    host: host.to_string(),
                    port: m["destinationPort"].as_str().and_then(|p| p.parse().ok()).or(m["destinationPort"].as_u64().map(|p| p as u16)).unwrap_or(0),
                    network: m["network"].as_str().unwrap_or("").to_string(),
                    process: process.to_string(),
                    outbound: c["chains"].as_array().and_then(|a| a.first()).and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    rule: c["rule"].as_str().unwrap_or("").to_string(),
                    up: c["upload"].as_u64().unwrap_or(0),
                    down: c["download"].as_u64().unwrap_or(0),
                    age_secs: c["start"].as_str().and_then(parse_rfc3339).map(|t| (now - t).max(0) as u64),
                }
            })
            .collect(),
    ))
}

/// Закрыть соединение.
pub fn close_connection(port: u16, id: &str) {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return;
    }
    let addr = ([127, 0, 0, 1], port).into();
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
        let _ = write!(s, "DELETE /connections/{id} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink);
    }
}

/// «2026-11-13T17:44:01.123456+03:00» → секунды Unix.
fn parse_rfc3339(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Смещение часового пояса: Z или ±HH:MM в конце.
    let off = if t.ends_with('Z') {
        0
    } else {
        let tail = &t[t.len().saturating_sub(6)..];
        let sign = match tail.as_bytes().first()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        sign * (tail.get(1..3)?.parse::<i64>().ok()? * 3600 + tail.get(4..6)?.parse::<i64>().ok()? * 60)
    };
    // Дни от 1970-01-01 (алгоритм days_from_civil).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + s - off)
}

#[cfg(test)]
mod conn_tests {
    #[test]
    fn rfc3339() {
        assert_eq!(super::parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(super::parse_rfc3339("2026-11-13T17:44:01.5+03:00"), Some(1794581041));
        assert_eq!(super::parse_rfc3339("2024-02-29T12:00:00-01:30"), Some(1709213400));
    }
}

/// 1536 → "1.5 КБ"
pub fn human_bytes(bytes: u64) -> String {
    human_speed(bytes).trim_end_matches("/с").to_string()
}

/// /traffic отдаёт раз в секунду строки вида {"up":123,"down":456}.
fn traffic_loop(
    port: u16,
    stopping: &AtomicBool,
    dead: impl Fn() -> bool,
    ev: &(dyn Fn(Event) + Send + Sync),
) {
    #[derive(serde::Deserialize)]
    struct T {
        up: u64,
        down: u64,
    }
    while !stopping.load(Ordering::SeqCst) && !dead() {
        let Ok(mut s) = http_get(port, "/traffic", Duration::from_millis(1500)) else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        let mut pending = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if stopping.load(Ordering::SeqCst) || dead() {
                return;
            }
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    pending.extend_from_slice(&chunk[..n]);
                    // Вынимаем все законченные {...}
                    while let (Some(a), Some(b)) =
                        (pending.iter().position(|&c| c == b'{'), pending.iter().position(|&c| c == b'}'))
                    {
                        if b < a {
                            pending.drain(..=b);
                            continue;
                        }
                        if let Ok(t) = serde_json::from_slice::<T>(&pending[a..=b]) {
                            ev(Event::Traffic { up: t.up, down: t.down });
                        }
                        pending.drain(..=b);
                    }
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    }
}

/// 1536 → "1.5 КБ/с"
pub fn human_speed(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["Б/с", "КБ/с", "МБ/с", "ГБ/с"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

#[cfg(test)]
mod conn_api_tests {
    #[test]
    fn parses_clash_connections() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = l.accept().unwrap();
            // Дочитываем запрос целиком — иначе закрытие сокета с непрочитанными данными даёт RST.
            let mut req = Vec::new();
            let mut b = [0u8; 512];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&b[..n]),
                }
            }
            let body = r#"{"downloadTotal":1,"uploadTotal":2,"connections":[{"id":"abc-1","metadata":{"network":"udp","type":"tun/tun-in","sourceIP":"172.19.0.1","destinationIP":"162.159.135.232","sourcePort":"50000","destinationPort":"50007","host":"","processPath":"C:\\Users\\tox\\AppData\\Local\\Discord\\app-1.0\\Discord.exe"},"upload":100,"download":2000,"start":"1970-01-01T00:00:00Z","chains":["direct"],"rule":"x","rulePayload":""}]}"#;
            let _ = write!(s, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
        });
        let list = super::connections(port).unwrap();
        assert_eq!(list.len(), 1);
        let c = &list[0];
        assert_eq!(c.host, "162.159.135.232");
        assert_eq!(c.port, 50007);
        assert_eq!(c.process, "Discord.exe");
        assert_eq!(c.outbound, "direct");
        assert_eq!(c.network, "udp");
        assert_eq!((c.up, c.down), (100, 2000));
        assert!(c.age_secs.unwrap() > 1_000_000);
    }
}
