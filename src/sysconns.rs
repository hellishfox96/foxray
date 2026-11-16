//! Открытые соединения из системы — для страницы «Соединения», когда VPN выключен
//! (sing-box не запущен, а zapret работает сам по себе). Без доменов и трафика:
//! программа, адрес и порт.
//!
//! Linux: /proc/net/{tcp,tcp6,udp,udp6} + сокеты из /proc/<pid>/fd (видны свои процессы).
//! Windows: `netstat -ano` + `tasklist` (имена по PID).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub struct SysConn {
    /// "tcp" / "udp"
    pub network: String,
    pub local_port: u16,
    /// Куда подключено. None — UDP-сокет без постоянного адреса (адрес в каждом пакете свой).
    pub remote: Option<(IpAddr, u16)>,
    /// TCP ещё подключается (SYN отправлен, ответа нет).
    pub connecting: bool,
    pub pid: u32,
    /// Имя для показа: «Discord», «DeadByDaylight-Win64-Shipping.exe».
    pub process: String,
    /// Имя исполняемого файла — его видит маршрутизация (в Linux под Wine это «wine64-preloader»).
    pub exe: String,
}

impl SysConn {
    /// Ключ соединения (для «сколько открыто» между опросами).
    pub fn key(&self) -> String {
        match self.remote {
            Some((ip, p)) => format!("{}|{}|{}|{ip}:{p}", self.pid, self.network, self.local_port),
            None => format!("{}|{}|{}|-", self.pid, self.network, self.local_port),
        }
    }
}

fn useful(ip: &IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified())
}

// ================================================================ Linux

#[cfg(target_os = "linux")]
pub fn list() -> Vec<SysConn> {
    let owners = socket_owners();
    let mut out = Vec::new();
    for (file, net) in [("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/net/{file}")) else { continue };
        for line in text.lines().skip(1) {
            let Some(e) = parse_proc_line(line) else { continue };
            let Some(owner) = owners.get(&e.inode) else { continue }; // чужой процесс или ядро
            let (connecting, keep) = match (net, e.state) {
                ("tcp", 0x01) => (false, true), // ESTABLISHED
                ("tcp", 0x02) => (true, true),  // SYN_SENT
                ("udp", _) => (false, true),
                _ => (false, false),
            };
            if !keep {
                continue;
            }
            let remote = Some(e.remote).filter(|(ip, port)| *port != 0 && useful(ip));
            if net == "tcp" && remote.is_none() {
                continue;
            }
            if remote.is_none() && e.local.0.is_loopback() {
                continue; // локальный UDP (DNS-заглушки и т. п.)
            }
            out.push(SysConn {
                network: net.into(),
                local_port: e.local.1,
                remote,
                connecting,
                pid: owner.0,
                process: owner.1.clone(),
                exe: owner.2.clone(),
            });
        }
    }
    out
}

#[cfg(target_os = "linux")]
struct ProcEntry {
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    state: u8,
    inode: u64,
}

/// Строка /proc/net/tcp: «sl local rem st tx:rx tr:tm retr uid timeout inode …».
#[cfg(target_os = "linux")]
fn parse_proc_line(line: &str) -> Option<ProcEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 10 {
        return None;
    }
    Some(ProcEntry {
        local: parse_hex_addr(f[1])?,
        remote: parse_hex_addr(f[2])?,
        state: u8::from_str_radix(f[3], 16).ok()?,
        inode: f[9].parse().ok()?,
    })
}

/// «0100007F:1F90» → 127.0.0.1:8080; IPv6 — 4 слова по 32 бита, каждое в порядке хоста.
pub fn parse_hex_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.swap_bytes())),
        32 => {
            let mut b = [0u8; 16];
            for w in 0..4 {
                let v = u32::from_str_radix(&a[w * 8..w * 8 + 8], 16).ok()?;
                b[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// inode сокета → (PID, имя для показа, имя исполняемого файла). Только свои процессы.
#[cfg(target_os = "linux")]
fn socket_owners() -> HashMap<u64, (u32, String, String)> {
    let mut map = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return map };
    for e in dir.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else { continue };
        let mut names: Option<(String, String)> = None;
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else { continue };
            let l = link.to_string_lossy();
            let Some(inode) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')).and_then(|x| x.parse::<u64>().ok()) else {
                continue;
            };
            let n = names.get_or_insert_with(|| process_names(pid)).clone();
            map.insert(inode, (pid, n.0, n.1));
        }
    }
    map
}

/// (имя для показа, имя исполняемого файла). Под Wine/Proton файл — «wine64-preloader»,
/// а показываем имя игры из командной строки («Z:\…\Game.exe» → «Game.exe»).
#[cfg(target_os = "linux")]
fn process_names(pid: u32) -> (String, String) {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().trim_end_matches(" (deleted)").to_string()))
        .or_else(|| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()))
        .unwrap_or_default();
    let mut shown = exe.clone();
    if exe.starts_with("wine") {
        if let Ok(cmd) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            if let Some(arg0) = cmd.split(|b| *b == 0).next() {
                let a = String::from_utf8_lossy(arg0);
                let base = a.rsplit(['\\', '/']).next().unwrap_or("").trim();
                if !base.is_empty() && !base.starts_with("wine") {
                    shown = base.to_string();
                }
            }
        }
    }
    (shown, exe)
}

// ================================================================ Windows

#[cfg(windows)]
pub fn list() -> Vec<SysConn> {
    use std::process::Command;
    let mut cmd = Command::new("netstat");
    cmd.arg("-ano");
    crate::sys::hide_window(&mut cmd);
    let Ok(out) = cmd.output() else { return Vec::new() };
    let text = crate::sys::decode_oem(&out.stdout);
    let mut rows = parse_netstat(&text);
    let names = pid_names();
    rows.retain_mut(|c| match names.get(&c.pid) {
        Some(n) => {
            c.process = n.clone();
            c.exe = n.clone();
            true
        }
        None => false,
    });
    rows
}

/// PID → имя программы («Discord.exe») из `tasklist`.
#[cfg(windows)]
fn pid_names() -> HashMap<u32, String> {
    let mut cmd = std::process::Command::new("tasklist");
    cmd.args(["/FO", "CSV", "/NH"]);
    crate::sys::hide_window(&mut cmd);
    let Ok(out) = cmd.output() else { return HashMap::new() };
    crate::sys::decode_oem(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split("\",\"").map(|x| x.trim_matches('"')).collect();
            Some((f.get(1)?.parse().ok()?, f.first()?.to_string()))
        })
        .collect()
}

/// Разбор `netstat -ano`. Состояние не сравниваем по тексту (в разных языках Windows оно
/// может отличаться): TCP с адресом назначения и PID ≠ 0 — открытое соединение,
/// «SYN» в состоянии — ещё подключается. UDP — сокеты без адреса назначения.
pub fn parse_netstat(text: &str) -> Vec<SysConn> {
    let addr = |s: &str| -> Option<(IpAddr, u16)> {
        let (a, p) = s.rsplit_once(':')?;
        let a = a.trim_start_matches('[').trim_end_matches(']');
        let a = a.split('%').next()?; // fe80::1%12
        Some((a.parse().ok()?, p.parse().ok()?))
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let net = match f[0] {
            "TCP" => "tcp",
            "UDP" => "udp",
            _ => continue,
        };
        let Some(pid) = f.last().and_then(|p| p.parse::<u32>().ok()).filter(|p| *p != 0) else { continue };
        let Some(local) = addr(f[1]) else { continue };
        let remote = addr(f[2]).filter(|(ip, port)| *port != 0 && useful(ip));
        if net == "tcp" && remote.is_none() {
            continue; // слушает или TIME_WAIT
        }
        if net == "udp" && local.0.is_loopback() {
            continue;
        }
        let connecting = net == "tcp" && f.len() >= 5 && f[3].contains("SYN");
        out.push(SysConn {
            network: net.into(),
            local_port: local.1,
            remote,
            connecting,
            pid,
            process: String::new(),
            exe: String::new(),
        });
    }
    out
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn list() -> Vec<SysConn> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_addresses() {
        assert_eq!(parse_hex_addr("0100007F:1F90"), Some(("127.0.0.1".parse().unwrap(), 8080)));
        assert_eq!(parse_hex_addr("E8879FA2:01BB"), Some(("162.159.135.232".parse().unwrap(), 443)));
        // ::ffff:162.159.135.232 → IPv4
        assert_eq!(
            parse_hex_addr("0000000000000000FFFF0000E8879FA2:01BB"),
            Some(("162.159.135.232".parse().unwrap(), 443))
        );
        // 2a00:1450:4010:c05::64
        assert_eq!(parse_hex_addr("5014002A050C10400000000064000000:01BB"), Some(("2a00:1450:4010:c05::64".parse().unwrap(), 443)));
    }

    #[test]
    fn netstat_lines() {
        let t = "\nАктивные подключения\n\n  Имя    Локальный адрес        Внешний адрес          Состояние       PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1000\n  TCP    192.168.1.5:50123      162.159.135.232:443    ESTABLISHED     4321\n  TCP    192.168.1.5:50124      18.192.44.10:7777      SYN_SENT        555\n  TCP    192.168.1.5:50125      1.1.1.1:443            TIME_WAIT       0\n  TCP    [2a00::5]:50126        [2a00:1450::64]:443    ESTABLISHED     4321\n  UDP    0.0.0.0:50003          *:*                                    4321\n  UDP    127.0.0.1:53           *:*                                    77\n";
        let r = parse_netstat(t);
        assert_eq!(r.len(), 4, "{r:?}");
        assert_eq!(r[0].remote, Some(("162.159.135.232".parse().unwrap(), 443)));
        assert_eq!(r[0].pid, 4321);
        assert!(!r[0].connecting);
        assert!(r[1].connecting);
        assert_eq!(r[2].remote.unwrap().0, "2a00:1450::64".parse::<IpAddr>().unwrap());
        assert_eq!((r[3].network.as_str(), r[3].remote, r[3].local_port), ("udp", None, 50003));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_socket_is_listed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        // соединение на 127.0.0.1 не показываем, но и падать ничего не должно
        let all = list();
        assert!(all.iter().all(|c| c.remote.map_or(true, |(ip, _)| !ip.is_loopback())));
    }
}
