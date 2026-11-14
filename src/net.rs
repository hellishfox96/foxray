//! Пинг серверов.

use crate::link::{Profile, Proto};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Задержка до сервера в мс.
/// VLESS — время TCP-подключения к порту; Hysteria2 (UDP) — системный ping до хоста.
pub fn ping(p: &Profile) -> Result<u32, String> {
    match p.proto {
        Proto::Vless(_) => tcp_ping(&p.server, p.port),
        Proto::Hysteria2(_) => icmp_ping(&p.server),
    }
}

fn tcp_ping(host: &str, port: u16) -> Result<u32, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| "адрес не найден".to_string())?
        .next()
        .ok_or("адрес не найден")?;
    let t = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|_| "нет ответа".to_string())?;
    Ok((t.elapsed().as_millis() as u32).max(1))
}

fn icmp_ping(host: &str) -> Result<u32, String> {
    let mut cmd = std::process::Command::new("ping");
    if cfg!(windows) {
        cmd.args(["-n", "1", "-w", "3000", host]);
    } else {
        cmd.args(["-c", "1", "-W", "3", host]);
    }
    crate::sys::hide_window(&mut cmd);
    let out = cmd.output().map_err(|e| format!("ping: {e}"))?;
    // Вывод зависит от языка Windows: "time=23ms", "время=23мс", "time<1ms".
    let text = String::from_utf8_lossy(&out.stdout).to_string()
        + &crate::sys::decode_oem(&out.stdout);
    parse_ping_ms(&text).ok_or_else(|| "нет ответа".to_string())
}

pub fn parse_ping_ms(text: &str) -> Option<u32> {
    for marker in ["time=", "time<", "время=", "время<", "Zeit=", "temps="] {
        if let Some(i) = text.find(marker) {
            let rest = &text[i + marker.len()..];
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(v) = num.parse::<f32>() {
                return Some(v.round().max(1.0) as u32);
            }
        }
    }
    None
}
