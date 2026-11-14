//! Только одна копия Foxray: вторая передаёт команду первой и выходит.
//! Связь — через локальный порт (доступен только с этого компьютера).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const ADDR: &str = "127.0.0.1:47811";

/// Отправить команду уже запущенной копии. true — копия есть и команду приняла.
pub fn send(cmd: &str) -> bool {
    let Ok(addr) = ADDR.parse() else { return false };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    if writeln!(s, "foxray {cmd}").is_err() {
        return false;
    }
    let mut reply = String::new();
    let _ = BufReader::new(s).read_line(&mut reply);
    reply.trim() == "ok"
}

/// Стать «главной» копией и слушать команды. Ошибка — порт занят чем-то другим.
pub fn listen(on_cmd: impl Fn(String) + Send + 'static) -> std::io::Result<()> {
    let l = TcpListener::bind(ADDR)?;
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
            let mut line = String::new();
            let mut r = BufReader::new(&conn);
            if r.read_line(&mut line).is_ok() {
                if let Some(cmd) = line.trim().strip_prefix("foxray ") {
                    let _ = (&conn).write_all(b"ok\n");
                    on_cmd(cmd.to_string());
                }
            }
        }
    });
    Ok(())
}
