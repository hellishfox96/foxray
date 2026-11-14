//! Системные мелочи: скрытые окна консоли, список процессов, автозапуск.

use std::process::Command;

pub fn hide_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Вывод консольных программ Windows на русской системе — в кодировке CP866.
pub fn decode_oem(bytes: &[u8]) -> String {
    if !cfg!(windows) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    bytes
        .iter()
        .map(|&b| match b {
            0x00..=0x7F => b as char,
            0x80..=0xAF => char::from_u32(0x0410 + (b as u32 - 0x80)).unwrap(),
            0xE0..=0xEF => char::from_u32(0x0440 + (b as u32 - 0xE0)).unwrap(),
            0xF0 => 'Ё',
            0xF1 => 'ё',
            _ => ' ',
        })
        .collect()
}

/// Имена запущенных программ (без повторов, по алфавиту).
pub fn running_processes() -> Vec<String> {
    let mut names: Vec<String> = if cfg!(windows) {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FO", "CSV", "/NH"]);
        hide_window(&mut cmd);
        cmd.output()
            .map(|o| {
                decode_oem(&o.stdout)
                    .lines()
                    .filter_map(|l| l.split("\",\"").next())
                    .map(|n| n.trim_matches('"').to_string())
                    .filter(|n| n.to_ascii_lowercase().ends_with(".exe"))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        // Linux: имя исполняемого файла из /proc/<pid>/exe — именно его сравнивает sing-box.
        // Чужие и системные процессы (ссылка не читается) пропускаем.
        std::fs::read_dir("/proc")
            .map(|dir| {
                dir.flatten()
                    .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
                    .filter_map(|e| std::fs::read_link(e.path().join("exe")).ok())
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().trim_end_matches(" (deleted)").to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    // Системный мусор, который никто не захочет маршрутизировать.
    const SKIP: &[&str] = &[
        "svchost.exe", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "conhost.exe", "sihost.exe",
        "taskhostw.exe", "runtimebroker.exe", "dllhost.exe", "ctfmon.exe", "searchindexer.exe",
        "sing-box.exe", "foxray-gui.exe", "foxray.exe", "tasklist.exe", "wmiprvse.exe",
        "system idle process", "memory compression", "smartscreen.exe", "audiodg.exe",
        // Linux
        "sing-box", "foxray-gui", "foxray", "systemd", "dbus-daemon", "dbus-broker", "pipewire",
        "wireplumber", "pulseaudio", "xdg-desktop-portal", "at-spi-bus-launcher", "at-spi2-registryd",
        "gvfsd", "bash", "sh", "zsh", "fish", "sudo",
    ];
    names.retain(|n| !n.is_empty() && !SKIP.contains(&n.to_ascii_lowercase().as_str()));
    names.sort_by_key(|n| n.to_ascii_lowercase());
    names.dedup_by_key(|n| n.to_ascii_lowercase());
    names
}

/// Автозапуск.
/// Windows — через Планировщик заданий: только так приложение с правами
/// администратора стартует при входе в систему без окна UAC.
/// Linux — файл foxray.desktop в ~/.config/autostart (стандарт XDG, понимают GNOME, KDE, XFCE…).
pub mod autostart {
    #[cfg(windows)]
    use super::*;

    #[cfg(windows)]
    const TASK: &str = "Foxray";

    #[cfg(windows)]
    pub fn is_enabled() -> bool {
        let mut cmd = Command::new("schtasks");
        cmd.args(["/Query", "/TN", TASK]);
        hide_window(&mut cmd);
        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }

    #[cfg(windows)]
    pub fn set(enabled: bool) -> Result<(), String> {
        let mut cmd = Command::new("schtasks");
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let tr = format!("\"{}\" --minimized", exe.display());
            cmd.args(["/Create", "/F", "/TN", TASK, "/SC", "ONLOGON", "/RL", "HIGHEST", "/TR", &tr]);
        } else {
            cmd.args(["/Delete", "/F", "/TN", TASK]);
        }
        hide_window(&mut cmd);
        let out = cmd.output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(decode_oem(&out.stderr).trim().to_string())
        }
    }

    #[cfg(not(windows))]
    fn desktop_file() -> Option<std::path::PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))?;
        Some(base.join("autostart").join("foxray.desktop"))
    }

    #[cfg(not(windows))]
    pub fn is_enabled() -> bool {
        desktop_file().is_some_and(|p| p.exists())
    }

    #[cfg(not(windows))]
    pub fn set(enabled: bool) -> Result<(), String> {
        let path = desktop_file().ok_or("не найдена домашняя папка")?;
        if !enabled {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            };
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = exe.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
        let text = format!(
            "[Desktop Entry]\nType=Application\nName=Foxray\nComment=VPN-клиент\nExec=\"{exe}\" --minimized\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        );
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, text).map_err(|e| e.to_string())
    }
}

/// Права на TUN в Linux. Foxray работает от обычного пользователя, а sing-box
/// получает право управлять сетью (cap_net_admin) один раз — через `pkexec setcap`,
/// система спросит пароль. После замены файла sing-box право нужно выдать заново,
/// поэтому проверяем перед каждым подключением.
#[cfg(target_os = "linux")]
pub mod tun_rights {
    use super::*;
    use std::path::Path;

    pub const CAPS: &str = "cap_net_admin,cap_net_bind_service,cap_net_raw+ep";

    fn is_root() -> bool {
        // Владелец /proc/self — это мы сами.
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
    }

    fn find(tool: &str) -> Option<std::path::PathBuf> {
        ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
    }

    /// Уже есть права? None — проверить нечем (нет getcap), пробуем как есть.
    pub fn has(singbox: &Path) -> Option<bool> {
        if is_root() {
            return Some(true);
        }
        let out = Command::new(find("getcap")?).arg(singbox).output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).contains("cap_net_admin"))
    }

    /// Выдать права (покажет системное окно ввода пароля).
    pub fn grant(singbox: &Path) -> Result<(), String> {
        let manual = format!("sudo setcap {CAPS} \"{}\"", singbox.display());
        let setcap = find("setcap").ok_or_else(|| format!("нет программы setcap (пакет libcap2-bin). Потом: {manual}"))?;
        let pkexec = find("pkexec").ok_or_else(|| format!("нет pkexec — выполните в терминале: {manual}"))?;
        let out = Command::new(pkexec)
            .arg(setcap)
            .arg(CAPS)
            .arg(singbox)
            .output()
            .map_err(|e| e.to_string())?;
        match out.status.code() {
            Some(0) => Ok(()),
            Some(126) | Some(127) => Err("пароль не введён — без прав VPN (TUN) не запустится".into()),
            _ => Err(format!(
                "не удалось выдать права: {}. Вручную: {manual}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }
}
