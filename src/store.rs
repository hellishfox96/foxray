//! Где лежат файлы приложения и как сохраняются серверы/настройки.

use crate::link::{parse_many, Profile};
use crate::subs::Subscription;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SINGBOX_EXE: &str = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };

/// Папка приложения: где лежит sing-box. Ищем рядом с exe и на 3 уровня выше
/// (чтобы работало и из target\release при разработке). Если не нашли — папка exe.
pub fn app_dir() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let mut dir = Some(exe_dir.as_path());
    for _ in 0..4 {
        match dir {
            Some(d) if d.join(SINGBOX_EXE).exists() => return d.to_path_buf(),
            Some(d) => dir = d.parent(),
            None => break,
        }
    }
    exe_dir
}

pub fn singbox_path(dir: &Path) -> Option<PathBuf> {
    let p = dir.join(SINGBOX_EXE);
    p.exists().then_some(p)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub lan_bypass: bool,
    pub selected: Option<usize>,
    /// Подключаться сразу при запуске программы.
    pub connect_on_start: bool,
    pub subscriptions: Vec<Subscription>,
    /// Подсказку «я в трее» уже показывали.
    pub tray_hint_shown: bool,
    /// Кнопка «Закрыть»: 0 — в трей, 1 — в панель задач, 2 — выход.
    pub close_action: i32,
    /// Свой DNS-сервер включён.
    pub custom_dns: bool,
    /// Адрес своего DNS (хранится и при выключенном переключателе).
    pub dns_address: String,
    /// Zapret включён (только Windows).
    pub zapret_enabled: bool,
    /// Стратегия zapret — имя .bat без расширения: «general (ALT3)».
    pub zapret_strategy: String,
    /// Результаты последней проверки стратегий: стратегия → «7/7 · 180 мс».
    pub zapret_results: std::collections::BTreeMap<String, String>,
    /// Включать zapret при запуске Foxray (если был включён при выходе). Выкл — после запуска zapret выключен.
    pub zapret_autostart: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self { lan_bypass: true, selected: None, connect_on_start: false, subscriptions: Vec::new(), tray_hint_shown: false, close_action: 0, custom_dns: false, dns_address: String::new(), zapret_enabled: false, zapret_strategy: "general".into(), zapret_results: Default::default(), zapret_autostart: true }
    }
}

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn rules_path(&self) -> PathBuf {
        self.path("rules.json")
    }

    pub fn config_path(&self) -> PathBuf {
        self.path("config.json")
    }

    /// Серверы из profiles.json. При первом запуске импортирует links.txt, если он есть.
    pub fn load_profiles(&self) -> Vec<Profile> {
        if let Ok(text) = std::fs::read_to_string(self.path("profiles.json")) {
            if let Ok(list) = serde_json::from_str(&text) {
                return list;
            }
        }
        if let Ok(text) = std::fs::read_to_string(self.path("links.txt")) {
            let (list, _) = parse_many(&text);
            if !list.is_empty() {
                let _ = self.save_profiles(&list);
            }
            return list;
        }
        Vec::new()
    }

    pub fn save_profiles(&self, list: &[Profile]) -> std::io::Result<()> {
        write_atomic(&self.path("profiles.json"), &serde_json::to_string_pretty(list).unwrap())
    }

    pub fn load_settings(&self) -> AppSettings {
        std::fs::read_to_string(self.path("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save_settings(&self, s: &AppSettings) -> std::io::Result<()> {
        write_atomic(&self.path("settings.json"), &serde_json::to_string_pretty(s).unwrap())
    }
}

/// Запись через временный файл, чтобы не потерять данные при сбое.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}
