//! Готовые наборы доменов и IP-адресов (rule-set .srs).
//! В списках они записываются как `geosite:youtube` или `geoip:telegram`.
//! Файлы скачиваем сами в папку rulesets и подключаем как локальные —
//! так запуск sing-box не зависит от того, доступен ли GitHub в момент подключения.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Сервис в каталоге: что показать и какие записи добавить в список.
pub struct Service {
    pub name: &'static str,
    pub group: &'static str,
    pub entries: &'static [&'static str],
}

const fn s(name: &'static str, group: &'static str, entries: &'static [&'static str]) -> Service {
    Service { name, group, entries }
}

/// Каталог для выбора в интерфейсе. Всё, чего тут нет, можно вписать вручную:
/// `geosite:<имя>` — любой набор из github.com/SagerNet/sing-geosite (ветка rule-set),
/// `geoip:<код страны>` — из SagerNet/sing-geoip, `geoip:<сервис>` — из MetaCubeX/meta-rules-dat.
pub const CATALOG: &[Service] = &[
    s("Российские сайты", "Россия", &["geosite:category-ru", "geoip:ru"]),
    s("Госуслуги и гос. сайты", "Россия", &["geosite:category-gov-ru"]),
    s("ВКонтакте", "Россия", &["geosite:vk"]),
    s("Яндекс", "Россия", &["geosite:yandex"]),
    s("Mail.ru", "Россия", &["geosite:mailru"]),
    s("Ozon", "Россия", &["geosite:ozon"]),
    s("Wildberries", "Россия", &["geosite:wildberries"]),
    s("Авито", "Россия", &["geosite:avito"]),
    s("Кинопоиск", "Россия", &["geosite:kinopoisk"]),
    s("YouTube", "Видео и музыка", &["geosite:youtube"]),
    s("Twitch", "Видео и музыка", &["geosite:twitch"]),
    s("Netflix", "Видео и музыка", &["geosite:netflix", "geoip:netflix"]),
    s("Spotify", "Видео и музыка", &["geosite:spotify"]),
    s("SoundCloud", "Видео и музыка", &["geosite:soundcloud"]),
    s("Disney+", "Видео и музыка", &["geosite:disney"]),
    s("HBO", "Видео и музыка", &["geosite:hbo"]),
    s("Prime Video", "Видео и музыка", &["geosite:primevideo"]),
    s("Telegram", "Общение", &["geosite:telegram", "geoip:telegram"]),
    s("Discord", "Общение", &["geosite:discord"]),
    s("WhatsApp", "Общение", &["geosite:whatsapp"]),
    s("Signal", "Общение", &["geosite:signal"]),
    s("Viber", "Общение", &["geosite:viber"]),
    s("Zoom", "Общение", &["geosite:zoom"]),
    s("Slack", "Общение", &["geosite:slack"]),
    s("Instagram", "Соцсети", &["geosite:instagram"]),
    s("Facebook", "Соцсети", &["geosite:facebook", "geoip:facebook"]),
    s("X (Twitter)", "Соцсети", &["geosite:twitter", "geoip:twitter"]),
    s("TikTok", "Соцсети", &["geosite:tiktok"]),
    s("Reddit", "Соцсети", &["geosite:reddit"]),
    s("LinkedIn", "Соцсети", &["geosite:linkedin"]),
    s("Pinterest", "Соцсети", &["geosite:pinterest"]),
    s("Medium", "Соцсети", &["geosite:medium"]),
    s("Quora", "Соцсети", &["geosite:quora"]),
    s("Patreon", "Соцсети", &["geosite:patreon"]),
    s("ChatGPT", "Нейросети", &["geosite:openai"]),
    s("Claude", "Нейросети", &["geosite:anthropic"]),
    s("Gemini", "Нейросети", &["geosite:google-gemini"]),
    s("Perplexity", "Нейросети", &["geosite:perplexity"]),
    s("Grok", "Нейросети", &["geosite:xai"]),
    s("Steam", "Игры", &["geosite:steam"]),
    s("Epic Games", "Игры", &["geosite:epicgames"]),
    s("Xbox", "Игры", &["geosite:xbox"]),
    s("PlayStation", "Игры", &["geosite:playstation"]),
    s("Riot Games", "Игры", &["geosite:riot"]),
    s("EA", "Игры", &["geosite:ea"]),
    s("Ubisoft", "Игры", &["geosite:ubisoft"]),
    s("Blizzard", "Игры", &["geosite:blizzard"]),
    s("Roblox", "Игры", &["geosite:roblox"]),
    s("Все игровые сервисы", "Игры", &["geosite:category-games"]),
    s("Google", "Работа и сервисы", &["geosite:google", "geoip:google"]),
    s("Microsoft", "Работа и сервисы", &["geosite:microsoft"]),
    s("Apple", "Работа и сервисы", &["geosite:apple"]),
    s("GitHub", "Работа и сервисы", &["geosite:github"]),
    s("Docker", "Работа и сервисы", &["geosite:docker"]),
    s("JetBrains", "Работа и сервисы", &["geosite:jetbrains"]),
    s("Notion", "Работа и сервисы", &["geosite:notion"]),
    s("Figma", "Работа и сервисы", &["geosite:figma"]),
    s("Canva", "Работа и сервисы", &["geosite:canva"]),
    s("Dropbox", "Работа и сервисы", &["geosite:dropbox"]),
    s("MEGA", "Работа и сервисы", &["geosite:mega"]),
    s("Proton Mail", "Работа и сервисы", &["geosite:protonmail"]),
    s("Википедия", "Работа и сервисы", &["geosite:wikimedia"]),
    s("Cloudflare", "Работа и сервисы", &["geosite:cloudflare", "geoip:cloudflare"]),
    s("Реклама и трекеры", "Прочее", &["geosite:category-ads-all"]),
    s("Tor Project", "Прочее", &["geosite:torproject"]),
    s("RuTracker", "Прочее", &["geosite:rutracker"]),
];

/// Сервис из каталога, к которому относится запись (для красивого названия).
pub fn service_of(entry: &str) -> Option<&'static Service> {
    let e = entry.trim().to_ascii_lowercase();
    CATALOG.iter().find(|s| s.entries.iter().any(|x| *x == e))
}

/// Имя набора допустимо: латиница, цифры, «-», «!», «@» (как в sing-geosite).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '!' | '@' | '_'))
}

/// Тег набора в конфиге sing-box: geosite-youtube, geoip-ru.
pub fn tag(kind: &str, name: &str) -> String {
    format!("{kind}-{}", name.to_ascii_lowercase())
}

/// Откуда качать набор по тегу.
pub fn url(tag: &str) -> Option<String> {
    if let Some(name) = tag.strip_prefix("geosite-") {
        return Some(format!("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{name}.srs"));
    }
    let name = tag.strip_prefix("geoip-")?;
    if name.len() == 2 {
        // страны — из sing-geoip
        Some(format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{name}.srs"))
    } else {
        // сервисы (telegram, google…) — в sing-geoip их нет
        Some(format!("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/{name}.srs"))
    }
}

pub fn set_path(dir: &Path, tag: &str) -> PathBuf {
    dir.join(format!("{tag}.srs"))
}

pub fn is_ready(dir: &Path, tag: &str) -> bool {
    set_path(dir, tag).exists()
}

/// Нет файла или он старше недели.
pub fn needs_update(dir: &Path, tag: &str) -> bool {
    std::fs::metadata(set_path(dir, tag))
        .and_then(|m| m.modified())
        .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() > Duration::from_secs(7 * 24 * 3600))
        .unwrap_or(true)
}

/// Скачать один набор (блокирующе — вызывать из фонового потока).
pub fn download(dir: &Path, tag: &str) -> Result<(), String> {
    let url = url(tag).ok_or_else(|| format!("{tag}: неизвестный набор"))?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let resp = agent.get(&url).call().map_err(|e| match e {
        ureq::Error::Status(404, _) => format!("{tag}: такого набора нет"),
        e => format!("{tag}: {e}"),
    })?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut bytes).map_err(|e| format!("{tag}: {e}"))?;
    if bytes.len() < 16 {
        return Err(format!("{tag}: пустой файл"));
    }
    let path = set_path(dir, tag);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}
