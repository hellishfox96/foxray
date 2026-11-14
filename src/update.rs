//! Обновление Foxray из выпусков (Releases) на GitHub.
//!
//! Репозиторий берётся из поля `repository` в Cargo.toml (https://github.com/<владелец>/<репозиторий>).
//! Выпуск собирает GitHub Actions (.github/workflows/release.yml) по метке vX.Y.Z и кладёт архивы:
//!   Foxray-X.Y.Z-windows-x64.zip       — Foxray/Foxray.exe, sing-box.exe, …
//!   Foxray-X.Y.Z-linux-x86_64.tar.gz   — foxray/foxray, sing-box, …
//! Обновление заменяет только программы (Foxray и sing-box); серверы, настройки и правила не трогает.
//! Работающий exe в Windows перезаписать нельзя, но можно переименовать: старый файл
//! становится *.old и удаляется при следующем запуске (cleanup_old).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// «владелец/репозиторий» из Cargo.toml. None — репозиторий не указан.
pub fn repo() -> Option<String> {
    let r = REPOSITORY.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = r.strip_prefix("https://github.com/")?;
    let mut parts = path.split('/');
    let (owner, name) = (parts.next()?, parts.next()?);
    if owner.is_empty() || name.is_empty() || owner == "OWNER" {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

/// «1.10.4» → [1, 10, 4]; «v0.7.0-beta» → [0, 7, 0].
fn parse_version(v: &str) -> Vec<u64> {
    v.trim()
        .trim_start_matches('v')
        .split(['.', '-', '+'])
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

/// a новее b?
pub fn newer(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (parse_version(a), parse_version(b));
    x.resize(3, 0);
    y.resize(3, 0);
    x > y
}

/// Имя архива этого выпуска для нашей системы.
pub fn asset_name(version: &str) -> Option<String> {
    let v = version.trim_start_matches('v');
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some(format!("Foxray-{v}-windows-x64.zip")),
        ("linux", "x86_64") => Some(format!("Foxray-{v}-linux-x86_64.tar.gz")),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Release {
    /// «0.7.0»
    pub version: String,
    /// Ссылка на архив для нашей системы.
    pub url: String,
    /// Описание выпуска (что нового).
    pub notes: String,
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(timeout)
        .user_agent(&format!("Foxray/{VERSION}"))
        .build()
}

/// Последний выпуск на GitHub.
pub fn latest() -> Result<Release, String> {
    let repo = repo().ok_or("в Cargo.toml не указан repository (https://github.com/…)")?;
    let v: serde_json::Value = agent(Duration::from_secs(20))
        .get(&format!("https://api.github.com/repos/{repo}/releases/latest"))
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => "на GitHub пока нет выпусков".to_string(),
            e => format!("GitHub не ответил: {e}"),
        })?
        .into_string()
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| format!("ответ GitHub не разобран: {e}")))?;
    let tag = v["tag_name"].as_str().ok_or("в ответе GitHub нет tag_name")?;
    let version = tag.trim_start_matches('v').to_string();
    let want = asset_name(&version).ok_or("для этой системы выпусков нет")?;
    let url = v["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(want.as_str())))
        .and_then(|x| x["browser_download_url"].as_str())
        .ok_or_else(|| format!("в выпуске {version} нет файла {want}"))?
        .to_string();
    let notes = v["body"].as_str().unwrap_or("").trim().to_string();
    Ok(Release { version, url, notes })
}

/// Выпуск для списка «Что нового».
#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseInfo {
    pub version: String,
    /// «15.11.2026»
    pub date: String,
    /// Пункты списка изменений.
    pub notes: Vec<String>,
}

/// Последние выпуски (новые сверху) — для страницы «Обновление».
pub fn releases() -> Result<Vec<ReleaseInfo>, String> {
    let repo = repo().ok_or("в Cargo.toml не указан repository")?;
    let v: serde_json::Value = agent(Duration::from_secs(20))
        .get(&format!("https://api.github.com/repos/{repo}/releases?per_page=10"))
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub не ответил: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))?;
    Ok(v.as_array()
        .into_iter()
        .flatten()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false) && !r["prerelease"].as_bool().unwrap_or(false))
        .filter_map(|r| {
            let version = r["tag_name"].as_str()?.trim_start_matches('v').to_string();
            let date = r["published_at"].as_str().map(iso_date).unwrap_or_default();
            Some(ReleaseInfo { version, date, notes: release_notes(r["body"].as_str().unwrap_or("")) })
        })
        .collect())
}

/// «2026-11-15T10:20:00Z» → «15.11.2026».
fn iso_date(s: &str) -> String {
    let d = s.get(..10).unwrap_or("");
    let p: Vec<&str> = d.split('-').collect();
    if p.len() == 3 { format!("{}.{}.{}", p[2], p[1], p[0]) } else { String::new() }
}

/// Описание выпуска (Markdown) → пункты: строки «- …» / «* …»; служебное GitHub («Full Changelog»,
/// заголовки, «by @… in #…») убираем. Нет пунктов — берём обычные строки.
pub fn release_notes(body: &str) -> Vec<String> {
    let clean = |l: &str| -> Option<String> {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') || l.contains("Full Changelog") || l.starts_with("**Full") {
            return None;
        }
        let l = l.split(" by @").next().unwrap_or(l).trim();
        Some(l.replace("**", "").replace('`', ""))
    };
    let bullets: Vec<String> = body
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).and_then(clean)
        })
        .collect();
    if !bullets.is_empty() {
        return bullets;
    }
    body.lines().filter_map(clean).collect()
}

/// Какие файлы берём из архива: (имя в архиве, куда положить рядом с Foxray).
fn wanted(exe: &Path) -> Vec<(&'static str, PathBuf)> {
    let dir = exe.parent().unwrap_or(Path::new("."));
    if cfg!(windows) {
        vec![("Foxray.exe", exe.to_path_buf()), ("sing-box.exe", dir.join("sing-box.exe"))]
    } else {
        vec![("foxray", exe.to_path_buf()), ("sing-box", dir.join("sing-box"))]
    }
}

/// Скачать выпуск и разложить новые файлы. После этого Foxray нужно перезапустить.
/// VPN (sing-box) перед этим должен быть остановлен — его файл тоже меняется.
pub fn install(rel: &Release) -> Result<(), String> {
    let resp = agent(Duration::from_secs(300)).get(&rel.url).call().map_err(|e| format!("не скачалось: {e}"))?;
    let mut data = Vec::new();
    resp.into_reader()
        .take(200 * 1024 * 1024)
        .read_to_end(&mut data)
        .map_err(|e| format!("не скачалось: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let files = extract(&data, &wanted(&exe))?;
    if !files.iter().any(|(dst, _)| *dst == exe) {
        return Err("в архиве нет самого Foxray".into());
    }
    for (dst, bytes) in files {
        replace(&dst, &bytes)?;
    }
    Ok(())
}

/// Достать нужные файлы из архива (по имени файла, папка внутри архива не важна).
fn extract(data: &[u8], wanted: &[(&str, PathBuf)]) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let pick = |name: &str| -> Option<PathBuf> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        wanted.iter().find(|(n, _)| *n == base).map(|(_, p)| p.clone())
    };
    if data.starts_with(b"PK") {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|e| format!("архив повреждён: {e}"))?;
        for i in 0..zip.len() {
            let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
            if f.is_dir() {
                continue;
            }
            if let Some(dst) = pick(f.name()) {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
                out.push((dst, buf));
            }
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            let gz = flate2::read::GzDecoder::new(data);
            let mut ar = tar::Archive::new(gz);
            for e in ar.entries().map_err(|e| format!("архив повреждён: {e}"))? {
                let mut e = e.map_err(|e| e.to_string())?;
                let name = e.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
                if let Some(dst) = pick(&name) {
                    let mut buf = Vec::new();
                    e.read_to_end(&mut buf).map_err(|e| e.to_string())?;
                    out.push((dst, buf));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        return Err("неизвестный формат архива".into());
    }
    Ok(out)
}

/// Заменить файл, даже если он сейчас запущен: старый → *.old, новый — на его место.
fn replace(dst: &Path, bytes: &[u8]) -> Result<(), String> {
    let new = dst.with_extension("new");
    std::fs::write(&new, bytes).map_err(|e| format!("{}: {e}", new.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755));
    }
    if dst.exists() {
        let old = old_path(dst);
        let _ = std::fs::remove_file(&old);
        std::fs::rename(dst, &old).map_err(|e| format!("{} занят: {e}", dst.display()))?;
    }
    std::fs::rename(&new, dst).map_err(|e| format!("{}: {e}", dst.display()))
}

fn old_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

/// При запуске: удалить *.old, оставшиеся после обновления.
pub fn cleanup_old() {
    let Ok(exe) = std::env::current_exe() else { return };
    for (_, p) in wanted(&exe) {
        let old = old_path(&p);
        if old.exists() {
            let _ = std::fs::remove_file(old);
        }
    }
}

/// Запустить новую версию (она дождётся, пока эта закроется).
pub fn restart() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--after-update");
    crate::sys::hide_window(&mut cmd);
    cmd.spawn().map(|_| ()).map_err(|e| format!("не удалось перезапустить: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(newer("0.7.0", "0.6.0"));
        assert!(newer("v0.10.0", "0.9.9"));
        assert!(newer("1.0", "0.99.99"));
        assert!(!newer("0.6.0", "0.6.0"));
        assert!(!newer("0.6.0-beta", "0.6.0"));
        assert!(!newer("0.5.9", "0.6.0"));
    }

    #[test]
    fn notes() {
        let body = "## Что нового\n- Вкладка «Серверы» в новом стиле\n* **Избранное** by @x in #3\n\n**Full Changelog**: https://…";
        assert_eq!(release_notes(body), vec!["Вкладка «Серверы» в новом стиле", "Избранное"]);
        assert_eq!(release_notes("**Full Changelog**: https://github.com/x/y/commits/v0.6.0"), Vec::<String>::new());
        assert_eq!(release_notes("Первый выпуск"), vec!["Первый выпуск"]);
        assert_eq!(iso_date("2026-11-15T10:20:00Z"), "15.11.2026");
    }

    #[test]
    fn repo_parse() {
        // repo() читает Cargo.toml; здесь проверяем только, что не падает.
        let _ = repo();
    }

    #[test]
    fn zip_extract_and_replace() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("foxray-update-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(if cfg!(windows) { "Foxray.exe" } else { "foxray" });
        std::fs::write(&exe, b"old").unwrap();
        // архив как у выпуска: папка внутри + лишние файлы
        let mut buf = Vec::new();
        {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let o = zip::write::SimpleFileOptions::default();
            let (n1, n2) = if cfg!(windows) { ("Foxray/Foxray.exe", "Foxray/sing-box.exe") } else { ("foxray/foxray", "foxray/sing-box") };
            z.start_file(n1, o).unwrap();
            z.write_all(b"new-foxray").unwrap();
            z.start_file(n2, o).unwrap();
            z.write_all(b"new-singbox").unwrap();
            z.start_file("Foxray/readme.txt", o).unwrap();
            z.write_all(b"x").unwrap();
            z.finish().unwrap();
        }
        let files = extract(&buf, &wanted(&exe)).unwrap();
        assert_eq!(files.len(), 2);
        for (dst, bytes) in files {
            replace(&dst, &bytes).unwrap();
        }
        assert_eq!(std::fs::read(&exe).unwrap(), b"new-foxray");
        assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"old");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
