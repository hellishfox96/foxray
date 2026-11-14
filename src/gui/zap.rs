//! Zapret в окне: включение, выбор и подбор стратегии, скачивание сборки.

use super::*;
use foxray::zapret;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct ZapState {
    /// Запущенный нами winws.exe.
    winws: Option<zapret::Winws>,
    /// Адреса VPN-сервера — zapret их не трогает.
    ips: Vec<IpAddr>,
    /// Идёт подбор стратегии (флаг отмены).
    cancel: Option<Arc<AtomicBool>>,
    /// Какая стратегия сейчас проверяется.
    testing_id: Option<String>,
    /// Подбор: какая по счёту стратегия проверяется и сколько всего, имя проверяемой.
    test_pos: (usize, usize),
    test_title: String,
    progress: String,
    status: String,
    status_bad: bool,
    /// Идёт скачивание.
    busy: bool,
    /// Последняя версия на GitHub (если уже узнали).
    latest: Option<String>,
    /// Linux: ждём пароль для помощника с правами root.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    asking: bool,
    /// Linux: пароль не ввели — сами больше не спрашиваем (до явного действия).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    refused: bool,
}

/// Linux: zapret работает через помощника с правами root (pkexec, пароль — раз за запуск Foxray).
/// true — помощник готов, можно запускать. false — спрашиваем пароль в фоне,
/// по готовности снова вызовем `then`.
fn root_ready(ui: &AppWindow, then: fn(&AppWindow)) -> bool {
    #[cfg(target_os = "linux")]
    {
        if foxray::nfq::helper_ready() {
            return true;
        }
        let skip = with_app(|app| {
            let skip = app.zap.asking || app.zap.refused;
            if !skip {
                app.zap.asking = true;
            }
            skip
        });
        if skip {
            if with_app(|app| app.zap.refused) {
                set_status("Нет прав root — выключи и снова включи zapret, чтобы ввести пароль.", true);
                refresh(ui);
            }
            return false;
        }
        set_status("Нужен пароль администратора: nfqws и правила nftables работают от root.", false);
        refresh(ui);
        let w = ui.as_weak();
        std::thread::spawn(move || {
            let res = foxray::nfq::helper_start();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = w.upgrade() else { return };
                with_app(|app| {
                    app.zap.asking = false;
                    app.zap.refused = res.is_err();
                });
                match res {
                    Ok(()) => {
                        set_status("", false);
                        then(&ui);
                    }
                    Err(e) => {
                        set_status(e, true);
                        refresh(&ui);
                    }
                }
            });
        });
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ui, then);
        true
    }
}

fn zdir() -> PathBuf {
    with_app(|app| zapret::dir(&app.store.dir))
}

fn set_status(text: impl Into<String>, bad: bool) {
    with_app(|app| {
        app.zap.status = text.into();
        app.zap.status_bad = bad;
    });
}

/// «7/7 · 180 мс» → (7, 7).
fn parse_score(s: &str) -> Option<(usize, usize)> {
    let head = s.split_whitespace().next()?;
    let (a, b) = head.split_once('/')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn score_state(s: &str) -> i32 {
    match parse_score(s) {
        Some((ok, total)) if ok == total && total > 0 => 1,
        Some((0, _)) => 3,
        Some(_) => 2,
        None if s.starts_with("ошибка") => 3,
        None => 0,
    }
}

pub(super) fn setup(ui: &AppWindow) {
    ui.set_zapret_supported(zapret::supported());
    if !zapret::supported() {
        return;
    }

    // «Включать при запуске» выключено — после запуска zapret выключен (до явного включения).
    with_app(|app| {
        if !app.settings.zapret_autostart && app.settings.zapret_enabled {
            app.settings.zapret_enabled = false;
            let _ = app.store.save_settings(&app.settings);
        }
    });

    let w = ui.as_weak();
    ui.on_zapret_autostart_toggled(move |on| {
        let ui = w.unwrap();
        with_app(|app| {
            app.settings.zapret_autostart = on;
            let _ = app.store.save_settings(&app.settings);
        });
        refresh(&ui);
    });

    let w = ui.as_weak();
    ui.on_zapret_toggled(move |on| {
        let ui = w.unwrap();
        with_app(|app| {
            app.settings.zapret_enabled = on;
            app.zap.refused = false; // явное действие — можно снова спросить пароль (Linux)
            let _ = app.store.save_settings(&app.settings);
        });
        if on && !zapret::installed(&zdir()) {
            set_status("Сначала скачай сборку zapret — кнопка «Скачать» выше.", true);
        }
        apply(&ui);
        // Списки zapret идут «напрямую» только при включённом zapret — нужен новый конфиг.
        if with_app(|app| app.runner.is_some()) {
            reconnect(&ui);
        }
        refresh(&ui);
    });

    let w = ui.as_weak();
    ui.on_zapret_select(move |i| {
        let ui = w.unwrap();
        let Some(s) = zapret::strategies(&zdir()).into_iter().nth(i as usize) else { return };
        with_app(|app| {
            app.settings.zapret_strategy = s.id.clone();
            let _ = app.store.save_settings(&app.settings);
        });
        if with_app(|app| app.settings.zapret_enabled) {
            apply(&ui);
            show_toast(&ui, format!("Стратегия {}", s.title));
        }
        refresh(&ui);
    });

    let w = ui.as_weak();
    ui.on_zapret_download(move || download(&w.unwrap()));

    let w = ui.as_weak();
    ui.on_zapret_test(move || start_test(&w.unwrap()));

    ui.on_zapret_cancel_test(move || {
        with_app(|app| {
            if let Some(c) = &app.zap.cancel {
                c.store(true, Ordering::SeqCst);
                app.zap.progress = "Останавливаю проверку…".into();
            }
        });
    });

    ui.on_zapret_open_folder(move || {
        let d = zdir();
        let _ = std::fs::create_dir_all(&d);
        open_path(&d, false);
    });

    // Есть ли обновление сборки — тихо, в фоне.
    if zapret::installed(&zdir()) {
        let w = ui.as_weak();
        std::thread::spawn(move || {
            if let Ok(v) = zapret::latest_version() {
                let _ = slint::invoke_from_event_loop(move || {
                    with_app(|app| app.zap.latest = Some(v));
                    if let Some(ui) = w.upgrade() {
                        refresh(&ui);
                    }
                });
            }
        });
    }
    refresh(ui);
}

/// Всё, что видно на странице zapret и в строке настроек.
pub(super) fn refresh(ui: &AppWindow) {
    if !zapret::supported() {
        return;
    }
    let dir = zdir();
    let installed = zapret::installed(&dir);
    let version = zapret::version(&dir);
    let list = zapret::strategies(&dir);
    with_app(|app| {
        let z = &app.zap;
        let running = z.winws.is_some();
        let sel = &app.settings.zapret_strategy;
        let sel_title = zapret::title_of(sel);
        ui.set_zapret_enabled(app.settings.zapret_enabled);
        ui.set_zapret_autostart(app.settings.zapret_autostart);
        ui.set_zapret_installed(installed);
        let update = matches!((&z.latest, &version), (Some(l), Some(v)) if l != v);
        ui.set_zapret_update(update);
        ui.set_zapret_info(
            match (installed, &version, &z.latest) {
                (false, _, _) => "не установлена — Foxray скачает её с GitHub".to_string(),
                (true, Some(v), Some(l)) if l != v => format!("версия {v}, есть новая {l}"),
                (true, Some(v), _) => match zapret::engine_version(&dir) {
                    Some(e) => format!("версия {v} · nfqws {e}"),
                    None => format!("версия {v}"),
                },
                (true, None, _) => "установлена".to_string(),
            }
            .into(),
        );
        ui.set_zapret_status(z.status.clone().into());
        ui.set_zapret_status_bad(z.status_bad);
        ui.set_zapret_busy(z.busy);
        ui.set_zapret_testing(z.cancel.is_some());
        ui.set_zapret_progress(z.progress.clone().into());
        ui.set_zapret_short(
            if z.cancel.is_some() {
                "подбираю стратегию…".to_string()
            } else if !app.settings.zapret_enabled {
                "выключен".to_string()
            } else if running {
                format!("работает · {sel_title}")
            } else if !installed {
                "включён, но сборка не скачана".to_string()
            } else {
                "включён, но не запущен".to_string()
            }
            .into(),
        );
        let rows: Vec<ZapretRow> = list
            .iter()
            .map(|s| {
                let testing = z.testing_id.as_deref() == Some(s.id.as_str());
                let result = app.settings.zapret_results.get(&s.id).cloned().unwrap_or_default();
                ZapretRow {
                    title: s.title.clone().into(),
                    result: if testing { "проверяю…".into() } else if result.is_empty() { "не проверена".into() } else { result.clone().into() },
                    selected: s.id == *sel,
                    state: if testing { 4 } else { score_state(&result) },
                }
            })
            .collect();
        ui.set_zapret_rows(ModelRc::new(VecModel::from(rows)));

        // Плитка на главной.
        let (title, sub, bad) = if z.cancel.is_some() {
            let sub = if z.test_title.is_empty() { "Проверяю, что открывается без zapret…".to_string() } else { format!("Проверяю {}…", z.test_title) };
            ("Подбор стратегии".to_string(), sub, false)
        } else if !app.settings.zapret_enabled {
            ("Выключен".into(), "Discord и YouTube без VPN".into(), false)
        } else if running {
            ("Работает".into(), "Discord · YouTube".into(), false)
        } else if !installed {
            ("Не скачан".into(), "нажми «стратегия», чтобы скачать".into(), true)
        } else {
            ("Не запущен".into(), if z.status.is_empty() { "подробности — на странице zapret".into() } else { z.status.clone() }, true)
        };
        ui.set_zapret_home_title(title.into());
        ui.set_zapret_home_sub(sub.into());
        ui.set_zapret_home_bad(bad);
        ui.set_zapret_home_strategy(
            if z.cancel.is_some() && z.test_pos.1 > 0 {
                format!("{}/{}", z.test_pos.0, z.test_pos.1).into()
            } else if z.cancel.is_some() {
                "…".into()
            } else if installed {
                sel_title.into()
            } else {
                "Скачать".into()
            },
        );
    });
    refresh_routes(ui);
}

/// Строка zapret для «Куда идёт трафик»: (название, подпись, работает ли). None — zapret выключен.
pub(super) fn home_route() -> Option<(String, String, bool)> {
    if !zapret::supported() {
        return None;
    }
    with_app(|app| {
        if !app.settings.zapret_enabled {
            return None;
        }
        let running = app.zap.winws.is_some();
        let sub = if app.zap.cancel.is_some() {
            "подбираю стратегию…".to_string()
        } else if running {
            String::new()
        } else {
            "zapret не запущен".into()
        };
        Some(("Discord, YouTube".to_string(), sub, running))
    })
}

/// Перезапустить winws по текущим настройкам (или остановить, если zapret выключен).
pub(super) fn apply(ui: &AppWindow) {
    if !zapret::supported() {
        return;
    }
    // Старый процесс — долой (Drop его убивает).
    let (enabled, testing) = with_app(|app| {
        app.zap.winws = None;
        (app.settings.zapret_enabled, app.zap.cancel.is_some())
    });
    if testing {
        return; // во время подбора winws запускает сама проверка
    }
    if !enabled {
        set_status("", false);
        refresh(ui);
        return;
    }
    let dir = zdir();
    if !zapret::installed(&dir) {
        refresh(ui);
        return;
    }
    let foreign = zapret::foreign_winws(&[]);
    if !foreign.is_empty() {
        set_status(
            if cfg!(windows) {
                "Уже запущен другой zapret (окно «zapret: …» или служба zapret). Закрой его — два сразу мешают друг другу."
            } else {
                "Уже запущен другой nfqws (установленный zapret?). Останови его — два сразу мешают друг другу."
            },
            true,
        );
        refresh(ui);
        return;
    }
    if !root_ready(ui, apply) {
        return;
    }
    match prepare_args(&dir) {
        Err(e) => set_status(e, true),
        Ok((id, args)) => {
            let w = ui.as_weak();
            let res = zapret::Winws::start(&dir, &args, move |line| {
                let w = w.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    with_app(|app| push_log(app, format!("zapret: {line}")));
                    if let Some(ui) = w.upgrade() {
                        if ui.get_settings_view() == 1 {
                            refresh_log(&ui);
                        }
                    }
                });
            });
            match res {
                Ok(p) => {
                    with_app(|app| {
                        push_log(app, format!("foxray: zapret запущен, стратегия {}", zapret::title_of(&id)));
                        app.zap.winws = Some(p);
                    });
                    set_status("", false);
                }
                Err(e) => set_status(e, true),
            }
        }
    }
    refresh(ui);
}

/// Аргументы winws для выбранной стратегии (нет такой — первая по списку).
fn prepare_args(dir: &Path) -> Result<(String, Vec<String>), String> {
    zapret::ensure_user_lists(dir);
    let ips = with_app(|app| app.zap.ips.clone());
    let ex = zapret::write_exclude(dir, &ips);
    let list = zapret::strategies(dir);
    let want = with_app(|app| app.settings.zapret_strategy.clone());
    let s = list.iter().find(|s| s.id == want).or(list.first()).ok_or("в папке zapret нет стратегий")?;
    let text = std::fs::read_to_string(&s.file).map_err(|e| format!("{}: {e}", s.id))?;
    let args = zapret::parse_bat(&text, dir, Some(&ex)).map_err(|e| format!("{}: {e}", s.title))?;
    Ok((s.id.clone(), args))
}

/// Каждую секунду: не умер ли winws.
pub(super) fn tick(ui: &AppWindow) {
    let died = with_app(|app| {
        let code = app.zap.winws.as_mut().and_then(|w| w.exited());
        if code.is_some() {
            app.zap.winws = None;
        }
        code
    });
    if let Some(code) = died {
        set_status(format!("zapret остановился (код {code}). Подробности — в журнале. Выбери стратегию ещё раз, чтобы перезапустить."), true);
        refresh(ui);
    }
}

/// Список «напрямую» для sing-box: домены из списков zapret и сам Discord (голос идёт по IP).
pub(super) fn routing_list() -> Option<RuleList> {
    if !zapret::supported() || !with_app(|app| app.settings.zapret_enabled) {
        return None;
    }
    let dir = zdir();
    if !zapret::installed(&dir) {
        return None;
    }
    let mut entries = zapret::domains(&dir);
    // Discord и сторонние клиенты (голос идёт по IP — ловим по программе).
    // Vencord внутри обычного Discord — это всё ещё Discord; Vesktop, Equibop, Legcord — свои программы.
    if cfg!(windows) {
        for p in ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "Vesktop.exe", "Equibop.exe", "Legcord.exe", "ArmCord.exe"] {
            entries.push(p.into());
        }
    } else {
        for p in ["Discord", "discord", "DiscordPTB", "DiscordCanary", "vesktop", "Vesktop", "equibop", "legcord", "armcord"] {
            entries.push(format!("process:{p}"));
        }
    }
    Some(RuleList { name: "zapret".into(), builtin: false, enabled: true, action: Action::Direct, entries })
}

/// Адреса VPN-сервера сменились (новый сервер) — перезапустить zapret с новым исключением.
pub(super) fn set_server_ips(ui: &AppWindow, mut ips: Vec<IpAddr>) {
    ips.sort();
    ips.dedup();
    let changed = with_app(|app| {
        if app.zap.ips == ips {
            return false;
        }
        app.zap.ips = ips;
        app.zap.winws.is_some()
    });
    if changed {
        apply(ui);
    }
}

pub(super) fn stop_all() {
    with_app(|app| {
        if let Some(c) = &app.zap.cancel {
            c.store(true, Ordering::SeqCst);
        }
        app.zap.winws = None;
    });
}

// ---------------------------------------------------------------- скачивание

fn download(ui: &AppWindow) {
    if with_app(|app| app.zap.busy || app.zap.cancel.is_some()) {
        return;
    }
    with_app(|app| {
        app.zap.busy = true;
        app.zap.winws = None; // файлы winws заняты, пока он работает
    });
    set_status("Узнаю последнюю версию…", false);
    refresh(ui);
    let dir = zdir();
    let w = ui.as_weak();
    std::thread::spawn(move || {
        let local = zapret::installed(&dir).then(|| zapret::version(&dir)).flatten();
        let result = zapret::latest_version().and_then(|v| {
            if local.as_deref() == Some(v.as_str()) {
                Ok((v, false))
            } else {
                zapret::download(&dir, &v).map(|_| (v, true))
            }
        });
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = w.upgrade() else { return };
            with_app(|app| app.zap.busy = false);
            match result {
                Ok((v, fresh)) => {
                    with_app(|app| {
                        app.zap.latest = Some(v.clone());
                        if fresh {
                            push_log(app, format!("foxray: zapret {v} скачан"));
                        }
                    });
                    set_status(if fresh { format!("Скачана версия {v}.") } else { format!("Уже последняя версия ({v}).") }, false);
                }
                Err(e) => set_status(format!("Не получилось: {e}"), true),
            }
            apply(&ui);
            if with_app(|app| app.runner.is_some() && app.settings.zapret_enabled) {
                reconnect(&ui); // списки доменов могли поменяться
            }
            refresh(&ui);
        });
    });
}

// ---------------------------------------------------------------- подбор стратегии

fn start_test(ui: &AppWindow) {
    if with_app(|app| app.zap.cancel.is_some() || app.zap.busy) {
        return;
    }
    let dir = zdir();
    if !zapret::installed(&dir) {
        return;
    }
    // Чужой zapret исказит результаты.
    if !zapret::foreign_winws(&[]).is_empty() {
        set_status(
            if cfg!(windows) {
                "Сначала закрой другой zapret (окно «zapret: …» или службу zapret)."
            } else {
                "Сначала останови другой nfqws (установленный zapret)."
            },
            true,
        );
        refresh(ui);
        return;
    }
    if !root_ready(ui, start_test) {
        return;
    }
    // При включённом VPN сайты zapret должны идти «напрямую» — значит, zapret включаем.
    let mut wait = Duration::from_millis(0);
    if !with_app(|app| app.settings.zapret_enabled) {
        with_app(|app| {
            app.settings.zapret_enabled = true;
            let _ = app.store.save_settings(&app.settings);
        });
        if with_app(|app| app.runner.is_some()) {
            reconnect(ui);
            wait = Duration::from_secs(3);
        }
    }

    // Аргументы всех стратегий готовим здесь; битые сразу помечаем.
    zapret::ensure_user_lists(&dir);
    let ex = zapret::write_exclude(&dir, &with_app(|app| app.zap.ips.clone()));
    let mut jobs = Vec::new();
    for s in zapret::strategies(&dir) {
        let parsed = std::fs::read_to_string(&s.file)
            .map_err(|e| e.to_string())
            .and_then(|t| zapret::parse_bat(&t, &dir, Some(&ex)));
        match parsed {
            Ok(args) => jobs.push((s.id, s.title, args)),
            Err(e) => {
                with_app(|app| app.settings.zapret_results.insert(s.id, format!("ошибка: {e}")));
            }
        }
    }

    let cancel = Arc::new(AtomicBool::new(false));
    with_app(|app| {
        app.zap.winws = None;
        app.zap.cancel = Some(cancel.clone());
        app.zap.progress = "Проверяю, что открывается без zapret…".into();
        app.zap.status.clear();
        push_log(app, format!("foxray: подбор стратегии zapret — {} шт.", jobs.len()));
    });
    refresh(ui);

    let w = ui.as_weak();
    std::thread::spawn(move || {
        std::thread::sleep(wait);
        let post = |f: Box<dyn FnOnce(&AppWindow) + Send>| {
            let w = w.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = w.upgrade() {
                    f(&ui);
                    refresh(&ui);
                }
            });
        };

        let base = zapret::check_all();
        let base_text = base.text();
        let n = jobs.len();
        let mut scores: Vec<(String, String, zapret::Score)> = Vec::new();
        for (k, (id, title, args)) in jobs.into_iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            {
                let (id, title) = (id.clone(), title.clone());
                post(Box::new(move |_| {
                    with_app(|app| {
                        app.zap.testing_id = Some(id);
                        app.zap.test_pos = (k + 1, n);
                        app.zap.progress = format!("Проверяю {title} ({}/{n})…", k + 1);
                        app.zap.test_title = title;
                    })
                }));
            }
            let result = match zapret::Winws::start(&dir, &args, |_| {}) {
                Ok(mut p) => {
                    std::thread::sleep(Duration::from_millis(1500)); // WinDivert включается не мгновенно
                    let s = zapret::check_all();
                    p.stop();
                    Ok(s)
                }
                Err(e) => Err(e),
            };
            let text = match &result {
                Ok(s) => s.text(),
                Err(e) => format!("ошибка: {e}"),
            };
            {
                let (id, text) = (id.clone(), text.clone());
                let fails = result.as_ref().map(|s| s.failed.join("; ")).unwrap_or_default();
                post(Box::new(move |_| {
                    with_app(|app| {
                        if !fails.is_empty() {
                            push_log(app, format!("foxray: zapret {} — {text}; не открылось: {fails}", zapret::title_of(&id)));
                        }
                        app.settings.zapret_results.insert(id, text);
                    })
                }));
            }
            if let Ok(s) = result {
                scores.push((id, title, s));
            }
        }
        let cancelled = cancel.load(Ordering::SeqCst);

        post(Box::new(move |ui| {
            // Лучшие: больше открылось, при равенстве — быстрее.
            scores.sort_by(|a, b| b.2.ok.cmp(&a.2.ok).then(a.2.avg_ms.cmp(&b.2.avg_ms)));
            let best: Vec<&(String, String, zapret::Score)> = scores.iter().filter(|s| s.2.ok > 0).take(3).collect();
            let summary = if best.is_empty() {
                format!("Ни одна стратегия не открыла сайты (без zapret: {base_text}). Попробуй обновить сборку zapret.")
            } else {
                let names: Vec<&str> = best.iter().map(|s| s.1.as_str()).collect();
                format!(
                    "{}Без zapret: {base_text}. Лучшие: {}. Выбрана {} — зайди в голосовой канал; не работает голос — выбери следующую.",
                    if cancelled { "Проверка остановлена. " } else { "" },
                    names.join(", "),
                    names[0]
                )
            };
            with_app(|app| {
                if let Some(b) = best.first() {
                    app.settings.zapret_strategy = b.0.clone();
                }
                let _ = app.store.save_settings(&app.settings);
                app.zap.cancel = None;
                app.zap.testing_id = None;
                app.zap.test_pos = (0, 0);
                app.zap.test_title.clear();
                app.zap.progress = summary;
            });
            apply(ui);
        }));
    });
}
