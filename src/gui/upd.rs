//! «Обновление» в настройках: проверка выпусков на GitHub и установка.

use super::*;
use foxray::update::{self, Release, ReleaseInfo};

#[derive(Default)]
pub(super) struct UpdState {
    latest: Option<Release>,
    status: String,
    bad: bool,
    busy: bool,
    /// Выпуски для «Что нового».
    releases: Vec<ReleaseInfo>,
    /// Когда проверяли (секунды Unix, 0 — ещё нет).
    checked: u64,
}

pub(super) fn setup(ui: &AppWindow) {
    update::cleanup_old();
    ui.set_app_version(update::VERSION.into());

    let w = ui.as_weak();
    ui.on_update_check(move || check(&w.unwrap(), false));
    let w = ui.as_weak();
    ui.on_update_install(move || install(&w.unwrap()));
    let w = ui.as_weak();
    ui.on_open_update(move || {
        let ui = w.unwrap();
        refresh(&ui);
        ui.set_settings_view(3);
        // Давно не проверяли — проверим заодно.
        if with_app(|app| unix_now().saturating_sub(app.upd.checked) > 600) {
            check(&ui, true);
        }
    });

    if update::repo().is_none() {
        with_app(|app| app.upd.status = "обновления не настроены (нет repository в Cargo.toml)".into());
    } else {
        // Тихая проверка при запуске.
        check(ui, true);
    }
    refresh(ui);
}

fn refresh(ui: &AppWindow) {
    with_app(|app| {
        let u = &app.upd;
        ui.set_update_status(u.status.clone().into());
        ui.set_update_bad(u.bad);
        ui.set_update_busy(u.busy);
        let avail = u.latest.as_ref().filter(|r| update::newer(&r.version, update::VERSION));
        ui.set_update_available(avail.is_some());
        ui.set_update_latest(avail.map(|r| r.version.clone()).unwrap_or_default().into());
        ui.set_update_checked(if u.checked == 0 { String::new() } else { format!("проверено {}", ago(u.checked, unix_now())) }.into());
        let rows: Vec<ReleaseRow> = u
            .releases
            .iter()
            .map(|r| ReleaseRow {
                version: r.version.clone().into(),
                date: r.date.clone().into(),
                notes: ModelRc::new(VecModel::from(
                    if r.notes.is_empty() { vec![SharedString::from("без описания")] } else { r.notes.iter().map(|n| n.into()).collect::<Vec<SharedString>>() },
                )),
                is_new: update::newer(&r.version, update::VERSION),
                installed: r.version == update::VERSION,
            })
            .collect();
        ui.set_releases(ModelRc::new(VecModel::from(rows)));
    });
}

fn check(ui: &AppWindow, quiet: bool) {
    if with_app(|app| app.upd.busy) {
        return;
    }
    with_app(|app| {
        app.upd.busy = true;
        if !quiet {
            app.upd.status = "проверяю…".into();
            app.upd.bad = false;
        }
    });
    refresh(ui);
    let w = ui.as_weak();
    std::thread::spawn(move || {
        let res = update::latest();
        let rels = update::releases();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = w.upgrade() else { return };
            with_app(|app| {
                app.upd.busy = false;
                if let Ok(r) = rels {
                    app.upd.releases = r;
                }
                if res.is_ok() {
                    app.upd.checked = unix_now();
                }
                match res {
                    Ok(r) => {
                        app.upd.bad = false;
                        app.upd.status = if update::newer(&r.version, update::VERSION) {
                            format!("доступна версия {}", r.version)
                        } else {
                            "установлена последняя версия".into()
                        };
                        app.upd.latest = Some(r);
                    }
                    // Тихая проверка при запуске: ошибку (нет сети, нет выпусков) не показываем.
                    Err(_) if quiet => {}
                    Err(e) => {
                        app.upd.bad = true;
                        app.upd.status = e;
                    }
                }
            });
            refresh(&ui);
        });
    });
}

fn install(ui: &AppWindow) {
    let Some(rel) = with_app(|app| app.upd.latest.clone()) else {
        return check(ui, false);
    };
    if with_app(|app| app.upd.busy) || !update::newer(&rel.version, update::VERSION) {
        return;
    }
    // Файл sing-box тоже меняется — VPN на время обновления выключаем.
    if with_app(|app| app.runner.is_some()) {
        disconnect(ui);
    }
    with_app(|app| {
        app.upd.busy = true;
        app.upd.bad = false;
        app.upd.status = format!("скачиваю {}…", rel.version);
    });
    refresh(ui);
    let w = ui.as_weak();
    std::thread::spawn(move || {
        let res = update::install(&rel).and_then(|_| update::restart());
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = w.upgrade() else { return };
            match res {
                // Новая версия уже запущена и ждёт, пока эта закроется.
                Ok(()) => {
                    let _ = slint::quit_event_loop();
                }
                Err(e) => {
                    with_app(|app| {
                        app.upd.busy = false;
                        app.upd.bad = true;
                        app.upd.status = format!("не получилось: {e}");
                    });
                    refresh(&ui);
                }
            }
        });
    });
}
