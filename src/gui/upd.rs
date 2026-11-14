//! «Обновление» в настройках: проверка выпусков на GitHub и установка.

use super::*;
use foxray::update::{self, Release};

#[derive(Default)]
pub(super) struct UpdState {
    latest: Option<Release>,
    status: String,
    bad: bool,
    busy: bool,
}

pub(super) fn setup(ui: &AppWindow) {
    update::cleanup_old();
    ui.set_app_version(update::VERSION.into());

    let w = ui.as_weak();
    ui.on_update_check(move || check(&w.unwrap(), false));
    let w = ui.as_weak();
    ui.on_update_install(move || install(&w.unwrap()));

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
        ui.set_update_available(u.latest.as_ref().is_some_and(|r| update::newer(&r.version, update::VERSION)));
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
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = w.upgrade() else { return };
            with_app(|app| {
                app.upd.busy = false;
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
