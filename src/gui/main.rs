// Без чёрного окна консоли на Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod edit;
#[cfg(windows)]
mod jumplist;
mod single;
mod conns;
mod tray;
mod upd;
mod zap;
#[cfg(windows)]
mod win_frame;

use foxray::link::{Profile, Proto, Security};
use foxray::rules::{describe, parse_entry, Action, Entry, RuleList};
use foxray::runner::{human_bytes, human_speed, Event, Runner};
use foxray::store::{self, AppSettings, Store};
use foxray::subs::{self, Subscription};
use foxray::{build_config, geo, net, parse_many, sys, Rules, Settings};
use slint::{CloseRequestResponse, ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

slint::include_modules!();

const MAX_LOG_LINES: usize = 300;
const HIST_LEN: usize = 40;

#[derive(Clone)]
enum Ping {
    Running,
    Ok(u32),
    Fail,
}

/// Состояние приложения живёт в потоке интерфейса.
struct App {
    store: Store,
    profiles: Vec<Profile>,
    settings: AppSettings,
    runner: Option<Runner>,
    /// Номер текущего запуска — события от старых запусков игнорируем.
    run_id: u64,
    conn_state: i32,
    /// Строка состояния для трея.
    status: String,
    connected_at: Option<Instant>,
    down_hist: VecDeque<u64>,
    up_hist: VecDeque<u64>,
    log: VecDeque<String>,
    rules: Rules,
    list_sel: Option<usize>,
    processes: Vec<String>,
    process_filter: String,
    pings: HashMap<String, Ping>,
    sub_info: HashMap<String, String>,
    search: String,
    collapsed: HashSet<String>,
    autostart: bool,
    tray: Option<tray::Tray>,
    has_tray: bool,
    edit: Option<edit::EditState>,
    last_tab: i32,
    /// Пользователь хочет быть подключённым (для автоповтора при обрыве).
    want_connected: bool,
    retry: u32,
    retry_timer: Timer,
    /// Состояние загрузки наборов: тег → «скачивается…» / ошибка.
    set_status: HashMap<String, String>,
    /// Поиск в окне выбора набора.
    set_filter: String,
    last_ping_all: Option<Instant>,
    last_home_ping: Option<Instant>,
    apply_timer: Timer,
    toast_timer: Timer,
    /// Zapret: winws, подбор стратегии, скачивание.
    zap: zap::ZapState,
    /// Страница «Соединения».
    conns: conns::ConnState,
    /// Обновление программы.
    upd: upd::UpdState,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// Доступ к состоянию. Внутри нельзя снова вызывать with_app.
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> R {
    APP.with(|a| f(a.borrow_mut().as_mut().expect("App не создан")))
}

fn main() -> Result<(), slint::PlatformError> {
    // Linux: помощник zapret с правами root (запускается самим Foxray через pkexec).
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("--zapret-helper") {
        std::process::exit(foxray::nfq::helper_main());
    }
    // Windows: отрисовка программная — у femtovg/Skia на дробном масштабе экрана (125 %, 150 %)
    // края скруглений (переключатели) получались с «заусенцами». Окно маленькое — CPU хватает.
    // Linux: остаётся обычная (femtovg) — с программной окно в Ubuntu/GNOME не реагировало на нажатия.
    // Свой способ всегда можно задать переменной SLINT_BACKEND (например, winit-skia).
    #[cfg(windows)]
    if std::env::var_os("SLINT_BACKEND").is_none() {
        std::env::set_var("SLINT_BACKEND", "winit-software");
    }
    let start_minimized = std::env::args().any(|a| a == "--minimized");
    let quit_cmd = std::env::args().any(|a| a == "--quit");
    let toggle_cmd = std::env::args().any(|a| a == "--toggle");

    // Запуск после обновления: ждём, пока старая версия закроется (до 10 с).
    if std::env::args().any(|a| a == "--after-update") {
        for _ in 0..100 {
            if !single::send("ping") {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // Уже запущен? Передаём команду ему и выходим.
    // (--minimized — это автозапуск: если копия уже есть, просто ничего не делаем.)
    let cmd = if quit_cmd {
        "quit"
    } else if toggle_cmd {
        "toggle"
    } else if start_minimized {
        "ping"
    } else {
        "show"
    };
    if single::send(cmd) || quit_cmd {
        return Ok(());
    }

    let ui = AppWindow::new()?;
    if !cfg!(windows) {
        ui.set_autostart_title("Запускать при входе в систему".into());
    }
    ui.set_frameless(!cfg!(windows)); // на Windows рамка своя (win_frame), иначе — без рамки

    let store = Store::new(store::app_dir());
    let profiles = store.load_profiles();
    let mut settings = store.load_settings();
    if settings.selected.map_or(true, |s| s >= profiles.len()) {
        settings.selected = if profiles.is_empty() { None } else { Some(0) };
    }
    let mut log = VecDeque::new();
    let rules_path = store.rules_path();
    let rules = if rules_path.exists() {
        Rules::load(&rules_path.to_string_lossy()).unwrap_or_else(|e| {
            log.push_back(format!("foxray: не удалось прочитать rules.json — {e}"));
            Rules::default()
        })
    } else {
        Rules::default()
    };
    let singbox = store::singbox_path(&store.dir);
    // Linux: sing-box, оставшийся от упавшего Foxray, — закрываем (иначе TUN занят).
    #[cfg(unix)]
    if let Some(dir) = store.config_path().parent() {
        foxray::runner::kill_stale(dir);
    }
    let dir_text = store.dir.display().to_string();

    APP.with(|a| {
        *a.borrow_mut() = Some(App {
            store,
            profiles,
            settings,
            runner: None,
            run_id: 0,
            conn_state: 0,
            status: "Отключено".into(),
            connected_at: None,
            down_hist: VecDeque::new(),
            up_hist: VecDeque::new(),
            log,
            rules,
            list_sel: None,
            processes: Vec::new(),
            process_filter: String::new(),
            pings: HashMap::new(),
            sub_info: HashMap::new(),
            search: String::new(),
            collapsed: HashSet::new(),
            autostart: sys::autostart::is_enabled(),
            tray: None,
            has_tray: false,
            edit: None,
            last_tab: -1,
            want_connected: false,
            retry: 0,
            retry_timer: Timer::default(),
            set_status: HashMap::new(),
            set_filter: String::new(),
            last_ping_all: None,
            last_home_ping: None,
            apply_timer: Timer::default(),
            toast_timer: Timer::default(),
            zap: Default::default(),
            conns: Default::default(),
            upd: Default::default(),
        })
    });

    ui.set_version(format!("Foxray {}", env!("CARGO_PKG_VERSION")).into());
    refresh_settings(&ui);
    refresh_servers(&ui);
    refresh_rules(&ui);
    refresh_subs(&ui);
    refresh_log(&ui);
    refresh_home(&ui);
    reset_speed(&ui);
    set_conn(&ui, 0, None);
    if singbox.is_none() {
        set_conn(&ui, 3, Some(format!("Не найден {} — положи его в папку {dir_text}", store::SINGBOX_EXE)));
    }

    // Версия sing-box — в фоне, чтобы не тормозить запуск.
    if let Some(sb) = singbox.clone() {
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new(sb);
            cmd.arg("version");
            sys::hide_window(&mut cmd);
            let v = cmd
                .output()
                .ok()
                .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(|l| l.replace("sing-box version ", "")))
                .unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.set_version(format!("Foxray {} · sing-box {v}", env!("CARGO_PKG_VERSION")).into());
                }
            });
        });
    }

    // ---- Трей (Windows и Linux, только в режиме «Закрыть → в трей») ----
    ensure_tray();
    let has_tray = with_app(|app| app.has_tray);

    // Команды от второй копии (повторный запуск, «Выйти»).
    {
        let weak = ui.as_weak();
        let res = single::listen(move |cmd| {
            let weak = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else { return };
                match cmd.as_str() {
                    "show" => show_window(&ui),
                    "toggle" => toggle(&ui),
                    "quit" => {
                        let _ = slint::quit_event_loop();
                    }
                    _ => {}
                }
            });
        });
        if let Err(e) = res {
            with_app(|app| push_log(app, format!("foxray: защита от второй копии не работает — {e}")));
        }
    }

    setup_window(&ui);
    setup_home(&ui);
    setup_servers(&ui);
    setup_editor(&ui);
    setup_rules(&ui);
    setup_settings(&ui);
    zap::setup(&ui);
    conns::setup(&ui);
    upd::setup(&ui);

    // Закрытие окна (Alt+F4) — так же, как наша кнопка «Закрыть».
    {
        let w = ui.as_weak();
        ui.window().on_close_requested(move || {
            if let Some(ui) = w.upgrade() {
                close_window(&ui);
            }
            CloseRequestResponse::KeepWindowShown
        });
    }

    // События трея опрашиваем таймером в потоке интерфейса.
    let tray_poll = Timer::default();
    if HAS_TRAY {
        let w = ui.as_weak();
        tray_poll.start(TimerMode::Repeated, Duration::from_millis(100), move || {
            if let Some(ui) = w.upgrade() {
                poll_tray(&ui);
            }
        });
    }

    // Время подключения — раз в секунду.
    let clock = Timer::default();
    {
        let w = ui.as_weak();
        clock.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            let Some(ui) = w.upgrade() else { return };
            if let Some(t) = with_app(|app| app.connected_at) {
                let s = t.elapsed().as_secs();
                ui.set_uptime(format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60).into());
            }
            auto_ping(&ui);
            zap::tick(&ui);
        });
    }

    if !(start_minimized && has_tray) {
        ui.show()?;
        if start_minimized {
            ui.window().set_minimized(true); // автозапуск без трея — свёрнутым в панель задач
        }
    }
    // Меню на кнопке в панели задач (правый клик).
    update_jumplist(false);

    // Zapret (если включён) — сразу, ещё до подключения VPN.
    zap::apply(&ui);

    // Готовые наборы: скачать недостающие / обновить старше недели.
    update_sets(&ui, false);
    // Если Foxray не закрывают неделями — проверяем свежесть наборов раз в 6 часов.
    let sets_timer = Timer::default();
    {
        let w = ui.as_weak();
        sets_timer.start(TimerMode::Repeated, Duration::from_secs(6 * 3600), move || {
            if let Some(ui) = w.upgrade() {
                update_sets(&ui, false);
            }
        });
    }

    // Рамка: ждём, пока появится настоящее окно, и ставим её (каждые 20 мс, до 5 с).
    let frame_timer = Timer::default();
    {
        let w = ui.as_weak();
        let tries = std::cell::Cell::new(0u32);
        frame_timer.start(TimerMode::Repeated, Duration::from_millis(20), move || {
            let n = tries.get();
            if n == u32::MAX {
                return; // уже готово
            }
            let Some(ui) = w.upgrade() else { return };
            if !ui.window().is_visible() {
                return; // окно спрятано (старт в трей) — поставим при показе
            }
            if style_window(&ui) {
                tries.set(u32::MAX);
                if cfg!(windows) {
                    with_app(|app| push_log(app, "foxray: рамка окна подключена".into()));
                }
            } else if n == 250 {
                with_app(|app| push_log(app, "foxray: не удалось получить окно для рамки".into()));
                tries.set(n + 1);
            } else {
                tries.set(n + 1);
            }
        });
    }

    if with_app(|app| app.settings.connect_on_start && app.settings.selected.is_some()) && singbox.is_some() {
        if start_minimized {
            // Автозапуск с Windows: сеть может быть ещё не готова — ждём до минуты.
            wait_network_then_connect(&ui);
        } else {
            connect(&ui);
        }
    }
    if with_app(|app| !app.settings.subscriptions.is_empty()) {
        update_subs(&ui, None);
    }

    slint::run_event_loop_until_quit()?;

    // Выход — гасим sing-box и убираем иконку.
    zap::stop_all();
    let runner = with_app(|app| {
        app.tray = None;
        app.runner.take()
    });
    if let Some(r) = runner {
        r.stop();
    }
    Ok(())
}

fn show_toast(ui: &AppWindow, text: impl Into<SharedString>) {
    ui.set_toast(text.into());
    let w = ui.as_weak();
    with_app(|app| {
        app.toast_timer.start(TimerMode::SingleShot, Duration::from_millis(1800), move || {
            if let Some(ui) = w.upgrade() {
                ui.set_toast("".into());
            }
        })
    });
}

// =====================================================================
// Окно без системной рамки
// =====================================================================

fn setup_window(ui: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor;

    let w = ui.as_weak();
    ui.on_start_drag(move || {
        let ui = w.unwrap();
        ui.window().with_winit_window(|win| {
            let _ = win.drag_window();
        });
        // Перетаскивание окна забирает себе отпускание кнопки мыши (его получает оконный
        // менеджер, а не Foxray). Slint тогда считает кнопку всё ещё зажатой на полосе
        // заголовка и отдаёт ей все следующие нажатия — окно «перестаёт откликаться».
        // Сообщаем об отпускании сами (отложенно — после начала перетаскивания).
        let w2 = ui.as_weak();
        slint::Timer::single_shot(Duration::from_millis(50), move || {
            if let Some(ui) = w2.upgrade() {
                use slint::platform::{PointerEventButton, WindowEvent};
                let pos = slint::LogicalPosition::new(0.0, 0.0);
                ui.window().dispatch_event(WindowEvent::PointerReleased { position: pos, button: PointerEventButton::Left });
                ui.window().dispatch_event(WindowEvent::PointerExited);
            }
        });
    });

    let w = ui.as_weak();
    ui.on_minimize(move || w.unwrap().window().set_minimized(true));

    let w = ui.as_weak();
    ui.on_close_window(move || close_window(&w.unwrap()));

    ui.on_quit_app(|| {
        let _ = slint::quit_event_loop();
    });

    let w = ui.as_weak();
    ui.on_set_close_action(move |a| {
        let ui = w.unwrap();
        with_app(|app| {
            app.settings.close_action = a;
            let _ = app.store.save_settings(&app.settings);
        });
        ui.set_close_action(a);
        ensure_tray();
    });
}

/// Кнопка «Закрыть» / Alt+F4 — по настройке.
fn close_window(ui: &AppWindow) {
    let (action, has_tray) = with_app(|app| (app.settings.close_action, app.has_tray));
    match action {
        0 if has_tray => {
            let _ = ui.hide();
            if !with_app(|app| app.settings.tray_hint_shown) {
                with_app(|app| {
                    app.settings.tray_hint_shown = true;
                    let _ = app.store.save_settings(&app.settings);
                });
                // Подсказка один раз — что окно не закрылось, а ушло в трей.
                let _ = tray_notify("Foxray работает в трее. Выйти — правый клик по иконке → «Выход».");
            }
        }
        2 => {
            let _ = slint::quit_event_loop();
        }
        // В панель задач (или трея нет — например, его не поддерживает рабочий стол).
        _ => ui.window().set_minimized(true),
    }
}

/// Трей поддерживается в Windows и Linux.
const HAS_TRAY: bool = cfg!(any(windows, target_os = "linux"));

/// Трей есть только в режиме «Закрыть → в трей».
fn ensure_tray() {
    let want = HAS_TRAY && with_app(|app| app.settings.close_action == 0);
    let have = with_app(|app| app.tray.is_some());
    if want && !have {
        let st = tray_state();
        match tray::Tray::new(&st.as_ref()) {
            Ok(t) => with_app(|app| app.tray = Some(t)),
            Err(e) => with_app(|app| push_log(app, format!("foxray: трей недоступен — {e}"))),
        }
    } else if !want && have {
        with_app(|app| app.tray = None);
    }
    with_app(|app| app.has_tray = app.tray.is_some());
}

/// HWND окна (на других системах — None).
#[cfg_attr(not(windows), allow(dead_code))]
fn native_hwnd(ui: &AppWindow) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use slint::winit_030::WinitWindowAccessor;
    ui.window()
        .with_winit_window(|win| match win.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
            _ => None,
        })
        .flatten()
}

/// Рамка как в Telegram: окно Windows с тенью и скруглением, но без стандартного заголовка.
/// Возвращает true, если окно уже существует и рамка поставлена.
/// Важно: настоящее окно Windows Slint создаёт только после старта цикла событий,
/// поэтому сразу после show() его ещё нет — main повторяет попытки таймером.
fn style_window(ui: &AppWindow) -> bool {
    #[cfg(windows)]
    {
        use slint::winit_030::winit::platform::windows::{CornerPreference, WindowExtWindows};
        use slint::winit_030::WinitWindowAccessor;
        let Some(hwnd) = native_hwnd(ui) else { return false };
        // 380×720 — размер окна, 26 — высота полосы, 48 — две кнопки по 22 + отступ 4 справа (app.slint).
        unsafe { win_frame::install(hwnd as _, 380, 720, 26, 48) };
        ui.window().with_winit_window(|win| win.set_corner_preference(CornerPreference::Round));
        true
    }
    #[cfg(not(windows))]
    {
        let _ = ui;
        true
    }
}

fn tray_notify(text: &str) -> Option<()> {
    with_app(|app| app.tray.as_ref().map(|t| t.set_tooltip_hint(text)))
}

// =====================================================================
// Главная
// =====================================================================

fn setup_home(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_toggle_connection(move || toggle(&w.unwrap()));

    let w = ui.as_weak();
    ui.on_set_mode(move |i| {
        let ui = w.unwrap();
        with_app(|app| app.rules.final_action = if i == 1 { Action::Direct } else { Action::Proxy });
        ui.set_final_action(i);
        rules_changed(&ui, true);
    });

    let w = ui.as_weak();
    ui.on_route_clicked(move |target| {
        let ui = w.unwrap();
        match target {
            0 => {
                let direct = with_app(|app| {
                    app.rules.final_action = if app.rules.final_action == Action::Direct { Action::Proxy } else { Action::Direct };
                    app.rules.final_action == Action::Direct
                });
                ui.set_final_action(if direct { 1 } else { 0 });
                rules_changed(&ui, true);
                show_toast(&ui, if direct { "Остальное — напрямую" } else { "Остальное — через VPN" });
            }
            1 => {
                ui.set_settings_view(2);
                ui.set_tab(3);
            }
            _ => {
                ui.set_rules_view(0);
                ui.set_tab(2);
            }
        }
    });
}

/// Короткая метка сервера для квадратика: «Lucario-volcano-MSK» → «MSK».
/// «🇳🇱 Amsterdam» → «NL», «DE-Frankfurt-2» → «DE2», «Germany 1» → «GE1».
///   1. флаг страны в имени → код страны;
///   2. иначе слово из 2–4 букв (сначала ЗАГЛАВНЫЕ, ближе к концу — важнее);
///   3. иначе первые две буквы имени.
/// Номер сервера (последнее слово из 1–2 цифр) дописывается: два сервера одной страны различимы.
fn tag_for(name: &str) -> String {
    // Флаг — пара «региональных» символов: 🇳 🇱 → N L.
    let regional: Vec<char> = name
        .chars()
        .filter_map(|c| {
            let u = c as u32;
            (0x1F1E6..=0x1F1FF).contains(&u).then(|| char::from_u32('A' as u32 + (u - 0x1F1E6)).unwrap())
        })
        .collect();
    let words: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let number = words
        .last()
        .filter(|w| w.len() <= 2 && w.chars().all(|c| c.is_ascii_digit()))
        .map(|w| w.to_string())
        .unwrap_or_default();
    let short = |w: &&str| (2..=4).contains(&w.chars().count()) && w.chars().all(|c| c.is_alphabetic());
    let code = if regional.len() >= 2 {
        regional[..2].iter().collect::<String>()
    } else if let Some(w) = words.iter().rev().find(|w| short(w) && w.chars().all(|c| c.is_uppercase())) {
        w.to_string()
    } else if let Some(w) = words.iter().rev().find(|w| short(w)) {
        w.to_uppercase()
    } else {
        name.chars().filter(|c| c.is_alphabetic()).take(2).collect::<String>().to_uppercase()
    };
    let code = if code.is_empty() { "?".to_string() } else { code };
    // Не длиннее 5 символов — иначе не влезет в квадратик в списке серверов.
    if !number.is_empty() && code.chars().count() + number.len() <= 5 {
        format!("{code}{number}")
    } else {
        code
    }
}

#[cfg(test)]
mod tag_tests {
    use super::tag_for;

    #[test]
    fn tags() {
        assert_eq!(tag_for("Lucario-volcano-toxashhh-MSK"), "MSK");
        assert_eq!(tag_for("🇳🇱 Amsterdam"), "NL");
        assert_eq!(tag_for("🇩🇪 Germany #2"), "DE2");
        assert_eq!(tag_for("DE-Frankfurt-2"), "DE2");
        assert_eq!(tag_for("Germany 1"), "GE1");
        assert_eq!(tag_for("Germany 2"), "GE2");
        assert_eq!(tag_for("Server de"), "DE");
        assert_eq!(tag_for("Финляндия FI"), "FI");
        assert_eq!(tag_for("Москва"), "МО");
        assert_eq!(tag_for("hy2-fast-NL-12"), "NL12");
        assert_eq!(tag_for("12345"), "?");
    }
}

fn refresh_home(ui: &AppWindow) {
    with_app(|app| {
        ui.set_final_action(if app.rules.final_action == Action::Direct { 1 } else { 0 });
        match app.settings.selected.and_then(|i| app.profiles.get(i)) {
            Some(p) => {
                ui.set_has_server(true);
                ui.set_cur_name(p.name.clone().into());
                ui.set_cur_tag(tag_for(&p.name).into());
                let ping = match app.pings.get(&ping_key(p)) {
                    Some(Ping::Ok(ms)) => format!("{ms} мс"),
                    Some(Ping::Fail) => "нет ответа".into(),
                    _ => String::new(),
                };
                let sep = if ping.is_empty() { "" } else { " · " };
                ui.set_cur_desc(format!("{}{sep}{ping}", proto_label(p)).into());
                ui.set_cur_ping(ping.into());
            }
            None => {
                ui.set_has_server(false);
                ui.set_cur_ping("".into());
            }
        }
    });
    refresh_routes(ui);
}

/// «1 соединение», «3 соединения», «25 соединений».
fn conns_text(n: u32) -> String {
    let word = match (n % 10, n % 100) {
        (1, r) if r != 11 => "соединение",
        (2..=4, r) if !(12..=14).contains(&r) => "соединения",
        _ => "соединений",
    };
    format!("{n} {word}")
}

/// Коротко о содержимом списков: «Российские сайты, qbittorrent и ещё 2».
fn summarize(lists: &[&RuleList]) -> String {
    // Сначала понятные названия наборов («Российские сайты»), потом программы и домены.
    let mut names: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    for l in lists {
        for e in &l.entries {
            if let Some(svc) = geo::service_of(e) {
                if !names.iter().any(|n| n == svc.name) {
                    names.push(svc.name.to_string());
                }
                continue;
            }
            let name = {
                let e = e.trim();
                let e = e.split_once(':').filter(|(k, _)| matches!(*k, "process" | "domain" | "full" | "keyword" | "geosite" | "geoip")).map(|(_, v)| v).unwrap_or(e);
                let base = e.rsplit(['\\', '/']).next().unwrap_or(e);
                base.strip_suffix(".exe").or_else(|| base.strip_suffix(".EXE")).unwrap_or(base).to_string()
            };
            if !name.is_empty() && !other.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                other.push(name);
            }
        }
    }
    names.extend(other);
    // Строка узкая: влезает ~26 символов, дальше — «и ещё N».
    let mut shown = 0;
    let mut len = 0;
    for n in &names {
        let add = n.chars().count() + if shown > 0 { 2 } else { 0 };
        if shown > 0 && len + add > 26 {
            break;
        }
        len += add;
        shown += 1;
    }
    if shown < names.len() {
        format!("{} и ещё {}", names[..shown].join(", "), names.len() - shown)
    } else {
        names.join(", ")
    }
}

/// «Куда идёт трафик» на главной.
fn refresh_routes(ui: &AppWindow) {
    let zap = zap::home_route();
    let zm = conns::ZapMatch::current();
    let rows = with_app(|app| {
        // Сколько соединений и трафика у каждого маршрута (по открытым сейчас соединениям).
        // Группа: 0 — «всё остальное», 1 — zapret, 2 — списки «напрямую», 3 — списки «через VPN».
        let mut stat = [(0u32, 0u64); 4];
        let direct_mode = app.rules.final_action == Action::Direct;
        for c in &app.conns.home {
            let (kind, _) = zm.classify(c);
            let bytes = c.down + c.up;
            let g = if kind == 1 {
                1
            } else if c.rule == "final" || c.rule.is_empty() && ((kind == 0) != direct_mode) {
                0
            } else if kind == 2 {
                2
            } else if kind == 0 {
                3
            } else {
                continue;
            };
            stat[g].0 += 1;
            stat[g].1 += bytes;
        }
        let have_stats = !app.conns.home.is_empty();
        let info = |g: usize| -> String {
            if !have_stats {
                return String::new();
            }
            let (n, b) = stat[g];
            if n == 0 {
                return "нет соединений".into();
            }
            format!("{} · {}", conns_text(n), human_bytes(b))
        };
        let on = app.conn_state == 1 || app.conn_state == 2;
        let all_vpn = app.rules.final_action != Action::Direct;
        let active = |a: Action| -> Vec<&RuleList> {
            app.rules.lists.iter().filter(|l| l.enabled && l.action == a && !l.entries.is_empty()).collect()
        };
        let row = |title: String, sub: &str, chip: &str, kind: i32, target: i32| RouteRow {
            title: title.into(),
            sub: sub.into(),
            chip: chip.into(),
            kind,
            target,
        };
        let mut rows = Vec::new();
        // Всё остальное: нажатие меняет режим.
        rows.push(match (on, all_vpn) {
            (true, true) => row("Всё остальное".into(), &info(0), "VPN", 0, 0),
            (true, false) => row("Всё остальное".into(), &info(0), "напрямую", 2, 0),
            (false, true) => row("Всё остальное".into(), "", "напрямую", 4, 0),
            (false, false) => row("Всё остальное".into(), "", "напрямую", 2, 0),
        });
        if let Some((title, sub, running)) = zap {
            let sub = if sub.is_empty() && on { info(1) } else { sub };
            rows.push(row(title, &sub, "zapret", if running { 1 } else { 4 }, 1));
        }
        let direct = active(Action::Direct);
        if !direct.is_empty() {
            rows.push(row(summarize(&direct), &if on { info(2) } else { String::new() }, "напрямую", 2, 2));
        }
        if !all_vpn {
            let proxy = active(Action::Proxy);
            if !proxy.is_empty() {
                rows.push(row(summarize(&proxy), &if on { info(3) } else { "с VPN".into() }, "VPN", if on { 0 } else { 4 }, 2));
            }
        }
        let block = active(Action::Block);
        if !block.is_empty() {
            rows.push(row(summarize(&block), if on { "" } else { "с VPN" }, "блок", if on { 3 } else { 4 }, 2));
        }
        rows
    });
    ui.set_routes(ModelRc::new(VecModel::from(rows)));
}

fn split_speed(s: String) -> (SharedString, SharedString) {
    match s.rsplit_once(' ') {
        Some((n, u)) => (n.into(), u.into()),
        None => (s.into(), "".into()),
    }
}

/// Мини-график: последние HIST_LEN значений → путь в координатах 100×28.
fn sparkline(hist: &VecDeque<u64>) -> SharedString {
    if hist.len() < 2 {
        return "M0 27 L100 27".into();
    }
    let max = hist.iter().copied().max().unwrap_or(0).max(20 * 1024) as f32;
    let step = 100.0 / (HIST_LEN - 1) as f32;
    let start = HIST_LEN - hist.len();
    let mut s = String::new();
    for (i, v) in hist.iter().enumerate() {
        let x = (start + i) as f32 * step;
        let y = 27.0 - (*v as f32 / max) * 23.0;
        s += &format!("{}{x:.1} {y:.1} ", if i == 0 { "M" } else { "L" });
    }
    s.into()
}

fn reset_speed(ui: &AppWindow) {
    with_app(|app| {
        app.down_hist.clear();
        app.up_hist.clear();
    });
    ui.set_down_num("0".into());
    ui.set_down_unit("Б/с".into());
    ui.set_up_num("0".into());
    ui.set_up_unit("Б/с".into());
    ui.set_down_path("M0 27 L100 27".into());
    ui.set_up_path("M0 27 L100 27".into());
    ui.set_totals("—".into());
    ui.set_conns("—".into());
    ui.set_down_total("".into());
    ui.set_up_total("".into());
}

fn on_traffic(ui: &AppWindow, up: u64, down: u64) {
    let (dp, upath) = with_app(|app| {
        app.down_hist.push_back(down);
        app.up_hist.push_back(up);
        while app.down_hist.len() > HIST_LEN {
            app.down_hist.pop_front();
        }
        while app.up_hist.len() > HIST_LEN {
            app.up_hist.pop_front();
        }
        (sparkline(&app.down_hist), sparkline(&app.up_hist))
    });
    let (n, u) = split_speed(human_speed(down));
    ui.set_down_num(n);
    ui.set_down_unit(u);
    let (n, u) = split_speed(human_speed(up));
    ui.set_up_num(n);
    ui.set_up_unit(u);
    ui.set_down_path(dp);
    ui.set_up_path(upath);
}

// =====================================================================
// Серверы
// =====================================================================

fn setup_servers(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_select_server(move |i| select_server(&w.unwrap(), i as usize));

    let w = ui.as_weak();
    ui.on_remove_server(move |i| {
        let ui = w.unwrap();
        let i = i as usize;
        let was_active = with_app(|app| app.runner.is_some() && app.settings.selected == Some(i));
        if was_active {
            disconnect(&ui);
        }
        let name = with_app(|app| {
            if i >= app.profiles.len() {
                return None;
            }
            let key = selected_key(app).filter(|_| app.settings.selected != Some(i));
            let p = app.profiles.remove(i);
            reselect(app, key);
            save_all(app);
            Some(p.name)
        });
        refresh_servers(&ui);
        refresh_home(&ui);
        refresh_subs(&ui);
        refresh_tray();
        if let Some(n) = name {
            show_toast(&ui, format!("Удалён «{n}»"));
        }
    });

    let w = ui.as_weak();
    ui.on_rename_server(move |i, name| {
        let name = name.trim().to_string();
        if name.is_empty() {
            return;
        }
        with_app(|app| {
            if let Some(p) = app.profiles.get_mut(i as usize) {
                p.name = name;
                let _ = app.store.save_profiles(&app.profiles);
            }
        });
        let ui = w.unwrap();
        refresh_servers(&ui);
        refresh_home(&ui);
        refresh_tray();
    });

    let w = ui.as_weak();
    ui.on_copy_link(move |i| {
        let ui = w.unwrap();
        let link = with_app(|app| app.profiles.get(i as usize).map(|p| p.to_link()));
        if let Some(link) = link {
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(link)) {
                Ok(()) => show_toast(&ui, "Ссылка скопирована"),
                Err(e) => show_toast(&ui, format!("Буфер обмена недоступен: {e}")),
            }
        }
    });

    let w = ui.as_weak();
    ui.on_search(move |t| {
        with_app(|app| app.search = t.trim().to_lowercase());
        refresh_servers(&w.unwrap());
    });

    let w = ui.as_weak();
    ui.on_toggle_group(move |key| {
        with_app(|app| {
            let k = key.to_string();
            if !app.collapsed.remove(&k) {
                app.collapsed.insert(k);
            }
        });
        refresh_servers(&w.unwrap());
    });

    let w = ui.as_weak();
    ui.on_refresh_group(move |key| update_subs(&w.unwrap(), Some(key.to_string())));

    let w = ui.as_weak();
    ui.on_ping_all(move || ping_all(&w.unwrap()));

    ui.on_read_clipboard(|| read_clipboard().into());

    let w = ui.as_weak();
    ui.on_open_add(move || {
        let ui = w.unwrap();
        ui.set_add_error("".into());
        if ui.get_add_text().trim().is_empty() {
            let clip = read_clipboard();
            if clip.contains("://") {
                ui.set_add_text(clip.trim().into());
            }
        }
        ui.set_adding(true);
    });

    let w = ui.as_weak();
    ui.on_add_links(move |text| add_links(&w.unwrap(), &text));
}

fn read_clipboard() -> String {
    arboard::Clipboard::new().and_then(|mut c| c.get_text()).unwrap_or_default()
}

fn toggle(ui: &AppWindow) {
    // Идёт ожидание повтора — нажатие означает «хватит».
    if with_app(|app| app.runner.is_some() || app.want_connected) {
        disconnect(ui);
    } else {
        with_app(|app| app.retry = 0); // ручное включение — попытки заново
        connect(ui);
    }
}

fn select_server(ui: &AppWindow, i: usize) {
    let changed = with_app(|app| {
        if i >= app.profiles.len() {
            return false;
        }
        let changed = app.settings.selected != Some(i);
        app.settings.selected = Some(i);
        let _ = app.store.save_settings(&app.settings);
        changed
    });
    refresh_servers(ui);
    refresh_home(ui);
    refresh_tray();
    if changed && with_app(|app| app.runner.is_some()) {
        reconnect(ui);
    }
}

fn add_links(ui: &AppWindow, text: &str) {
    let mut sub_urls = Vec::new();
    let mut plain = String::new();
    for line in text.split_whitespace() {
        if subs::is_subscription_url(line) {
            sub_urls.push(line.to_string());
        } else {
            plain.push_str(line);
            plain.push('\n');
        }
    }
    let (new, errors) = parse_many(&plain);
    let n_new = new.len();

    let n_subs = with_app(|app| {
        let first_new = app.profiles.len();
        app.profiles.extend(new);
        if app.settings.selected.is_none() && n_new > 0 {
            app.settings.selected = Some(first_new);
        }
        let mut added = 0;
        for url in sub_urls {
            if !app.settings.subscriptions.iter().any(|s| s.url == url) {
                app.settings.subscriptions.push(Subscription::from_url(&url));
                added += 1;
            }
        }
        save_all(app);
        added
    });

    let err_text = errors.iter().map(|(_, e)| e.to_string()).collect::<Vec<_>>().join("\n");
    if n_new == 0 && n_subs == 0 {
        ui.set_add_error(if err_text.is_empty() { "Вставь ссылку".into() } else { err_text.into() });
        return;
    }
    ui.set_add_error("".into());
    ui.set_add_text("".into());
    ui.set_adding(false);
    refresh_servers(ui);
    refresh_home(ui);
    refresh_subs(ui);
    refresh_tray();
    let mut msg = Vec::new();
    if n_new > 0 {
        msg.push(format!("Добавлено: {n_new}"));
    }
    if n_subs > 0 {
        msg.push("подписка загружается…".to_string());
    }
    if !errors.is_empty() {
        msg.push(format!("пропущено {}", errors.len()));
    }
    show_toast(ui, msg.join(", "));
    if n_subs > 0 {
        update_subs(ui, None);
    }
}

/// Раз в секунду: пингуем, пока открыта вкладка «Серверы» (каждые 45 с)
/// и текущий сервер на «Главной» при подключении (раз в минуту). Только при видимом окне.
fn auto_ping(ui: &AppWindow) {
    let tab = ui.get_tab();
    let visible = ui.window().is_visible() && !ui.window().is_minimized();
    let (entered, all_due, home_due) = with_app(|app| {
        let entered = tab != app.last_tab;
        app.last_tab = tab;
        let due = |t: Option<Instant>, secs| t.map_or(true, |t| t.elapsed() >= Duration::from_secs(secs));
        (entered, due(app.last_ping_all, 45), due(app.last_home_ping, 60))
    });
    if !visible {
        return;
    }
    if tab == 1 && ui.get_servers_view() == 0 && (entered || all_due) {
        // При возврате на вкладку не чаще раза в 10 с.
        let recent = with_app(|app| app.last_ping_all.map_or(false, |t| t.elapsed() < Duration::from_secs(10)));
        if !recent || all_due {
            ping_all(ui);
        }
    }
    if tab == 0 && (entered || home_due) && with_app(|app| app.conn_state == 2) {
        let target = with_app(|app| {
            app.last_home_ping = Some(Instant::now());
            app.settings.selected.and_then(|i| app.profiles.get(i)).cloned()
        });
        if let Some(p) = target {
            ping_profiles(ui, vec![(ping_key(&p), p)]);
        }
    }
}

fn ping_key(p: &Profile) -> String {
    format!("{}:{}", p.server, p.port)
}

fn ping_all(ui: &AppWindow) {
    let targets: Vec<(String, Profile)> = with_app(|app| {
        app.last_ping_all = Some(Instant::now());
        let mut seen = HashSet::new();
        app.profiles.iter().filter(|p| seen.insert(ping_key(p))).map(|p| (ping_key(p), p.clone())).collect()
    });
    ping_profiles(ui, targets);
}

fn ping_profiles(ui: &AppWindow, targets: Vec<(String, Profile)>) {
    with_app(|app| {
        for (k, _) in &targets {
            // Пока идёт повторная проверка — показываем прошлый результат, без мигания «…».
            app.pings.entry(k.clone()).or_insert(Ping::Running);
        }
    });
    refresh_servers(ui);
    for (key, profile) in targets {
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let res = match net::ping(&profile) {
                Ok(ms) => Ping::Ok(ms),
                Err(_) => Ping::Fail,
            };
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.pings.insert(key, res));
                if let Some(ui) = weak.upgrade() {
                    refresh_servers(&ui);
                    refresh_home(&ui);
                }
            });
        });
    }
}

/// Список с группами: «Мои» и по подпискам.
fn refresh_servers(ui: &AppWindow) {
    with_app(|app| {
        let known: HashSet<&str> = app.settings.subscriptions.iter().map(|s| s.url.as_str()).collect();
        let mut groups: Vec<(String, String, bool)> = vec![(String::new(), "Мои".into(), false)];
        for s in &app.settings.subscriptions {
            groups.push((s.url.clone(), format!("Подписка {}", s.name), true));
        }
        let q = &app.search;
        let mut rows = Vec::new();
        for (key, title, refreshable) in groups {
            let members: Vec<usize> = app
                .profiles
                .iter()
                .enumerate()
                .filter(|(_, p)| match p.sub.as_deref() {
                    Some(u) if known.contains(u) => u == key,
                    _ => key.is_empty(),
                })
                .filter(|(_, p)| q.is_empty() || p.name.to_lowercase().contains(q) || p.server.to_lowercase().contains(q))
                .map(|(i, _)| i)
                .collect();
            // Пустую группу «Мои» не показываем, если есть подписки; при поиске — любые пустые.
            if members.is_empty() && (!q.is_empty() || (key.is_empty() && !known.is_empty())) {
                continue;
            }
            let collapsed = app.collapsed.contains(&key);
            rows.push(Row {
                kind: 0,
                title: title.into(),
                count: members.len() as i32,
                key: key.clone().into(),
                collapsed,
                refreshable,
                ..Default::default()
            });
            if collapsed {
                continue;
            }
            for i in members {
                let p = &app.profiles[i];
                let (ping, ping_state) = match app.pings.get(&ping_key(p)) {
                    None => (String::new(), 0),
                    Some(Ping::Running) => ("…".into(), 4),
                    Some(Ping::Ok(ms)) => (format!("{ms} мс"), if *ms < 150 { 1 } else { 2 }),
                    Some(Ping::Fail) => ("нет".into(), 3),
                };
                rows.push(Row {
                    kind: 1,
                    title: p.name.clone().into(),
                    sub: p.server.clone().into(),
                    badge: short_proto(p).into(),
                    ping: ping.into(),
                    ping_state,
                    selected: app.settings.selected == Some(i),
                    index: i as i32,
                    ..Default::default()
                });
            }
        }
        ui.set_no_servers(app.profiles.is_empty());
        ui.set_rows(ModelRc::new(VecModel::from(rows)));
    });
}

fn proto_label(p: &Profile) -> &'static str {
    match &p.proto {
        Proto::Vless(v) => match v.security {
            Security::Reality { .. } => "VLESS Reality",
            Security::Tls { .. } => "VLESS TLS",
            Security::None => "VLESS",
        },
        Proto::Hysteria2(_) => "Hysteria2",
    }
}

fn short_proto(p: &Profile) -> &'static str {
    match &p.proto {
        Proto::Vless(v) => match v.security {
            Security::Reality { .. } => "Reality",
            Security::Tls { .. } => "VLESS TLS",
            Security::None => "VLESS",
        },
        Proto::Hysteria2(_) => "Hy2",
    }
}

/// Ключ выбранного сервера — чтобы найти его снова после изменений списка.
fn selected_key(app: &App) -> Option<(String, String, u16)> {
    let p = app.profiles.get(app.settings.selected?)?;
    Some((p.name.clone(), p.server.clone(), p.port))
}

fn reselect(app: &mut App, key: Option<(String, String, u16)>) {
    let found = key.and_then(|(n, s, port)| {
        app.profiles
            .iter()
            .position(|p| p.name == n && p.server == s && p.port == port)
            .or_else(|| app.profiles.iter().position(|p| p.server == s && p.port == port))
    });
    app.settings.selected = found.or(if app.profiles.is_empty() { None } else { Some(0) });
}

fn save_all(app: &App) {
    let _ = app.store.save_profiles(&app.profiles);
    let _ = app.store.save_settings(&app.settings);
}

// ---------------------------------------------------------------------
// Подключение
// ---------------------------------------------------------------------

/// state: 0 выкл, 1 подключение, 2 подключено, 3 ошибка. detail — подробность/текст ошибки.
fn set_conn(ui: &AppWindow, state: i32, detail: Option<String>) {
    update_jumplist(state == 1 || state == 2);
    let (lan, server) = with_app(|app| {
        (
            app.settings.lan_bypass,
            app.settings.selected.and_then(|i| app.profiles.get(i)).map(|p| p.name.clone()).unwrap_or_default(),
        )
    });
    let (title, sub, tray_text) = match state {
        2 => (
            "Подключено".to_string(),
            if lan { "TUN · локальная сеть напрямую" } else { "TUN · весь трафик через туннель" }.to_string(),
            format!("подключено: {server}"),
        ),
        1 => (
            "Подключение…".into(),
            detail.clone().unwrap_or_else(|| server.clone()),
            format!("подключение к {server}"),
        ),
        3 => {
            let d = detail.unwrap_or_default();
            ("Ошибка".into(), d.clone(), format!("ошибка: {d}"))
        }
        _ => ("Отключено".into(), "всё идёт напрямую".into(), "отключено".into()),
    };
    ui.set_state(state);
    ui.set_status_title(title.into());
    ui.set_status_sub(sub.into());
    with_app(|app| {
        app.conn_state = state;
        app.status = tray_text;
        if state == 2 {
            app.connected_at.get_or_insert_with(Instant::now);
        } else {
            app.connected_at = None;
        }
    });
    if state == 2 {
        ui.set_uptime("00:00:00".into());
    }
    refresh_routes(ui);
    refresh_tray();
}

fn connect(ui: &AppWindow) {
    // Zapret включён — его домены и Discord идут «напрямую», к zapret.
    let zap_list = zap::routing_list();
    let prepared = with_app(|app| -> Result<_, String> {
        let idx = app.settings.selected.ok_or("Выбери сервер на вкладке «Серверы»")?;
        let profile = app.profiles.get(idx).ok_or("Выбери сервер на вкладке «Серверы»")?.clone();
        let singbox = store::singbox_path(&app.store.dir).ok_or_else(|| {
            format!("Не найден {} в папке {}", store::SINGBOX_EXE, app.store.dir.display())
        })?;

        // rules.json — источник истины (его могли поправить в блокноте).
        let rules_path = app.store.rules_path();
        if rules_path.exists() {
            match Rules::load(&rules_path.to_string_lossy()) {
                Ok(r) => app.rules = r,
                Err(e) => push_log(app, format!("foxray: rules.json не прочитан — {e}")),
            }
        }
        let settings = Settings {
            lan_bypass: app.settings.lan_bypass,
            rule_set_dir: Some(app.store.dir.join("rulesets")),
            server_ips: foxray::config::resolve_server(&profile.server, profile.port),
            custom_dns: app.settings.custom_dns.then(|| app.settings.dns_address.clone()),
            ..Default::default()
        };
        let rules = match &zap_list {
            Some(l) => {
                let mut r = app.rules.clone();
                r.lists.insert(0, l.clone());
                r
            }
            None => app.rules.clone(),
        };
        let (cfg, errors) = build_config(&profile, &settings, &rules);
        for e in errors {
            push_log(app, format!("foxray: пропущено в списках — {e}"));
        }
        let config_path = app.store.config_path();
        std::fs::write(&config_path, serde_json::to_string_pretty(&cfg).unwrap())
            .map_err(|e| format!("Не удалось записать config.json: {e}"))?;

        app.run_id += 1;
        // Адреса сервера — чтобы zapret не трогал соединение с VPN.
        let mut ips = settings.server_ips.clone();
        if let Ok(ip) = profile.server.parse::<std::net::IpAddr>() {
            ips.push(ip);
        }
        Ok((singbox, config_path, settings.api_port, app.run_id, ips))
    });
    refresh_rules(ui);
    refresh_home(ui);

    let (singbox, config_path, api_port, run_id, server_ips) = match prepared {
        Ok(x) => x,
        Err(e) => {
            with_app(|app| app.want_connected = false);
            return set_conn(ui, 3, Some(e));
        }
    };
    with_app(|app| {
        app.want_connected = true;
        app.retry_timer.stop();
    });
    zap::set_server_ips(ui, server_ips);

    // Linux: sing-box нужно право управлять сетью (TUN) — выдаём один раз через pkexec.
    #[cfg(target_os = "linux")]
    if foxray::sys::tun_rights::has(&singbox) == Some(false) {
        with_app(|app| push_log(app, "foxray: выдаю sing-box права на TUN (pkexec setcap)…".into()));
        if let Err(e) = foxray::sys::tun_rights::grant(&singbox) {
            with_app(|app| app.want_connected = false);
            return set_conn(ui, 3, Some(e));
        }
    }

    let weak = ui.as_weak();
    let result = Runner::start(&singbox, &config_path, api_port, move |ev| {
        on_runner_event(weak.clone(), run_id, ev);
    });
    match result {
        Ok(r) => {
            with_app(|app| {
                app.runner = Some(r);
                app.conns.api_port = api_port;
            });
            reset_speed(ui);
            set_conn(ui, 1, None);
        }
        Err(e) => set_conn(ui, 3, Some(format!("Не удалось запустить sing-box: {e}"))),
    }
}

fn disconnect(ui: &AppWindow) {
    let runner = with_app(|app| {
        app.run_id += 1; // события старого запуска больше не интересны
        app.apply_timer.stop();
        app.retry_timer.stop();
        app.want_connected = false;
        app.retry = 0;
        app.runner.take()
    });
    conns::vpn_stopped();
    if let Some(r) = runner {
        r.stop();
    }
    reset_speed(ui);
    set_conn(ui, 0, None);
}

fn reconnect(ui: &AppWindow) {
    disconnect(ui);
    connect(ui);
}

thread_local! {
    static JUMP_STATE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Меню на кнопке в панели задач: «Подключить» или «Отключить» — по текущему состоянию.
fn update_jumplist(connected: bool) {
    if JUMP_STATE.with(|c| c.replace(Some(connected))) == Some(connected) {
        return;
    }
    #[cfg(windows)]
    {
        let dir = with_app(|app| app.store.dir.clone());
        std::thread::spawn(move || {
            let Ok(exe) = std::env::current_exe() else { return };
            let exe = exe.to_string_lossy().to_string();
            let icons = jumplist::icon_dir(&dir);
            let icon = |n: &str| icons.join(n).to_string_lossy().to_string();
            let toggle = if connected { "Отключить VPN" } else { "Подключить VPN" };
            let _ = jumplist::set_tasks(
                &exe,
                &[(toggle, "--toggle", icon("power.ico")), ("Выйти из Foxray", "--quit", icon("quit.ico"))],
            );
        });
    }
}

/// Вызывается из фоновых потоков — переносим обработку в поток интерфейса.
fn on_runner_event(weak: Weak<AppWindow>, run_id: u64, ev: Event) {
    let _ = slint::invoke_from_event_loop(move || {
        let Some(ui) = weak.upgrade() else { return };
        let current = with_app(|app| app.run_id == run_id);
        match ev {
            Event::Log(line) if is_log_noise(&line) => {}
            Event::Log(line) => {
                with_app(|app| push_log(app, line));
                refresh_log(&ui);
            }
            _ if !current => {}
            Event::Started => {
                with_app(|app| app.retry = 0);
                set_conn(&ui, 2, None);
            }
            Event::Traffic { up, down } => on_traffic(&ui, up, down),
            Event::Stats { down_total, up_total, conns, list } => {
                ui.set_totals(format!("{} / {}", human_bytes(down_total), human_bytes(up_total)).into());
                ui.set_down_total(human_bytes(down_total).into());
                ui.set_up_total(human_bytes(up_total).into());
                ui.set_conns(conns_text(conns).into());
                with_app(|app| app.conns.home = list);
                refresh_routes(&ui);
            }
            Event::Stopped(err) => {
                with_app(|app| app.runner = None);
                reset_speed(&ui);
                match err {
                    None => set_conn(&ui, 0, None),
                    Some(e) => schedule_retry(&ui, explain(&e)),
                }
            }
        }
    });
}

/// sing-box упал, а пользователь VPN не выключал — пробуем снова: 3, 5, 10, 20, 30 с.
fn schedule_retry(ui: &AppWindow, err: String) {
    const DELAYS: [u64; 5] = [3, 5, 10, 20, 30];
    let attempt = with_app(|app| {
        if !app.want_connected || app.retry as usize >= DELAYS.len() {
            app.want_connected = false;
            return None;
        }
        app.retry += 1;
        Some(app.retry)
    });
    let Some(n) = attempt else {
        return set_conn(ui, 3, Some(err));
    };
    let delay = DELAYS[n as usize - 1];
    with_app(|app| push_log(app, format!("foxray: обрыв ({err}), повтор {n}/{} через {delay} с", DELAYS.len())));
    set_conn(ui, 1, Some(format!("Обрыв — повтор {n} из {} через {delay} с", DELAYS.len())));
    let weak = ui.as_weak();
    with_app(|app| {
        app.retry_timer.start(TimerMode::SingleShot, Duration::from_secs(delay), move || {
            if let Some(ui) = weak.upgrade() {
                if with_app(|app| app.want_connected && app.runner.is_none()) {
                    let retry = with_app(|app| app.retry);
                    connect(&ui);
                    with_app(|app| app.retry = retry); // connect() не сбрасывает счётчик попыток
                }
            }
        });
    });
}

/// Автозапуск: ждём, пока сервер станет доступен (сеть поднялась), но не больше минуты.
fn wait_network_then_connect(ui: &AppWindow) {
    let target = with_app(|app| app.settings.selected.and_then(|i| app.profiles.get(i)).cloned());
    let Some(p) = target else { return };
    set_conn(ui, 1, Some("Жду сеть…".into()));
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(60) {
            if net::ping(&p).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                if with_app(|app| app.runner.is_none()) {
                    connect(&ui);
                }
            }
        });
    });
}

/// Обычный разрыв соединения программой или сайтом — sing-box пишет это как ERROR,
/// но к работе VPN отношения не имеет. В журнал не пускаем.
fn is_log_noise(line: &str) -> bool {
    line.contains("connection: connection upload closed") || line.contains("connection: connection download closed")
}

fn push_log(app: &mut App, line: String) {
    app.log.push_back(line);
    while app.log.len() > MAX_LOG_LINES {
        app.log.pop_front();
    }
}

fn refresh_log(ui: &AppWindow) {
    let text = with_app(|app| app.log.iter().cloned().collect::<Vec<_>>().join("\n"));
    ui.set_log_text(text.into());
}

/// Частые ошибки — по-человечески.
fn explain(e: &str) -> String {
    let low = e.to_lowercase();
    if low.contains("access is denied") || low.contains("operation not permitted") {
        "Нет прав администратора для TUN. Запусти Foxray от имени администратора.".into()
    } else if low.contains("address already in use") || low.contains("only one usage of each socket") {
        format!("Порт занят — возможно, запущен другой VPN-клиент (v2rayN?). {e}")
    } else if low.contains("configure tun") {
        format!("Не удалось создать TUN-адаптер — закрой другие VPN-клиенты. {e}")
    } else {
        e.to_string()
    }
}

// =====================================================================
// Редактор сервера
// =====================================================================

fn setup_editor(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_edit_server(move |i| {
        let ui = w.unwrap();
        let st = with_app(|app| app.profiles.get(i as usize).map(|p| edit::EditState::from_profile(i as usize, p)));
        if let Some(st) = st {
            open_editor(&ui, st);
        }
    });

    let w = ui.as_weak();
    ui.on_new_server(move || {
        let ui = w.unwrap();
        ui.set_tab(1);
        open_editor(&ui, edit::EditState::new_server());
    });

    let w = ui.as_weak();
    ui.on_set_edit_proto(move |p| {
        let ui = w.unwrap();
        with_app(|app| {
            if let Some(st) = app.edit.as_mut() {
                st.proto = p;
                // Порт и название переносим, остальное у протоколов разное.
                if p == 1 {
                    st.values.remove("security");
                }
            }
        });
        refresh_editor(&ui);
    });

    let w = ui.as_weak();
    ui.on_edit_field(move |i, v| {
        let ui = w.unwrap();
        // Выбор (Segmented) меняет набор полей — перерисовываем; текст — нет, чтобы не сбить курсор.
        let relayout = with_app(|app| {
            let st = app.edit.as_mut()?;
            let fields = st.fields();
            let f = fields.get(i as usize)?;
            st.set(f, &v);
            Some(f.kind != 0)
        });
        if relayout == Some(true) {
            refresh_editor(&ui);
        }
    });

    let w = ui.as_weak();
    ui.on_save_server(move || {
        let ui = w.unwrap();
        let res = with_app(|app| {
            let st = app.edit.clone()?;
            Some(st.build().map(|p| {
                let name = p.name.clone();
                match st.index {
                    Some(i) if i < app.profiles.len() => app.profiles[i] = p,
                    _ => {
                        app.profiles.push(p);
                        app.settings.selected = Some(app.profiles.len() - 1);
                    }
                }
                save_all(app);
                app.edit = None;
                (name, st.index)
            }))
        });
        match res {
            Some(Ok((name, idx))) => {
                ui.set_servers_view(0);
                refresh_servers(&ui);
                refresh_home(&ui);
                refresh_tray();
                show_toast(&ui, format!("Сохранено: {name}"));
                // Изменили сервер, через который сейчас подключены, — переподключаемся.
                if idx.is_some() && with_app(|app| app.runner.is_some() && app.settings.selected == idx) {
                    reconnect(&ui);
                }
            }
            Some(Err(e)) => ui.set_edit_error(e.into()),
            None => {}
        }
    });
}

fn open_editor(ui: &AppWindow, st: edit::EditState) {
    ui.set_edit_new(st.index.is_none());
    with_app(|app| app.edit = Some(st));
    refresh_editor(ui);
    ui.set_servers_view(1);
}

fn refresh_editor(ui: &AppWindow) {
    with_app(|app| {
        let Some(st) = &app.edit else { return };
        let items: Vec<FieldItem> = st
            .fields()
            .iter()
            .map(|f| FieldItem {
                key: f.key.into(),
                label: f.label.into(),
                value: st.get(f.key).into(),
                hint: f.hint.into(),
                kind: f.kind,
                labels: ModelRc::new(VecModel::from(
                    f.options.iter().map(|o| SharedString::from(o.1)).collect::<Vec<_>>(),
                )),
                choice: st.choice(f),
            })
            .collect();
        ui.set_edit_proto(st.proto);
        ui.set_edit_fields(ModelRc::new(VecModel::from(items)));
        ui.set_edit_error("".into());
    });
}

// =====================================================================
// Подписки
// =====================================================================

/// Обновить все подписки (only = None) или одну по url.
fn update_subs(ui: &AppWindow, only: Option<String>) {
    let list = with_app(|app| {
        let list: Vec<Subscription> = app
            .settings
            .subscriptions
            .iter()
            .filter(|s| only.as_deref().map_or(true, |u| u == s.url))
            .cloned()
            .collect();
        for s in &list {
            app.sub_info.insert(s.url.clone(), "обновляется…".into());
        }
        list
    });
    refresh_subs(ui);
    for sub in list {
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let res = subs::fetch(&sub);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else { return };
                apply_sub_result(&ui, &sub, res);
            });
        });
    }
}

fn apply_sub_result(ui: &AppWindow, sub: &Subscription, res: Result<(Vec<Profile>, usize), String>) {
    let msg = with_app(|app| {
        // Подписку могли удалить, пока она скачивалась.
        if !app.settings.subscriptions.iter().any(|s| s.url == sub.url) {
            return None;
        }
        Some(match res {
            Ok((list, bad)) => {
                let key = selected_key(app);
                let n = list.len();
                // Ставим новые серверы на место старых из этой подписки.
                let pos = app.profiles.iter().position(|p| p.sub.as_deref() == Some(sub.url.as_str()));
                app.profiles.retain(|p| p.sub.as_deref() != Some(sub.url.as_str()));
                let at = pos.unwrap_or(app.profiles.len()).min(app.profiles.len());
                app.profiles.splice(at..at, list);
                reselect(app, key);
                save_all(app);
                let mut info = format!("{n} {} · обновлено", plural(n, "сервер", "сервера", "серверов"));
                if bad > 0 {
                    info += &format!(" · пропущено {bad}");
                }
                app.sub_info.insert(sub.url.clone(), info);
                format!("Подписка {}: {n} {}", sub.name, plural(n, "сервер", "сервера", "серверов"))
            }
            Err(e) => {
                push_log(app, format!("foxray: подписка {} — {e}", sub.name));
                app.sub_info.insert(sub.url.clone(), "не обновилась — подробности в журнале".into());
                format!("Подписка {}: ошибка", sub.name)
            }
        })
    });
    refresh_servers(ui);
    refresh_home(ui);
    refresh_subs(ui);
    refresh_tray();
    if let Some(m) = msg {
        show_toast(ui, m);
    }
}

fn plural<'a>(n: usize, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    match (n % 10, n % 100) {
        (1, x) if x != 11 => one,
        (2..=4, x) if !(12..=14).contains(&x) => few,
        _ => many,
    }
}

fn refresh_subs(ui: &AppWindow) {
    let items: Vec<SubItem> = with_app(|app| {
        app.settings
            .subscriptions
            .iter()
            .map(|s| {
                let count = app.profiles.iter().filter(|p| p.sub.as_deref() == Some(s.url.as_str())).count();
                let info = app
                    .sub_info
                    .get(&s.url)
                    .cloned()
                    .unwrap_or_else(|| format!("{count} {}", plural(count, "сервер", "сервера", "серверов")));
                SubItem { name: s.name.clone().into(), info: info.into() }
            })
            .collect()
    });
    ui.set_subs(ModelRc::new(VecModel::from(items)));
}

// =====================================================================
// Правила
// =====================================================================

fn action_to_idx(a: Action) -> i32 {
    match a {
        Action::Proxy => 0,
        Action::Direct => 1,
        Action::Block => 2,
    }
}

fn idx_to_action(i: i32) -> Action {
    match i {
        1 => Action::Direct,
        2 => Action::Block,
        _ => Action::Proxy,
    }
}

fn summary(l: &RuleList) -> String {
    if l.entries.is_empty() {
        return "пусто".into();
    }
    // Наборы показываем по названию сервиса, Telegram (домены + IP) — один раз.
    let mut names: Vec<String> = Vec::new();
    for e in &l.entries {
        let name = geo::service_of(e).map_or_else(|| e.clone(), |sv| sv.name.to_string());
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let n = names.len();
    let first: Vec<&str> = names.iter().take(2).map(|s| s.as_str()).collect();
    format!(
        "{n} {} · {}{}",
        plural(n, "запись", "записи", "записей"),
        first.join(", "),
        if n > 2 { "…" } else { "" }
    )
}

fn refresh_rules(ui: &AppWindow) {
    with_app(|app| {
        if app.list_sel.map_or(false, |s| s >= app.rules.lists.len()) {
            app.list_sel = None;
        }
        let cards: Vec<RuleCard> = app
            .rules
            .lists
            .iter()
            .map(|l| RuleCard {
                name: l.name.clone().into(),
                builtin: l.builtin,
                action: action_to_idx(l.action),
                enabled: l.enabled,
                summary: summary(l).into(),
            })
            .collect();
        ui.set_rule_cards(ModelRc::new(VecModel::from(cards)));
        ui.set_list_sel(app.list_sel.map(|s| s as i32).unwrap_or(-1));
        match app.list_sel.and_then(|i| app.rules.lists.get(i)) {
            Some(l) => {
                ui.set_list_name(l.name.clone().into());
                ui.set_list_builtin(l.builtin);
                ui.set_list_enabled(l.enabled);
                ui.set_list_action(action_to_idx(l.action));
                let dir = app.store.dir.join("rulesets");
                let entries: Vec<EntryItem> = l
                    .entries
                    .iter()
                    .map(|e| match (parse_entry(e), describe(e)) {
                        (Ok(Entry::Geosite(t) | Entry::Geoip(t)), Ok(k)) => {
                            let status = app.set_status.get(&t).cloned().or_else(|| {
                                (!geo::is_ready(&dir, &t)).then(|| "не скачан".to_string())
                            });
                            let failed = status.as_deref().map_or(false, |x| x.starts_with("не скачался"));
                            let title = geo::service_of(e).map_or_else(|| e.clone(), |sv| sv.name.to_string());
                            let mut kind = format!("{k} · {}", foxray::rules::entry_name(&t));
                            if let Some(st) = status {
                                kind = format!("{kind} · {st}");
                            }
                            EntryItem { text: title.into(), kind: kind.into(), icon: if failed { 3 } else { 4 } }
                        }
                        (Ok(kind), Ok(k)) => EntryItem {
                            text: e.clone().into(),
                            kind: k.into(),
                            icon: match kind {
                                Entry::Process(_) | Entry::ProcessPath(_) => 0,
                                Entry::Cidr(_) => 2,
                                _ => 1,
                            },
                        },
                        (_, Err(err)) | (Err(err), _) => {
                            EntryItem { text: e.clone().into(), kind: err.into(), icon: 3 }
                        }
                    })
                    .collect();
                ui.set_entries(ModelRc::new(VecModel::from(entries)));
            }
            None => {
                ui.set_rules_view(0);
                ui.set_entries(ModelRc::new(VecModel::from(Vec::<EntryItem>::new())));
            }
        }
        ui.set_final_action(if app.rules.final_action == Action::Direct { 1 } else { 0 });
    });
}

/// Скачать наборы из всех списков, которых нет или которые старше недели (force — все).
/// После скачивания при активном подключении правила применяются заново.
fn update_sets(ui: &AppWindow, force: bool) {
    let (dir, todo) = with_app(|app| {
        let dir = app.store.dir.join("rulesets");
        let todo: Vec<String> = app
            .rules
            .set_tags()
            .into_iter()
            .filter(|t| force || geo::needs_update(&dir, t))
            .filter(|t| app.set_status.get(t).map_or(true, |s| s != "скачивается…"))
            .collect();
        for t in &todo {
            app.set_status.insert(t.clone(), "скачивается…".into());
        }
        (dir, todo)
    });
    if todo.is_empty() {
        return;
    }
    refresh_rules(ui);
    for tag in todo {
        let weak = ui.as_weak();
        let dir = dir.clone();
        std::thread::spawn(move || {
            let res = geo::download(&dir, &tag);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else { return };
                let was_ready = with_app(|app| match &res {
                    Ok(()) => app.set_status.remove(&tag).is_some(),
                    Err(e) => {
                        push_log(app, format!("foxray: набор {} не скачался — {e}", foxray::rules::entry_name(&tag)));
                        // старый файл (если был) продолжает работать
                        let st = if geo::is_ready(&dir, &tag) { "не обновился" } else { "не скачался" };
                        app.set_status.insert(tag.clone(), st.into());
                        false
                    }
                });
                refresh_rules(&ui);
                if res.is_ok() && was_ready {
                    rules_changed(&ui, true); // если подключены — применится через 1.5 с
                }
            });
        });
    }
}

/// Сохранить rules.json и (если подключены и apply) переподключиться через 1.5 с.
fn rules_changed(ui: &AppWindow, apply: bool) {
    refresh_routes(ui);
    let weak = ui.as_weak();
    with_app(|app| {
        if let Err(e) = app.rules.save(&app.store.rules_path().to_string_lossy()) {
            push_log(app, format!("foxray: {e}"));
        }
        if apply && app.runner.is_some() {
            app.apply_timer.start(TimerMode::SingleShot, Duration::from_millis(1500), move || {
                if let Some(ui) = weak.upgrade() {
                    if with_app(|app| app.runner.is_some()) {
                        reconnect(&ui);
                        show_toast(&ui, "Правила применены");
                    }
                }
            });
        }
    });
}

fn with_list<R>(f: impl FnOnce(&mut RuleList) -> R) -> Option<R> {
    with_app(|app| app.list_sel.and_then(|i| app.rules.lists.get_mut(i)).map(f))
}

fn setup_rules(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_open_list(move |i| {
        let ui = w.unwrap();
        with_app(|app| app.list_sel = Some(i as usize));
        ui.set_editing_list_name(false);
        refresh_rules(&ui);
        ui.set_rules_view(1);
    });

    let w = ui.as_weak();
    ui.on_add_list(move || {
        let ui = w.unwrap();
        with_app(|app| {
            app.rules.lists.push(RuleList {
                name: NEW_LIST_NAME.into(),
                builtin: false,
                enabled: true,
                action: Action::Direct,
                entries: Vec::new(),
            });
            app.list_sel = Some(app.rules.lists.len() - 1);
        });
        rules_changed(&ui, false);
        refresh_rules(&ui);
        ui.set_rules_view(1);
        ui.set_editing_list_name(true);
    });

    let w = ui.as_weak();
    ui.on_card_enabled(move |i, on| {
        let ui = w.unwrap();
        with_app(|app| {
            if let Some(l) = app.rules.lists.get_mut(i as usize) {
                l.enabled = on;
            }
        });
        rules_changed(&ui, true);
        refresh_rules(&ui);
    });

    let w = ui.as_weak();
    ui.on_set_list_enabled(move |on| {
        let ui = w.unwrap();
        with_list(|l| l.enabled = on);
        rules_changed(&ui, true);
        refresh_rules(&ui);
    });

    let w = ui.as_weak();
    ui.on_set_list_action(move |a| {
        let ui = w.unwrap();
        with_list(|l| {
            if !l.builtin {
                l.action = idx_to_action(a);
            }
        });
        rules_changed(&ui, true);
        refresh_rules(&ui);
    });

    let w = ui.as_weak();
    ui.on_rename_list(move |name| {
        let ui = w.unwrap();
        let name = name.trim().to_string();
        if !name.is_empty() {
            with_list(|l| l.name = name);
            rules_changed(&ui, false);
        }
        refresh_rules(&ui);
    });

    let w = ui.as_weak();
    ui.on_delete_list(move || {
        let ui = w.unwrap();
        let removed = with_app(|app| {
            let i = app.list_sel?;
            if app.rules.lists.get(i)?.builtin {
                return None; // базовые не удаляем
            }
            app.list_sel = None;
            Some(app.rules.lists.remove(i))
        });
        if let Some(l) = removed {
            rules_changed(&ui, l.enabled && !l.entries.is_empty());
            ui.set_rules_view(0);
            refresh_rules(&ui);
            show_toast(&ui, format!("Список «{}» удалён", l.name));
        }
    });

    let w = ui.as_weak();
    ui.on_add_entry(move |text| add_entries(&w.unwrap(), &text));

    let w = ui.as_weak();
    ui.on_remove_entry(move |i| {
        let ui = w.unwrap();
        with_list(|l| {
            if (i as usize) < l.entries.len() {
                l.entries.remove(i as usize);
            }
        });
        rules_changed(&ui, true);
        refresh_rules(&ui);
    });

    // Выбор программы из запущенных.
    let w = ui.as_weak();
    ui.on_pick_process(move || {
        let ui = w.unwrap();
        with_app(|app| app.process_filter.clear());
        ui.set_processes(ModelRc::new(VecModel::from(Vec::<SharedString>::new())));
        ui.set_picking(true);
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let list = sys::running_processes();
            let _ = slint::invoke_from_event_loop(move || {
                with_app(|app| app.processes = list);
                if let Some(ui) = weak.upgrade() {
                    refresh_processes(&ui);
                }
            });
        });
    });

    let w = ui.as_weak();
    ui.on_process_filter(move |f| {
        with_app(|app| app.process_filter = f.to_lowercase());
        refresh_processes(&w.unwrap());
    });

    let w = ui.as_weak();
    ui.on_process_chosen(move |name| {
        let ui = w.unwrap();
        ui.set_picking(false);
        // Linux: у программ нет .exe — помечаем явно, иначе «python3.12» примется за домен.
        let name = if cfg!(windows) || name.to_ascii_lowercase().ends_with(".exe") {
            name.to_string()
        } else {
            format!("process:{name}")
        };
        add_entries(&ui, &name);
    });

    let w = ui.as_weak();
    ui.on_close_picker(move || w.unwrap().set_picking(false));

    // Выбор готового набора.
    let w = ui.as_weak();
    ui.on_open_set_picker(move || {
        let ui = w.unwrap();
        with_app(|app| app.set_filter.clear());
        refresh_set_picker(&ui);
        ui.set_picking_set(true);
    });

    let w = ui.as_weak();
    ui.on_set_filter(move |f| {
        with_app(|app| app.set_filter = f.to_lowercase());
        refresh_set_picker(&w.unwrap());
    });

    let w = ui.as_weak();
    ui.on_set_chosen(move |i| {
        let ui = w.unwrap();
        let Some(sv) = geo::CATALOG.get(i as usize) else { return };
        let added = with_list(|l| {
            let has_all = sv.entries.iter().all(|e| l.entries.iter().any(|x| x.eq_ignore_ascii_case(e)));
            if has_all {
                // повторное нажатие — убрать набор из списка
                l.entries.retain(|x| !sv.entries.iter().any(|e| x.eq_ignore_ascii_case(e)));
                false
            } else {
                // новый пустой список сразу называем по сервису
                if !l.builtin && l.entries.is_empty() && l.name == NEW_LIST_NAME {
                    l.name = sv.name.to_string();
                }
                for e in sv.entries {
                    if !l.entries.iter().any(|x| x.eq_ignore_ascii_case(e)) {
                        l.entries.push(e.to_string());
                    }
                }
                true
            }
        });
        if added.is_none() {
            return;
        }
        ui.set_editing_list_name(false);
        rules_changed(&ui, true);
        refresh_rules(&ui);
        refresh_set_picker(&ui);
        update_sets(&ui, false);
    });

    let w = ui.as_weak();
    ui.on_close_set_picker(move || w.unwrap().set_picking_set(false));
}

const NEW_LIST_NAME: &str = "Новый список";

/// Каталог наборов с заголовками групп; отмечены те, что уже есть в открытом списке.
fn refresh_set_picker(ui: &AppWindow) {
    let rows: Vec<SetRow> = with_app(|app| {
        let current: Vec<String> = app
            .list_sel
            .and_then(|i| app.rules.lists.get(i))
            .map(|l| l.entries.iter().map(|e| e.to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let f = app.set_filter.trim().to_string();
        let mut rows = Vec::new();
        let mut group = "";
        for (i, sv) in geo::CATALOG.iter().enumerate() {
            let hit = f.is_empty()
                || sv.name.to_lowercase().contains(&f)
                || sv.group.to_lowercase().contains(&f)
                || sv.entries.iter().any(|e| e.contains(&f));
            if !hit {
                continue;
            }
            if sv.group != group {
                group = sv.group;
                rows.push(SetRow { kind: 0, title: group.into(), sub: "".into(), added: false, index: -1 });
            }
            rows.push(SetRow {
                kind: 1,
                title: sv.name.into(),
                sub: sv.entries.join(" + ").into(),
                added: sv.entries.iter().all(|e| current.iter().any(|x| x == e)),
                index: i as i32,
            });
        }
        rows
    });
    ui.set_set_rows(ModelRc::new(VecModel::from(rows)));
}

fn add_entries(ui: &AppWindow, text: &str) {
    let changed = with_list(|l| {
        let mut changed = false;
        // Несколько записей — через пробел, запятую или с новой строки.
        // Путь с пробелами (C:\Program Files\...) — целиком.
        let parts: Vec<String> = if text.contains('\\') {
            vec![text.trim().to_string()]
        } else {
            text.split(|c: char| c.is_whitespace() || c == ',' || c == ';').map(|s| s.trim().to_string()).collect()
        };
        for p in parts {
            if !p.is_empty() && !l.entries.iter().any(|e| e.eq_ignore_ascii_case(&p)) {
                l.entries.push(p);
                changed = true;
            }
        }
        changed
    })
    .unwrap_or(false);
    if changed {
        rules_changed(ui, true);
        refresh_rules(ui);
        update_sets(ui, false);
    }
}

fn refresh_processes(ui: &AppWindow) {
    let items: Vec<SharedString> = with_app(|app| {
        app.processes
            .iter()
            .filter(|p| app.process_filter.is_empty() || p.to_lowercase().contains(&app.process_filter))
            .map(|p| SharedString::from(p.as_str()))
            .collect()
    });
    ui.set_processes(ModelRc::new(VecModel::from(items)));
}

// =====================================================================
// Настройки
// =====================================================================

fn refresh_settings(ui: &AppWindow) {
    with_app(|app| {
        ui.set_lan_bypass(app.settings.lan_bypass);
        ui.set_connect_on_start(app.settings.connect_on_start);
        ui.set_autostart(app.autostart);
        ui.set_close_action(app.settings.close_action);
        ui.set_dns_custom(app.settings.custom_dns);
        ui.set_dns_address(app.settings.dns_address.clone().into());
    });
    refresh_dns_note(ui);
}

/// Подпись под адресом своего DNS: куда пойдут запросы или что не так с адресом.
fn refresh_dns_note(ui: &AppWindow) {
    let (on, addr) = with_app(|app| (app.settings.custom_dns, app.settings.dns_address.clone()));
    let (note, bad) = if !on {
        (String::new(), false)
    } else if addr.trim().is_empty() {
        ("Впиши IP-адрес, например 192.168.1.10. Пока пусто — работает 1.1.1.1.".to_string(), false)
    } else {
        match foxray::config::parse_dns(&addr) {
            Ok((ip, _)) if foxray::config::is_local_ip(ip) => {
                ("Домашний DNS: запросы идут к нему напрямую, мимо VPN. Он же резолвит домашние домены.".into(), false)
            }
            Ok(_) => ("Внешний DNS: запросы идут к нему через VPN.".into(), false),
            Err(e) => (format!("{e}. Пока работает 1.1.1.1."), true),
        }
    };
    ui.set_dns_note(note.into());
    ui.set_dns_note_bad(bad);
}

/// Применить изменение DNS: переподключиться через 1.5 с, если подключены.
fn dns_changed(ui: &AppWindow) {
    refresh_dns_note(ui);
    let valid = with_app(|app| {
        let _ = app.store.save_settings(&app.settings);
        !app.settings.custom_dns
            || app.settings.dns_address.trim().is_empty()
            || foxray::config::parse_dns(&app.settings.dns_address).is_ok()
    });
    let weak = ui.as_weak();
    with_app(|app| {
        if valid && app.runner.is_some() {
            app.apply_timer.start(TimerMode::SingleShot, Duration::from_millis(1500), move || {
                if let Some(ui) = weak.upgrade() {
                    if with_app(|app| app.runner.is_some()) {
                        reconnect(&ui);
                        show_toast(&ui, "DNS применён");
                    }
                }
            });
        } else {
            app.apply_timer.stop();
        }
    });
}

fn setup_settings(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_lan_bypass_toggled(move |on| {
        let ui = w.unwrap();
        with_app(|app| {
            app.settings.lan_bypass = on;
            let _ = app.store.save_settings(&app.settings);
        });
        ui.set_lan_bypass(on);
        if with_app(|app| app.runner.is_some()) {
            reconnect(&ui);
        }
    });

    let w = ui.as_weak();
    ui.on_dns_custom_toggled(move |on| {
        let ui = w.unwrap();
        with_app(|app| app.settings.custom_dns = on);
        ui.set_dns_custom(on);
        dns_changed(&ui);
    });

    let w = ui.as_weak();
    ui.on_dns_address_edited(move |text| {
        let ui = w.unwrap();
        let changed = with_app(|app| {
            let new = text.trim().to_string();
            let changed = app.settings.dns_address != new;
            app.settings.dns_address = new;
            changed
        });
        if changed {
            dns_changed(&ui);
        }
    });

    let w = ui.as_weak();
    ui.on_autostart_toggled(move |on| set_autostart(&w.unwrap(), on));

    let w = ui.as_weak();
    ui.on_connect_on_start_toggled(move |on| {
        with_app(|app| {
            app.settings.connect_on_start = on;
            let _ = app.store.save_settings(&app.settings);
        });
        w.unwrap().set_connect_on_start(on);
    });

    let w = ui.as_weak();
    ui.on_refresh_sub(move |i| {
        let ui = w.unwrap();
        let url = with_app(|app| app.settings.subscriptions.get(i as usize).map(|s| s.url.clone()));
        if let Some(u) = url {
            update_subs(&ui, Some(u));
        }
    });

    let w = ui.as_weak();
    ui.on_remove_sub(move |i| {
        let ui = w.unwrap();
        let name = with_app(|app| {
            let i = i as usize;
            if i >= app.settings.subscriptions.len() {
                return None;
            }
            let sub = app.settings.subscriptions.remove(i);
            let key = selected_key(app);
            app.profiles.retain(|p| p.sub.as_deref() != Some(sub.url.as_str()));
            app.sub_info.remove(&sub.url);
            reselect(app, key);
            save_all(app);
            Some(sub.name)
        });
        refresh_servers(&ui);
        refresh_home(&ui);
        refresh_subs(&ui);
        refresh_tray();
        if let Some(n) = name {
            show_toast(&ui, format!("Подписка {n} удалена"));
        }
    });

    ui.on_open_folder(|| {
        let dir = with_app(|app| app.store.dir.clone());
        open_path(&dir, false);
    });

    ui.on_open_rules_file(|| {
        let path = with_app(|app| {
            let p = app.store.rules_path();
            if !p.exists() {
                let _ = app.rules.save(&p.to_string_lossy());
            }
            p
        });
        open_path(&path, true);
    });

    let w = ui.as_weak();
    ui.on_clear_log(move || {
        with_app(|app| app.log.clear());
        refresh_log(&w.unwrap());
    });
}

fn set_autostart(ui: &AppWindow, on: bool) {
    match sys::autostart::set(on) {
        Ok(()) => {
            with_app(|app| app.autostart = on);
            ui.set_autostart(on);
            ui.set_settings_message("".into());
        }
        Err(e) => {
            let actual = sys::autostart::is_enabled();
            with_app(|app| app.autostart = actual);
            ui.set_autostart(actual);
            ui.set_settings_message(format!("Автозапуск: {e}").into());
        }
    }
    refresh_tray();
}

fn open_path(path: &Path, edit: bool) {
    #[cfg(windows)]
    {
        let prog = if edit { "notepad" } else { "explorer" };
        let _ = std::process::Command::new(prog).arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = edit;
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

// =====================================================================
// Трей
// =====================================================================

/// Снимок данных для меню трея (владеющий — чтобы не держать заимствование App).
struct TrayData {
    conn_state: i32,
    status: String,
    servers: Vec<String>,
    selected: Option<usize>,
    autostart: bool,
}

impl TrayData {
    fn as_ref(&self) -> tray::TrayState<'_> {
        tray::TrayState {
            conn_state: self.conn_state,
            status: &self.status,
            servers: self.servers.clone(),
            selected: self.selected,
            autostart: self.autostart,
        }
    }
}

fn tray_state() -> TrayData {
    with_app(|app| TrayData {
        conn_state: app.conn_state,
        status: app.status.clone(),
        servers: app.profiles.iter().map(|p| p.name.clone()).collect(),
        selected: app.settings.selected,
        autostart: app.autostart,
    })
}

fn refresh_tray() {
    let data = tray_state();
    with_app(|app| {
        if let Some(t) = &app.tray {
            t.update(&data.as_ref());
        }
    });
}

fn show_window(ui: &AppWindow) {
    let _ = ui.show();
    ui.window().set_minimized(false);
    let _ = style_window(ui);
}

fn poll_tray(ui: &AppWindow) {
    use tray_icon::menu::MenuEvent;
    use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

    while let Ok(ev) = MenuEvent::receiver().try_recv() {
        let id = ev.id.as_ref().to_string();
        match id.as_str() {
            "open" => show_window(ui),
            "toggle" => toggle(ui),
            "autostart" => {
                let on = !with_app(|app| app.autostart);
                set_autostart(ui, on);
            }
            "quit" => {
                let _ = slint::quit_event_loop();
            }
            other => {
                if let Some(i) = other.strip_prefix("srv:").and_then(|s| s.parse::<usize>().ok()) {
                    select_server(ui, i);
                    // Выбор сервера из трея при выключенном VPN — сразу подключаемся.
                    if with_app(|app| app.runner.is_none()) {
                        connect(ui);
                    }
                }
            }
        }
    }
    while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
        match ev {
            TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
            | TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } => show_window(ui),
            _ => {}
        }
    }
}
