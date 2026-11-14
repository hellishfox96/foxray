//! Иконка в трее с меню.

use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// Снимок состояния для трея (своё, без ссылок — в Linux его передают в поток GTK).
#[derive(Clone)]
#[cfg_attr(windows, allow(dead_code))]
pub struct TrayData {
    pub conn_state: i32,
    pub status: String,
    pub servers: Vec<String>,
    pub selected: Option<usize>,
    pub autostart: bool,
}

pub struct TrayState<'a> {
    pub conn_state: i32,
    pub status: &'a str,
    pub servers: Vec<String>,
    pub selected: Option<usize>,
    pub autostart: bool,
}

#[cfg_attr(windows, allow(dead_code))]
impl TrayState<'_> {
    fn owned(&self) -> TrayData {
        TrayData {
            conn_state: self.conn_state,
            status: self.status.to_string(),
            servers: self.servers.clone(),
            selected: self.selected,
            autostart: self.autostart,
        }
    }
}

#[cfg_attr(windows, allow(dead_code))]
impl TrayData {
    fn view(&self) -> TrayState<'_> {
        TrayState {
            conn_state: self.conn_state,
            status: &self.status,
            servers: self.servers.clone(),
            selected: self.selected,
            autostart: self.autostart,
        }
    }
}

fn build(st: &TrayState) -> Result<TrayIcon, String> {
    TrayIconBuilder::new()
        .with_icon(make_icon(st.conn_state))
        .with_tooltip(tooltip(st))
        .with_menu(Box::new(build_menu(st)))
        .with_menu_on_left_click(false)
        .build()
        .map_err(|e| e.to_string())
}

fn apply(icon: &TrayIcon, st: &TrayState) {
    let _ = icon.set_icon(Some(make_icon(st.conn_state)));
    let _ = icon.set_tooltip(Some(tooltip(st)));
    icon.set_menu(Some(Box::new(build_menu(st))));
}

// ---------------------------------------------------------------- Windows и прочие
#[cfg(not(target_os = "linux"))]
pub struct Tray {
    icon: TrayIcon,
}

#[cfg(not(target_os = "linux"))]
impl Tray {
    pub fn new(st: &TrayState) -> Result<Self, String> {
        Ok(Self { icon: build(st)? })
    }

    pub fn update(&self, st: &TrayState) {
        apply(&self.icon, st);
    }

    /// Подсказка при наведении на иконку (до следующего обновления состояния).
    pub fn set_tooltip_hint(&self, text: &str) {
        let _ = self.icon.set_tooltip(Some(text.chars().take(120).collect::<String>()));
    }
}

// ---------------------------------------------------------------- Linux
// Трей в Linux работает через GTK (libayatana-appindicator): иконка живёт в своём
// потоке с циклом GTK, а окно Slint шлёт ей обновления через канал.
// События меню приходят как обычно — через общий MenuEvent::receiver().
#[cfg(target_os = "linux")]
enum Msg {
    Update(TrayData),
    Tooltip(String),
    Quit,
}

#[cfg(target_os = "linux")]
pub struct Tray {
    tx: std::sync::mpsc::Sender<Msg>,
}

#[cfg(target_os = "linux")]
impl Tray {
    pub fn new(st: &TrayState) -> Result<Self, String> {
        use gtk::glib;
        let (tx, rx) = std::sync::mpsc::channel::<Msg>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let first = st.owned();
        std::thread::Builder::new()
            .name("foxray-tray".into())
            .spawn(move || {
                if let Err(e) = gtk::init() {
                    let _ = ready_tx.send(Err(format!("GTK не запустился: {e}")));
                    return;
                }
                let icon = match build(&first.view()) {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                    loop {
                        match rx.try_recv() {
                            Ok(Msg::Update(d)) => apply(&icon, &d.view()),
                            Ok(Msg::Tooltip(t)) => {
                                let _ = icon.set_tooltip(Some(t));
                            }
                            Ok(Msg::Quit) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                let _ = icon.set_visible(false);
                                gtk::main_quit();
                                return glib::ControlFlow::Break;
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                        }
                    }
                });
                gtk::main();
            })
            .map_err(|e| e.to_string())?;
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "трей не ответил".to_string())??;
        Ok(Self { tx })
    }

    pub fn update(&self, st: &TrayState) {
        let _ = self.tx.send(Msg::Update(st.owned()));
    }

    /// Подсказка при наведении (большинство панелей Linux её не показывают).
    pub fn set_tooltip_hint(&self, text: &str) {
        let _ = self.tx.send(Msg::Tooltip(text.chars().take(120).collect()));
    }
}

#[cfg(target_os = "linux")]
impl Drop for Tray {
    fn drop(&mut self) {
        let _ = self.tx.send(Msg::Quit);
    }
}

fn tooltip(st: &TrayState) -> String {
    // Подсказка в трее Windows ограничена ~127 символами.
    let t = format!("Foxray — {}", st.status);
    t.chars().take(120).collect()
}

fn build_menu(st: &TrayState) -> Menu {
    let menu = Menu::new();
    let connected = st.conn_state == 1 || st.conn_state == 2;
    let _ = menu.append(&MenuItem::with_id("open", "Открыть Foxray", true, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id(
        "toggle",
        if connected { "Отключить" } else { "Подключить" },
        !st.servers.is_empty(),
        None,
    ));
    let sub = Submenu::new("Сервер", !st.servers.is_empty());
    for (i, name) in st.servers.iter().enumerate() {
        // '&' в меню Windows — признак горячей клавиши, экранируем.
        let label = if cfg!(windows) { name.replace('&', "&&") } else { name.clone() };
        let _ = sub.append(&CheckMenuItem::with_id(format!("srv:{i}"), label, true, st.selected == Some(i), None));
    }
    let _ = menu.append(&sub);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&CheckMenuItem::with_id("autostart", if cfg!(windows) { "Запускать с Windows" } else { "Запускать при входе" }, true, st.autostart, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("quit", "Выход", true, None));
    menu
}

/// Круглая иконка 32×32, цвет — состояние подключения.
fn make_icon(state: i32) -> Icon {
    let (r, g, b) = match state {
        2 => (0x1f, 0xa4, 0x63),
        1 => (0xd4, 0xa0, 0x17),
        3 => (0xd6, 0x45, 0x45),
        _ => (0x7a, 0x80, 0x8c),
    };
    let img = image::load_from_memory(include_bytes!("../../ui/tray.png")).expect("tray.png").to_rgba8();
    let (w, h) = img.dimensions();
    let mut rgba = img.into_raw();
    // цветная точка состояния в правом нижнем углу
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 - (w as f32 - 6.5), y as f32 - (h as f32 - 6.5));
            if dx * dx + dy * dy <= 30.0 {
                let i = ((y * w + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[r, g, b, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, w, h).expect("иконка")
}
