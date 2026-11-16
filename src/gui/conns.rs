//! Страница «Соединения»: что сейчас открыто через Foxray и куда оно пошло.
//! Данные — из Clash API sing-box (/connections), раз в секунду, в фоновом потоке.
//! VPN выключен — из системы (foxray::sysconns): программа, адрес и порт, без доменов и трафика.

use super::*;
use foxray::runner::{self, Conn};
use foxray::sysconns::{self, SysConn};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use slint::Model;
use std::rc::Rc;
use std::sync::Arc;

thread_local! {
    static MODEL: std::cell::OnceCell<Rc<VecModel<ConnRow>>> = const { std::cell::OnceCell::new() };
}

#[derive(Default)]
pub(super) struct ConnState {
    /// Флаг работы опроса (страница открыта).
    watch: Option<Arc<AtomicBool>>,
    /// Порт Clash API текущего подключения (0 — VPN не подключён).
    pub(super) api_port: u16,
    last: Option<Vec<Conn>>,
    search: String,
    /// Что считать zapret: домены (суффиксы / точные) и программы.
    zap: ZapMatch,
    /// Соединения из последней статистики (каждые 2 с, пока подключены) — для «Трафика» на главной.
    pub(super) home: Vec<Conn>,
    /// VPN выключен: соединения из системы.
    sys: Option<Vec<SysConn>>,
    /// Когда соединение из системы впервые увидели (ключ — SysConn::key).
    sys_seen: HashMap<String, Instant>,
}

pub(super) fn setup(ui: &AppWindow) {
    let w = ui.as_weak();
    ui.on_open_conns(move || open(&w.unwrap()));
    let w = ui.as_weak();
    ui.on_close_conns(move || close(&w.unwrap()));
    let w = ui.as_weak();
    ui.on_conn_search(move |t| {
        with_app(|app| app.conns.search = t.to_string());
        render(&w.unwrap());
    });
    let w = ui.as_weak();
    ui.on_conn_close(move |id| {
        let port = with_app(|app| app.conns.api_port);
        let id = id.to_string();
        // Сразу убираем из списка — не ждём следующего опроса.
        with_app(|app| {
            if let Some(l) = app.conns.last.as_mut() {
                l.retain(|c| c.id != id);
            }
        });
        render(&w.unwrap());
        std::thread::spawn(move || runner::close_connection(port, &id));
    });
}

/// Что считать zapret — по тем же спискам, что идут в конфиг.
#[derive(Default, Clone)]
pub(super) struct ZapMatch {
    suffix: Vec<String>,
    full: Vec<String>,
    procs: Vec<String>,
    /// Адреса из «Своих сайтов» (для соединений из системы — там нет доменов).
    cidrs: Vec<(IpAddr, u8)>,
    /// Программы игр («Zapret → Игры»).
    games: Vec<String>,
}

/// «104.16.0.0/13», «1.2.3.4», «ip:…» → (адрес, длина префикса).
fn parse_cidr(e: &str) -> Option<(IpAddr, u8)> {
    let e = e.strip_prefix("ip:").unwrap_or(e);
    let (a, n) = e.split_once('/').unwrap_or((e, ""));
    let ip: IpAddr = a.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let n = if n.is_empty() { max } else { n.trim().parse().ok()? };
    (n <= max).then_some((ip, n))
}

fn in_cidr(ip: IpAddr, (net, n): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => n == 0 || (u32::from(a) ^ u32::from(b)) >> (32 - n as u32) == 0,
        (IpAddr::V6(a), IpAddr::V6(b)) => n == 0 || (u128::from(a) ^ u128::from(b)) >> (128 - n as u32) == 0,
        _ => false,
    }
}

impl ZapMatch {
    /// Списки zapret (пусто, если zapret выключен). Вызывать вне with_app.
    pub(super) fn current() -> Self {
        let mut z = ZapMatch::default();
        if let Some(list) = zap::routing_list() {
            for e in list.entries {
                if let Some(d) = e.strip_prefix("full:") {
                    z.full.push(d.to_ascii_lowercase());
                } else if let Some(p) = e.strip_prefix("process:") {
                    z.procs.push(p.to_string());
                } else if e.to_ascii_lowercase().ends_with(".exe") {
                    z.procs.push(e.clone());
                } else if let Some(c) = parse_cidr(&e) {
                    z.cidrs.push(c);
                } else if e.contains(':') || e.contains('/') {
                    // наборы по имени хоста не сравнить — пропускаем
                } else {
                    z.suffix.push(e.to_ascii_lowercase());
                }
            }
        }
        z.games = zap::game_procs();
        z
    }

    /// Соединение из системы: (1 zapret, 2 напрямую) и подпись.
    fn classify_sys(&self, c: &SysConn) -> (i32, &'static str) {
        let named = |list: &[String]| {
            list.iter().any(|p| p.eq_ignore_ascii_case(&c.exe) || p.eq_ignore_ascii_case(&c.process))
        };
        if named(&self.games) {
            (1, "zapret · игра")
        } else if named(&self.procs) || c.remote.is_some_and(|(ip, _)| self.cidrs.iter().any(|n| in_cidr(ip, *n))) {
            (1, "zapret")
        } else {
            (2, "напрямую")
        }
    }

    fn is_zap(&self, c: &Conn) -> bool {
        if c.outbound != "direct" {
            return false;
        }
        let h = c.host.to_ascii_lowercase();
        self.full.iter().any(|d| *d == h)
            || self.suffix.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
            || (!c.process.is_empty() && self.procs.iter().any(|p| p.eq_ignore_ascii_case(&c.process)))
    }

    /// Куда ушло соединение: (0 VPN, 1 zapret, 2 напрямую, 4 прочее) и подпись.
    pub(super) fn classify<'a>(&self, c: &'a Conn) -> (i32, &'a str) {
        match c.outbound.as_str() {
            "proxy" => (0, "VPN"),
            "direct" if self.is_zap(c) => (1, "zapret"),
            "direct" => (2, "напрямую"),
            "" => (4, "?"),
            other => (4, other),
        }
    }
}

fn open(ui: &AppWindow) {
    let zm = ZapMatch::current();
    let flag = Arc::new(AtomicBool::new(true));
    with_app(|app| {
        if let Some(old) = app.conns.watch.take() {
            old.store(false, Ordering::SeqCst);
        }
        app.conns.watch = Some(flag.clone());
        app.conns.zap = zm;
        app.conns.last = None;
        app.conns.sys = None;
        app.conns.sys_seen.clear();
    });
    ui.set_home_view(1);
    render(ui);

    let w = ui.as_weak();
    std::thread::spawn(move || {
        while flag.load(Ordering::SeqCst) {
            let port = {
                let (tx, rx) = std::sync::mpsc::channel();
                let _ = slint::invoke_from_event_loop(move || {
                    let _ = tx.send(with_app(|app| app.conns.api_port));
                });
                rx.recv_timeout(Duration::from_secs(2)).unwrap_or(0)
            };
            let list = if port != 0 { runner::connections(port) } else { None };
            let sys = if port == 0 { Some(sysconns::list()) } else { None };
            let w2 = w.clone();
            let f2 = flag.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if !f2.load(Ordering::SeqCst) {
                    return;
                }
                with_app(|app| {
                    app.conns.last = list;
                    if let Some(s) = &sys {
                        let now = Instant::now();
                        let keys: HashSet<String> = s.iter().map(|c| c.key()).collect();
                        app.conns.sys_seen.retain(|k, _| keys.contains(k));
                        for k in keys {
                            app.conns.sys_seen.entry(k).or_insert(now);
                        }
                    }
                    app.conns.sys = sys;
                });
                if let Some(ui) = w2.upgrade() {
                    render(&ui);
                }
            });
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

fn close(ui: &AppWindow) {
    with_app(|app| {
        if let Some(f) = app.conns.watch.take() {
            f.store(false, Ordering::SeqCst);
        }
        app.conns.last = None;
        app.conns.sys = None;
    });
    ui.set_home_view(0);
}

/// VPN выключили, пока страница открыта.
pub(super) fn vpn_stopped() {
    with_app(|app| {
        app.conns.api_port = 0;
        app.conns.home.clear();
    });
}

fn age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} с"),
        60..=3599 => format!("{} мин", secs / 60),
        _ => format!("{} ч {} мин", secs / 3600, secs / 60 % 60),
    }
}

fn render(ui: &AppWindow) {
    let system = with_app(|app| app.conns.last.is_none() && app.conns.sys.is_some());
    let zapret_on = zap::routing_active();
    let (rows, title, note) = if system { render_sys(zapret_on) } else { with_app(|app| {
        let st = &app.conns;
        let Some(list) = st.last.as_ref() else {
            let note = if st.api_port == 0 {
                "VPN не подключён — соединения видны, пока он включён."
            } else {
                "Загружаю…"
            };
            return (Vec::new(), String::new(), note.to_string());
        };
        let q = st.search.trim().to_lowercase();
        let mut items: Vec<(&Conn, i32, &str)> = list
            .iter()
            .map(|c| {
                let (kind, route) = st.zap.classify(c);
                (c, kind, route)
            })
            .filter(|(c, _, route)| {
                q.is_empty()
                    || c.host.to_lowercase().contains(&q)
                    || c.process.to_lowercase().contains(&q)
                    || route.to_lowercase().contains(&q)
            })
            .collect();
        // Сверху — те, что прокачали больше.
        items.sort_by(|a, b| (b.0.down + b.0.up).cmp(&(a.0.down + a.0.up)).then(a.0.host.cmp(&b.0.host)));
        let total = list.len();
        let title = if q.is_empty() { format!("{total}") } else { format!("{} из {total}", items.len()) };
        // Группы по программе: сверху та, что прокачала больше; внутри — так же.
        let mut groups: Vec<(String, u64, Vec<(&Conn, i32, &str)>)> = Vec::new();
        for it in items {
            let name = if it.0.process.is_empty() { "ДРУГОЕ".to_string() } else { it.0.process.to_uppercase() };
            let bytes = it.0.down + it.0.up;
            match groups.iter_mut().find(|g| g.0 == name) {
                Some(g) => {
                    g.1 += bytes;
                    g.2.push(it);
                }
                None => groups.push((name, bytes, vec![it])),
            }
        }
        groups.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut rows: Vec<ConnRow> = Vec::new();
        for (name, _, list) in groups {
            rows.push(ConnRow { host: format!("{name} · {}", list.len()).into(), header: true, ..Default::default() });
            let n = list.len();
            for (k, (c, kind, route)) in list.into_iter().enumerate() {
                let mut sub = Vec::new();
                if !c.network.is_empty() {
                    sub.push(format!("{}:{}", c.network.to_uppercase(), c.port));
                }
                if let Some(a) = c.age_secs {
                    sub.push(age(a));
                }
                rows.push(ConnRow {
                    id: c.id.clone().into(),
                    host: c.host.clone().into(),
                    sub: sub.join(" · ").into(),
                    route: route.into(),
                    traffic: format!("↓ {}  ↑ {}", human_bytes(c.down), human_bytes(c.up)).into(),
                    kind,
                    header: false,
                    first: k == 0,
                    last: k + 1 == n,
                });
            }
        }
        let note = if total == 0 { "Открытых соединений нет.".to_string() } else { String::new() };
        (rows, title, note)
    }) };
    ui.set_conn_system(system);
    ui.set_conn_zapret(system && zapret_on);
    // Обновляем строки на месте, а не новой моделью: иначе Slint пересоздаёт строки каждую
    // секунду и теряется наведение (крестик бы мигал).
    MODEL.with(|m| {
        let model = m.get_or_init(|| {
            let vm = Rc::new(VecModel::<ConnRow>::default());
            ui.set_conn_rows(ModelRc::from(vm.clone()));
            vm
        });
        for (i, r) in rows.iter().enumerate() {
            if i < model.row_count() {
                if model.row_data(i).as_ref() != Some(r) {
                    model.set_row_data(i, r.clone());
                }
            } else {
                model.push(r.clone());
            }
        }
        while model.row_count() > rows.len() {
            model.remove(model.row_count() - 1);
        }
    });
    ui.set_conn_title(title.into());
    ui.set_conn_note(note.into());
}

/// Строки страницы из соединений системы (VPN выключен).
fn render_sys(zapret_on: bool) -> (Vec<ConnRow>, String, String) {
    with_app(|app| {
        let st = &app.conns;
        let list = st.sys.as_deref().unwrap_or_default();
        let q = st.search.trim().to_lowercase();
        let now = Instant::now();
        let mut items: Vec<(&SysConn, i32, &str)> = list
            .iter()
            .map(|c| {
                let (kind, route) = st.zap.classify_sys(c);
                (c, kind, route)
            })
            // UDP без адреса — только у Discord и игр (иначе браузер даёт десятки пустых строк).
            .filter(|(c, kind, _)| c.remote.is_some() || *kind == 1)
            .filter(|(c, _, route)| {
                q.is_empty()
                    || c.process.to_lowercase().contains(&q)
                    || c.exe.to_lowercase().contains(&q)
                    || route.to_lowercase().contains(&q)
                    || c.remote.is_some_and(|(ip, p)| format!("{ip}:{p}").contains(&q))
                    || format!("{}:{}", c.network, c.remote.map_or(c.local_port, |r| r.1)).contains(&q)
            })
            .collect();
        let total = items.len();
        let all = list.iter().filter(|c| c.remote.is_some() || st.zap.classify_sys(c).0 == 1).count();
        let shown = if q.is_empty() { format!("{all}") } else { format!("{total} из {all}") };
        let title = format!("{} · {shown}", if zapret_on { "только zapret" } else { "без VPN" });
        // Группы по программе: сверху zapret (игры, Discord), потом самые многочисленные.
        items.sort_by(|a, b| a.0.remote.is_none().cmp(&b.0.remote.is_none()).then(a.0.remote.cmp(&b.0.remote)));
        let mut groups: Vec<(String, i32, Vec<(&SysConn, i32, &str)>)> = Vec::new();
        for it in items {
            let name = if it.0.process.is_empty() { "ДРУГОЕ".to_string() } else { it.0.process.to_uppercase() };
            match groups.iter_mut().find(|g| g.0 == name) {
                Some(g) => {
                    g.1 = g.1.min(it.1);
                    g.2.push(it);
                }
                None => groups.push((name, it.1, vec![it])),
            }
        }
        groups.sort_by(|a, b| a.1.cmp(&b.1).then(b.2.len().cmp(&a.2.len())).then(a.0.cmp(&b.0)));
        let mut rows: Vec<ConnRow> = Vec::new();
        for (name, _, list) in groups {
            rows.push(ConnRow { host: format!("{name} · {}", list.len()).into(), header: true, ..Default::default() });
            let n = list.len();
            for (k, (c, kind, route)) in list.into_iter().enumerate() {
                let secs = st.sys_seen.get(&c.key()).map(|t| now.duration_since(*t).as_secs()).unwrap_or(0);
                let (host, sub) = match c.remote {
                    Some((ip, port)) => (
                        ip.to_string(),
                        format!("{}:{port} · {}", c.network.to_uppercase(), if c.connecting { "подключается…".to_string() } else { age(secs) }),
                    ),
                    None => ("UDP-сокет".to_string(), format!("локальный порт {} · {}", c.local_port, age(secs))),
                };
                rows.push(ConnRow {
                    id: c.key().into(),
                    host: host.into(),
                    sub: sub.into(),
                    route: route.into(),
                    traffic: SharedString::new(),
                    kind,
                    header: false,
                    first: k == 0,
                    last: k + 1 == n,
                });
            }
        }
        let note = if all == 0 { "Открытых соединений нет.".to_string() } else { String::new() };
        (rows, title, note)
    })
}
