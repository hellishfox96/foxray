//! Редактор сервера: профиль ⇄ поля формы.
//! Сохранение собирает из полей ссылку и прогоняет её через обычный разбор —
//! так проверки одни и те же для ссылок и ручного ввода.

use foxray::link::{parse, Profile, Proto};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::HashMap;

#[derive(Clone)]
pub struct EditState {
    /// None — новый сервер
    pub index: Option<usize>,
    /// 0 — VLESS, 1 — Hysteria2
    pub proto: i32,
    pub values: HashMap<String, String>,
    /// Подписка исходного сервера (сохраняем как было)
    pub sub: Option<String>,
}

/// Описание поля для интерфейса.
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    /// 0 текст, 1 переключатель, 2 выбор
    pub kind: i32,
    /// Для выбора: (значение, подпись)
    pub options: &'static [(&'static str, &'static str)],
}

const SECURITY: &[(&str, &str)] = &[("reality", "Reality"), ("tls", "TLS"), ("none", "Нет")];
const TRANSPORT: &[(&str, &str)] = &[("tcp", "TCP"), ("grpc", "gRPC"), ("ws", "WS"), ("httpupgrade", "HTTPUpgrade")];

const fn text(key: &'static str, label: &'static str, hint: &'static str) -> Field {
    Field { key, label, hint, kind: 0, options: &[] }
}

impl EditState {
    pub fn new_server() -> Self {
        let mut values = HashMap::new();
        values.insert("security".into(), "reality".into());
        values.insert("type".into(), "tcp".into());
        values.insert("fp".into(), "chrome".into());
        values.insert("port".into(), "443".into());
        values.insert("flow".into(), "xtls-rprx-vision".into());
        Self { index: None, proto: 0, values, sub: None }
    }

    /// Значения полей из существующего сервера (через его ссылку).
    pub fn from_profile(index: usize, p: &Profile) -> Self {
        let mut values = HashMap::new();
        if let Ok(u) = url::Url::parse(&p.to_link()) {
            for (k, v) in u.query_pairs() {
                values.insert(k.to_string(), v.to_string());
            }
        }
        values.insert("name".into(), p.name.clone());
        values.insert("server".into(), p.server.clone());
        values.insert("port".into(), p.port.to_string());
        let (proto, user) = match &p.proto {
            Proto::Vless(v) => (0, v.uuid.clone()),
            Proto::Hysteria2(h) => (1, h.password.clone()),
        };
        values.insert("user".into(), user);
        Self { index: Some(index), proto, values, sub: p.sub.clone() }
    }

    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map(|s| s.as_str()).unwrap_or("")
    }

    /// Какие поля показывать — зависит от протокола и выбранных вариантов.
    pub fn fields(&self) -> Vec<Field> {
        let mut f = vec![
            text("name", "Название", "как сервер будет называться в списке"),
            text("server", "Адрес", "IP или домен сервера"),
            text("port", "Порт", "обычно 443"),
        ];
        if self.proto == 0 {
            f.push(text("user", "UUID", "идентификатор пользователя"));
            f.push(Field { key: "security", label: "Защита", hint: "", kind: 2, options: SECURITY });
            match self.get("security") {
                "reality" => {
                    f.push(text("sni", "SNI (маскировочный сайт)", "например, www.microsoft.com"));
                    f.push(text("pbk", "Публичный ключ (pbk)", "из настроек сервера"));
                    f.push(text("sid", "Short ID (sid)", "можно оставить пустым"));
                    f.push(text("fp", "Отпечаток браузера (fp)", "chrome, firefox, safari…"));
                    f.push(text("flow", "Flow", "xtls-rprx-vision или пусто"));
                }
                "tls" => {
                    f.push(text("sni", "SNI", "домен сертификата"));
                    f.push(text("fp", "Отпечаток браузера (fp)", "можно оставить пустым"));
                    f.push(text("alpn", "ALPN", "например, h2,http/1.1"));
                    f.push(Field { key: "allowInsecure", label: "Не проверять сертификат", hint: "небезопасно", kind: 1, options: &[] });
                    f.push(text("flow", "Flow", "xtls-rprx-vision или пусто"));
                }
                _ => {}
            }
            f.push(Field { key: "type", label: "Транспорт", hint: "", kind: 2, options: TRANSPORT });
            match self.get("type") {
                "grpc" => f.push(text("serviceName", "gRPC service name", "")),
                "ws" | "httpupgrade" => {
                    f.push(text("path", "Путь", "например, /ws"));
                    f.push(text("host", "Host", "можно оставить пустым"));
                }
                _ => {}
            }
        } else {
            f.push(text("user", "Пароль", "пароль пользователя Hysteria2"));
            f.push(text("sni", "SNI", "домен сертификата"));
            f.push(Field { key: "insecure", label: "Не проверять сертификат", hint: "для самоподписанных", kind: 1, options: &[] });
            f.push(text("obfs-password", "Пароль обфускации (salamander)", "пусто — без обфускации"));
            f.push(text("mport", "Прыжки по портам", "например, 20000-30000"));
            f.push(text("upmbps", "Отдача, Мбит/с", "пусто — автоматически"));
            f.push(text("downmbps", "Загрузка, Мбит/с", "пусто — автоматически"));
        }
        f
    }

    /// Новое значение поля. Для выбора приходит номер варианта.
    pub fn set(&mut self, field: &Field, value: &str) {
        let v = if field.kind == 2 {
            value.parse::<usize>().ok().and_then(|i| field.options.get(i)).map(|o| o.0).unwrap_or("").to_string()
        } else {
            value.to_string()
        };
        self.values.insert(field.key.to_string(), v);
    }

    pub fn choice(&self, field: &Field) -> i32 {
        field.options.iter().position(|o| o.0 == self.get(field.key)).unwrap_or(0) as i32
    }

    /// Собрать ссылку и разобрать её.
    pub fn build(&self) -> Result<Profile, String> {
        let host = self.get("server").trim();
        if host.is_empty() {
            return Err("Укажи адрес сервера".into());
        }
        let port = self.get("port").trim();
        if port.parse::<u16>().map_or(true, |p| p == 0) {
            return Err("Порт — число от 1 до 65535".into());
        }
        let user = self.get("user").trim();
        if user.is_empty() {
            return Err(if self.proto == 0 { "Укажи UUID" } else { "Укажи пароль" }.into());
        }
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };

        let keys: &[&str] = if self.proto == 0 {
            &["security", "sni", "pbk", "sid", "fp", "alpn", "allowInsecure", "flow", "type", "serviceName", "path", "host"]
        } else {
            &["sni", "insecure", "obfs-password", "mport", "upmbps", "downmbps"]
        };
        // Берём только поля, которые сейчас на экране (скрытые не тянем).
        let visible: Vec<&str> = self.fields().iter().map(|f| f.key).collect();
        let mut q: Vec<String> = Vec::new();
        if self.proto == 0 {
            q.push("encryption=none".into());
        }
        for k in keys {
            if !visible.contains(k) {
                continue;
            }
            let v = self.get(k).trim();
            if v.is_empty() {
                continue;
            }
            if *k == "obfs-password" {
                q.push("obfs=salamander".into());
            }
            q.push(format!("{k}={}", enc(v)));
        }
        let scheme = if self.proto == 0 { "vless" } else { "hysteria2" };
        let slash = if self.proto == 0 { "" } else { "/" };
        let mut link = format!("{scheme}://{}@{host}:{port}{slash}?{}", enc(user), q.join("&"));
        let name = self.get("name").trim();
        if !name.is_empty() {
            link += &format!("#{}", enc(name));
        }
        let mut p = parse(&link).map_err(|e| {
            let s = e.to_string();
            let mut c = s.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        })?;
        p.sub = self.sub.clone();
        Ok(p)
    }
}

fn enc(s: &str) -> String {
    const KEEP: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    utf8_percent_encode(s, KEEP).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_form() {
        for l in [
            "vless://3f1c2a9e@203.0.113.10:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=KEY&sid=6ba8&type=tcp#Мой",
            "vless://u@h.com:443?security=tls&sni=h.com&alpn=h2&type=ws&path=/a&host=h.com#WS",
            "hy2://p%40ss@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=xyz&insecure=1&mport=20000-30000#HY",
        ] {
            let p = parse(l).unwrap();
            let st = EditState::from_profile(0, &p);
            assert_eq!(st.build().unwrap(), p, "{l}");
        }
    }

    #[test]
    fn new_server_validation() {
        let mut st = EditState::new_server();
        assert!(st.build().is_err());
        st.values.insert("server".into(), "1.2.3.4".into());
        st.values.insert("user".into(), "uuid".into());
        assert!(st.build().unwrap_err().contains("pbk"));
        st.values.insert("pbk".into(), "KEY".into());
        let p = st.build().unwrap();
        assert_eq!(p.name, "1.2.3.4:443");
    }
}
