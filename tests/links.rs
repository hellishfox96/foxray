use foxray::link::{parse, LinkError, Proto, Security, Transport};
use foxray::{build_config, Rules, Settings};

const REALITY: &str = "vless://3f1c2a9e-1111-4c2b-9d3e-abcdefabcdef@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80";

#[test]
fn vless_reality() {
    let p = parse(REALITY).unwrap();
    assert_eq!(p.name, "Мой сервер");
    assert_eq!(p.server, "203.0.113.10");
    assert_eq!(p.port, 443);
    let Proto::Vless(v) = &p.proto else { panic!() };
    assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(v.transport, Transport::Tcp);
    match &v.security {
        Security::Reality { sni, public_key, short_id, fingerprint } => {
            assert_eq!(sni.as_deref(), Some("www.microsoft.com"));
            assert_eq!(public_key, "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc");
            assert_eq!(short_id.as_deref(), Some("6ba85179e30d4fc2"));
            assert_eq!(fingerprint, "chrome");
        }
        s => panic!("{s:?}"),
    }
}

#[test]
fn vless_reality_grpc_no_name() {
    let p = parse("vless://uuid-1@example.com:8443?security=reality&pbk=KEY&type=grpc&serviceName=svc").unwrap();
    assert_eq!(p.name, "example.com:8443");
    let Proto::Vless(v) = &p.proto else { panic!() };
    assert_eq!(v.transport, Transport::Grpc { service_name: "svc".into() });
}

#[test]
fn vless_errors() {
    assert_eq!(
        parse("vless://u@h.com:443?security=reality").unwrap_err(),
        LinkError::Missing("pbk (публичный ключ Reality)")
    );
    assert!(matches!(
        parse("vless://u@h.com:443?security=reality&pbk=k&type=xhttp").unwrap_err(),
        LinkError::UnsupportedTransport(_)
    ));
    assert!(matches!(parse("vmess://abc").unwrap_err(), LinkError::UnsupportedScheme(_)));
}

#[test]
fn hy2_basic() {
    let p = parse("hy2://p%40ss@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=xyz&insecure=1#HY").unwrap();
    assert_eq!(p.name, "HY");
    assert_eq!(p.port, 8443);
    let Proto::Hysteria2(h) = &p.proto else { panic!() };
    assert_eq!(h.password, "p@ss");
    assert!(h.insecure);
    assert_eq!(h.obfs_password.as_deref(), Some("xyz"));
}

#[test]
fn hy2_userpass_and_default_port() {
    let p = parse("hysteria2://user:secret@1.2.3.4?sni=a.b").unwrap();
    assert_eq!(p.port, 443);
    let Proto::Hysteria2(h) = &p.proto else { panic!() };
    assert_eq!(h.password, "user:secret");
}

#[test]
fn hy2_port_hopping() {
    let p = parse("hy2://pw@h.example:443,20000-30000/?sni=h.example").unwrap();
    assert_eq!(p.port, 443);
    let Proto::Hysteria2(h) = &p.proto else { panic!() };
    assert_eq!(h.port_hopping, vec!["443:443", "20000:30000"]);

    let p = parse("hy2://pw@h.example:443/?mport=40000-50000").unwrap();
    let Proto::Hysteria2(h) = &p.proto else { panic!() };
    assert_eq!(h.port_hopping, vec!["40000:50000"]);
}

#[test]
fn ipv6_host() {
    let p = parse("hy2://pw@[2001:db8::1]:443").unwrap();
    assert_eq!(p.server, "2001:db8::1");
}

#[test]
fn config_lan_bypass() {
    let p = parse(REALITY).unwrap();
    let (cfg, _) = build_config(&p, &Settings::default(), &Rules::default());
    let excl = cfg["inbounds"][0]["route_exclude_address"].as_array().unwrap();
    assert!(excl.iter().any(|v| v == "192.168.0.0/16"));
    assert_eq!(cfg["outbounds"][0]["tls"]["reality"]["public_key"], "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc");
    assert_eq!(cfg["route"]["final"], "proxy");

    let (off, _) = build_config(&p, &Settings { lan_bypass: false, ..Default::default() }, &Rules::default());
    // Без обхода LAN в исключениях остаётся только адрес самого сервера.
    assert_eq!(off["inbounds"][0]["route_exclude_address"], serde_json::json!(["203.0.113.10/32"]));
}

#[test]
fn subscription_decode_and_ping_parse() {
    use base64::Engine;
    let links = "vless://u@a.b:443?security=reality&pbk=k#A\nhy2://p@c.d:443#B\n";
    let b64 = base64::engine::general_purpose::STANDARD.encode(links);
    let (list, errs) = foxray::parse_many(&foxray::subs::decode_body(&b64));
    assert_eq!((list.len(), errs.len()), (2, 0));
    let nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(links);
    assert_eq!(foxray::parse_many(&foxray::subs::decode_body(&nopad)).0.len(), 2);
    assert_eq!(foxray::subs::decode_body(links).lines().count(), 2);
    assert_eq!(foxray::net::parse_ping_ms("Ответ от 1.2.3.4: число байт=32 время=23мс TTL=57"), Some(23));
    assert_eq!(foxray::net::parse_ping_ms("64 bytes: icmp_seq=1 ttl=57 time=12.6 ms"), Some(13));
    assert_eq!(foxray::net::parse_ping_ms("Reply from 1.2.3.4: bytes=32 time<1ms TTL=128"), Some(1));
}

#[test]
fn link_roundtrip() {
    let links = [
        REALITY,
        "vless://uuid-1@example.com:8443?security=reality&pbk=KEY&type=grpc&serviceName=svc#gRPC",
        "vless://u@h.com:443?security=tls&sni=h.com&alpn=h2,http/1.1&type=ws&path=/a%20b&host=h.com#WS",
        "hy2://p%40ss@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=xyz&insecure=1&mport=20000-30000#HY%20два",
        "hy2://pw@[2001:db8::1]:443?upmbps=50&downmbps=200#v6",
    ];
    for l in links {
        let p = parse(l).unwrap();
        let back = parse(&p.to_link()).unwrap_or_else(|e| panic!("{l} → {} : {e}", p.to_link()));
        assert_eq!(p, back, "{}", p.to_link());
    }
}

#[test]
fn server_ips_bypass_tunnel() {
    let p = foxray::parse("hy2://pw@vpn.example.com:443?sni=vpn.example.com#t").unwrap();
    let s = Settings { server_ips: vec!["203.0.113.7".parse().unwrap()], ..Default::default() };
    let (cfg, _) = build_config(&p, &s, &Rules::default());
    let ex = cfg["inbounds"][0]["route_exclude_address"].to_string();
    assert!(ex.contains("203.0.113.7/32"), "{ex}");
    assert!(cfg["route"]["rules"].to_string().contains("203.0.113.7/32"));
}

#[test]
fn custom_dns_home_and_public() {
    let p = foxray::parse("hy2://pw@1.2.3.4:443#t").unwrap();
    let home = Settings { custom_dns: Some("192.168.1.10".into()), ..Default::default() };
    let (cfg, errs) = build_config(&p, &home, &Rules::default());
    assert!(errs.is_empty());
    let srv = &cfg["dns"]["servers"][0];
    assert_eq!(srv["type"], "udp");
    assert_eq!(srv["server"], "192.168.1.10");
    assert_eq!(srv["server_port"], 53);
    assert!(srv.get("detour").is_none(), "домашний DNS — без detour (напрямую)");
    // домашние суффиксы тоже идут в домашний DNS, адрес VPN-сервера — в системный
    assert_eq!(cfg["dns"]["rules"][0]["server"], "dns-remote");
    assert_eq!(cfg["dns"]["rules"][1]["server"], "dns-local");

    let public = Settings { custom_dns: Some("8.8.8.8:53".into()), ..Default::default() };
    let (cfg, _) = build_config(&p, &public, &Rules::default());
    assert_eq!(cfg["dns"]["servers"][0]["detour"], "proxy");
    assert_eq!(cfg["dns"]["rules"][0]["server"], "dns-local");

    let bad = Settings { custom_dns: Some("adguard".into()), ..Default::default() };
    let (cfg, errs) = build_config(&p, &bad, &Rules::default());
    assert_eq!(cfg["dns"]["servers"][0]["type"], "https");
    assert_eq!(errs.len(), 1);
}

#[test]
fn linux_local_dns_bypasses_resolved_stub() {
    // DNS «напрямую» — прямо на DNS сети, мимо туннеля (иначе в Linux он ходит по кругу через resolved).
    let p = parse(REALITY).unwrap();
    let s = Settings { local_dns: vec!["192.168.1.1".parse().unwrap()], ..Default::default() };
    let (cfg, _) = build_config(&p, &s, &Rules::default());
    let local = cfg["dns"]["servers"].as_array().unwrap().iter().find(|x| x["tag"] == "dns-local").unwrap().clone();
    assert_eq!(local["type"], "udp");
    assert_eq!(local["server"], "192.168.1.1");
    // без него — системный
    let (cfg, _) = build_config(&p, &Settings::default(), &Rules::default());
    let local = cfg["dns"]["servers"].as_array().unwrap().iter().find(|x| x["tag"] == "dns-local").unwrap().clone();
    assert_eq!(local["type"], "local");
}


#[test]
fn tun_address_not_docker() {
    // Не пересекаться с сетями Docker (172.17–172.31) — см. config::TUN_ADDR4.
    let p = parse(REALITY).unwrap();
    let (cfg, _) = build_config(&p, &Settings::default(), &Rules::default());
    let a = cfg["inbounds"][0]["address"][0].as_str().unwrap();
    assert_eq!(a, "198.18.0.1/30");
}

#[test]
fn remote_desktop_direct() {
    // RDP-клиенты и порт 3389 — мимо VPN; переключатель в настройках выключает.
    let p = parse(REALITY).unwrap();
    let has = |s: &Settings| {
        let (cfg, _) = build_config(&p, s, &Rules::default());
        let r = cfg["route"]["rules"].as_array().unwrap().clone();
        let proc = r.iter().any(|x| x["process_name"].as_array().is_some_and(|a| a.iter().any(|v| v == "mstsc.exe") && a.iter().any(|v| v == "xfreerdp")) && x["outbound"] == "direct");
        let port = r.iter().any(|x| x["port"] == serde_json::json!([3389]) && x["outbound"] == "direct");
        (proc, port)
    };
    assert_eq!(has(&Settings::default()), (true, true));
    assert_eq!(has(&Settings { remote_direct: false, ..Default::default() }), (false, false));
}
