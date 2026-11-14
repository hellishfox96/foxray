//! Разбор настоящих стратегий zapret. Папку сборки указать в ZAPRET_DIR, иначе тест пропускается.
use foxray::zapret;
use std::path::PathBuf;

#[test]
fn real_strategies_parse() {
    let Some(dir) = std::env::var_os("ZAPRET_DIR").map(PathBuf::from) else { return };
    let list = zapret::strategies(&dir);
    assert!(list.len() > 5, "мало стратегий: {}", list.len());
    let ex = dir.join("lists").join(zapret::EXCLUDE_FILE);
    for s in &list {
        let text = std::fs::read_to_string(&s.file).unwrap();
        let args = zapret::parse_bat(&text, &dir, Some(&ex)).unwrap_or_else(|e| panic!("{}: {e}", s.id));
        assert!(args[0].starts_with("--wf-"), "{}: {:?}", s.id, &args[..2]);
        // все упомянутые файлы существуют (кроме *-user, их создаёт ensure_user_lists, и нашего исключения)
        for a in &args {
            if let Some((_, path)) = a.split_once('=') {
                if (path.ends_with(".txt") || path.ends_with(".bin")) && !path.contains("-user") && !path.contains("foxray") {
                    assert!(std::path::Path::new(path).exists(), "{}: нет файла {path}", s.id);
                }
            }
        }
        println!("{:<22} {:>3} аргументов", s.title, args.len());
    }
    let d = zapret::domains(&dir);
    assert!(d.iter().any(|x| x == "discord.com"));
    assert!(d.iter().any(|x| x == "youtube.com"));
    assert!(d.iter().any(|x| x == "full:dns.google"));
    for e in &d {
        foxray::rules::parse_entry(e).unwrap_or_else(|err| panic!("{e}: {err}"));
    }
    println!("доменов: {}", d.len());
}

/// Linux: каждая стратегия, переведённая для nfqws, проходит его проверку параметров (--dry-run).
/// Путь к nfqws — в NFQWS, папка сборки — в ZAPRET_DIR; иначе пропуск.
#[cfg(target_os = "linux")]
#[test]
fn strategies_pass_nfqws_dry_run() {
    let (Some(dir), Some(nfqws)) = (std::env::var_os("ZAPRET_DIR").map(PathBuf::from), std::env::var_os("NFQWS")) else {
        return;
    };
    zapret::ensure_user_lists(&dir);
    let ex = zapret::write_exclude(&dir, &[]);
    for s in zapret::strategies(&dir) {
        let text = std::fs::read_to_string(&s.file).unwrap();
        let win = zapret::parse_bat(&text, &dir, Some(&ex)).unwrap();
        let (args, tcp, _udp) = foxray::nfq::plan(&win).unwrap();
        assert!(!tcp.is_empty(), "{}", s.id);
        let out = std::process::Command::new(&nfqws)
            .arg(format!("--qnum={}", foxray::nfq::QNUM))
            .arg("--uid=0:0")
            .args(&args)
            .arg("--dry-run")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}: nfqws отверг параметры:\n{}{}",
            s.id,
            String::from_utf8_lossy(&out.stdout).lines().rev().take(5).collect::<Vec<_>>().join("\n"),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("{:<22} ok", s.title);
    }
}
