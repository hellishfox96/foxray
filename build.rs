fn main() {
    // Интерфейс, тёмная тема в стиле Windows 11.
    let cfg = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", cfg).expect("ошибка в ui/app.slint");

    // На Windows: просить права администратора при запуске (нужны для TUN).
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        use embed_manifest::manifest::ExecutionLevel;
        use embed_manifest::{embed_manifest, new_manifest};
        embed_manifest(new_manifest("Foxray").requested_execution_level(ExecutionLevel::RequireAdministrator))
            .expect("не удалось встроить манифест");
            let mut res = winresource::WindowsResource::new();
            res.set_icon("ui/app.ico");
            // Название в меню панели задач, «Открыть с помощью» и т. п.
            res.set("FileDescription", "Foxray");
            res.set("ProductName", "Foxray");
            res.compile().expect("не удалось встроить иконку");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ui/app.ico");
}
