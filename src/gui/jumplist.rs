//! Меню на кнопке в панели задач (правый клик) — «список переходов» Windows.
//! Пункт запускает foxray-gui.exe с аргументом; запущенная копия получает команду
//! через single.rs (повторный запуск передаёт команду и сразу выходит).

use windows::core::{Interface, HSTRING, PROPVARIANT};
use windows::Win32::Storage::EnhancedStorage::PKEY_Title;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED};
use windows::Win32::UI::Shell::Common::{IObjectArray, IObjectCollection};
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{DestinationList, EnumerableObjectCollection, ICustomDestinationList, IShellLinkW, ShellLink};

/// Векторные значки пунктов (нарисованы из SVG в ui/jump, в .ico 16–48 px).
const ICONS: [(&str, &[u8]); 2] = [
    ("power.ico", include_bytes!("../../ui/jump/power.ico")),
    ("quit.ico", include_bytes!("../../ui/jump/quit.ico")),
];

/// Положить значки в папку программы (Windows берёт значок пункта из файла).
pub fn icon_dir(app_dir: &std::path::Path) -> std::path::PathBuf {
    let dir = app_dir.join("icons");
    let _ = std::fs::create_dir_all(&dir);
    for (name, bytes) in ICONS {
        let path = dir.join(name);
        if std::fs::read(&path).map_or(true, |old| old != bytes) {
            let _ = std::fs::write(&path, bytes);
        }
    }
    dir
}

/// tasks: (подпись, аргументы командной строки, путь к .ico)
pub fn set_tasks(exe: &str, tasks: &[(&str, &str, String)]) -> windows::core::Result<()> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let list: ICustomDestinationList = CoCreateInstance(&DestinationList, None, CLSCTX_INPROC_SERVER)?;
        let mut slots = 0u32;
        let _removed: IObjectArray = list.BeginList(&mut slots)?;
        let coll: IObjectCollection = CoCreateInstance(&EnumerableObjectCollection, None, CLSCTX_INPROC_SERVER)?;
        for (title, args, icon) in tasks {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&HSTRING::from(exe))?;
            link.SetArguments(&HSTRING::from(*args))?;
            link.SetIconLocation(&HSTRING::from(icon.as_str()), 0)?;
            let store: IPropertyStore = link.cast()?;
            store.SetValue(&PKEY_Title, &PROPVARIANT::from(*title))?;
            store.Commit()?;
            coll.AddObject(&link)?;
        }
        let arr: IObjectArray = coll.cast()?;
        list.AddUserTasks(&arr)?;
        list.CommitList()
    }
}
