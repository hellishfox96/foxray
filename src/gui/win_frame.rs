//! Рамка как в Telegram Desktop (Windows).
//!
//! Окно остаётся обычным окном Windows (тень, скругление углов, Alt+Пробел, Aero Snap),
//! но стандартный заголовок убирается: WM_NCCALCSIZE отдаёт всю площадь окна под наше
//! содержимое, а WM_NCHITTEST говорит Windows, что верхняя полоса — заголовок
//! (за неё можно таскать), кроме области наших кнопок справа.

use std::sync::atomic::{AtomicI32, AtomicIsize, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::DwmExtendFrameIntoClientArea;
use windows_sys::Win32::Graphics::Gdi::ScreenToClient;
use windows_sys::Win32::UI::Controls::MARGINS;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetClientRect, GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_STYLE, HTCAPTION, HTCLIENT, MINMAXINFO,
    SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, WM_GETMINMAXINFO, WM_NCACTIVATE, WM_NCCALCSIZE,
    WM_NCHITTEST, WS_CAPTION, WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_SYSMENU, WS_THICKFRAME,
};

// Размеры в логических пикселях (как в .slint).
static WIDTH: AtomicI32 = AtomicI32::new(380);
static HEIGHT: AtomicI32 = AtomicI32::new(720);
static CAPTION: AtomicI32 = AtomicI32::new(32);
static BUTTONS: AtomicI32 = AtomicI32::new(92);
static INSTALLED: AtomicIsize = AtomicIsize::new(0);

fn scale(hwnd: HWND, v: i32) -> i32 {
    let dpi = unsafe { GetDpiForWindow(hwnd) } as i32;
    let dpi = if dpi <= 0 { 96 } else { dpi };
    (v * dpi + 48) / 96
}

/// Подключить рамку. width/height — размер окна, caption — высота полосы,
/// buttons — ширина области кнопок справа (всё в логических пикселях).
///
/// # Safety
/// hwnd — живое окно этого процесса, вызывать из потока окна.
pub unsafe fn install(hwnd: HWND, width: i32, height: i32, caption: i32, buttons: i32) {
    WIDTH.store(width, Ordering::Relaxed);
    HEIGHT.store(height, Ordering::Relaxed);
    CAPTION.store(caption, Ordering::Relaxed);
    BUTTONS.store(buttons, Ordering::Relaxed);
    if INSTALLED.swap(hwnd as isize, Ordering::SeqCst) == hwnd as isize {
        return; // уже стоит на этом окне
    }

    // Обычное окно с заголовком (для тени и скругления), но без «развернуть» и растягивания.
    let style = GetWindowLongPtrW(hwnd, GWL_STYLE) as u32;
    let style = (style | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX) & !WS_MAXIMIZEBOX & !WS_THICKFRAME;
    SetWindowLongPtrW(hwnd, GWL_STYLE, style as isize);

    SetWindowSubclass(hwnd, Some(subclass_proc), 1, 0);

    // 1px «стекла» сверху — чтобы DWM продолжал рисовать тень.
    let m = MARGINS { cxLeftWidth: 0, cxRightWidth: 0, cyTopHeight: 1, cyBottomHeight: 0 };
    DwmExtendFrameIntoClientArea(hwnd, &m);

    // Пересчитать рамку и выставить точный размер (клиентская область = всё окно).
    SetWindowPos(
        hwnd,
        std::ptr::null_mut(),
        0,
        0,
        scale(hwnd, width),
        scale(hwnd, height),
        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
    );
}

unsafe extern "system" fn subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    match msg {
        // Вся площадь окна — наша (стандартного заголовка нет).
        WM_NCCALCSIZE if wparam != 0 => 0,

        // Не даём Windows мигнуть стандартным заголовком при активации.
        WM_NCACTIVATE => DefSubclassProc(hwnd, msg, wparam, -1),

        // Верхняя полоса — «заголовок» (таскать окно, Aero Snap), кроме наших кнопок.
        WM_NCHITTEST => {
            let r = DefSubclassProc(hwnd, msg, wparam, lparam);
            if r != HTCLIENT as LRESULT {
                return r;
            }
            let mut pt = POINT { x: (lparam & 0xFFFF) as i16 as i32, y: ((lparam >> 16) & 0xFFFF) as i16 as i32 };
            ScreenToClient(hwnd, &mut pt);
            let mut rc = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let rc: windows_sys::Win32::Foundation::RECT = rc;
            let cap = scale(hwnd, CAPTION.load(Ordering::Relaxed));
            let btn = scale(hwnd, BUTTONS.load(Ordering::Relaxed));
            if pt.y >= 0 && pt.y < cap && pt.x < rc.right - btn {
                HTCAPTION as LRESULT
            } else {
                r
            }
        }

        // Фиксированный размер окна.
        WM_GETMINMAXINFO => {
            let r = DefSubclassProc(hwnd, msg, wparam, lparam);
            let info = lparam as *mut MINMAXINFO;
            if !info.is_null() {
                let w = scale(hwnd, WIDTH.load(Ordering::Relaxed));
                let h = scale(hwnd, HEIGHT.load(Ordering::Relaxed));
                (*info).ptMinTrackSize = POINT { x: w, y: h };
                (*info).ptMaxTrackSize = POINT { x: w, y: h };
            }
            r
        }

        _ => DefSubclassProc(hwnd, msg, wparam, lparam),
    }
}
