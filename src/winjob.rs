//! sing-box умирает вместе с Foxray, даже если Foxray упал или его убили:
//! процесс кладём в «задание» Windows с флагом «убить всё при закрытии».

use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

static JOB: OnceLock<usize> = OnceLock::new();

fn job() -> HANDLE {
    *JOB.get_or_init(|| unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if !job.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
        }
        // Дескриптор не закрываем: он закроется при выходе Foxray — и заберёт sing-box с собой.
        job as usize
    }) as HANDLE
}

/// Привязать процесс к Foxray. false — не получилось (не критично).
pub fn bind(process: HANDLE) -> bool {
    let j = job();
    !j.is_null() && unsafe { AssignProcessToJobObject(j, process) } != 0
}
