//! Single-instance guard via a named mutex, so only one capture agent runs per machine
//! even if the logon task fires twice or a manual run overlaps a task run. Holding the
//! returned guard keeps the lock; dropping it (process exit) releases it.

#[cfg(windows)]
pub use win::{acquire, SingletonGuard};

#[cfg(not(windows))]
pub use portable::{acquire, SingletonGuard};

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    pub struct SingletonGuard(HANDLE);

    impl Drop for SingletonGuard {
        fn drop(&mut self) {
            // Safe on a null handle (CloseHandle just fails and is ignored).
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Returns `Some(guard)` if this process now owns the named lock, or `None` if another
    /// process already holds it. A creation failure is treated as "proceed" (never blocks
    /// collection over a lock-service hiccup).
    pub fn acquire(name: &str) -> Option<SingletonGuard> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 0, wide.as_ptr());
            let already = GetLastError() == ERROR_ALREADY_EXISTS;
            if !handle.is_null() && already {
                CloseHandle(handle);
                return None; // another instance owns it
            }
            Some(SingletonGuard(handle))
        }
    }
}

#[cfg(not(windows))]
mod portable {
    pub struct SingletonGuard;
    /// No-op on non-Windows dev builds; always allows running.
    pub fn acquire(_name: &str) -> Option<SingletonGuard> {
        Some(SingletonGuard)
    }
}
