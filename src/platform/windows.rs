//! Windows process identity and bounded process-tree inspection.
//!
//! Keep native calls here so the rest of Luvus can use the same platform
//! contract as macOS/Linux without carrying Windows handles through app state.

use std::collections::{HashMap, HashSet};
use std::mem::size_of;

use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

const MAX_PROCESS_ENTRIES: usize = 16_384;
const MAX_DESCENDANTS_PER_ROOT: usize = 64;

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `OwnedHandle` is constructed only from a successful Win32
        // handle-returning call and owns that handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn open_process(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: the access mask is read-only and `pid` is passed by value.
    OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

fn token_user(process: HANDLE) -> Option<Vec<usize>> {
    let mut token = std::ptr::null_mut();
    // SAFETY: `token` points to writable storage and the requested access is
    // read-only. The returned token handle is owned below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle::new(token)?;
    let mut needed = 0_u32;
    // The first call intentionally supplies no buffer to obtain its exact size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return None;
    }
    // TOKEN_USER contains a pointer and must be read from suitably aligned
    // storage. A byte vector is not guaranteed to provide that alignment.
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    // SAFETY: the buffer is exactly the size requested by Windows and remains
    // alive for every later `TOKEN_USER`/SID access.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    Some(buffer)
}

/// Confirm that `pid` belongs to the same Windows account as this process.
/// Used by named-pipe clients before trusting a discovered server endpoint.
pub(super) fn process_belongs_to_current_user(pid: u32) -> bool {
    let Some(process) = open_process(pid) else {
        return false;
    };
    // SAFETY: `GetCurrentProcess` returns a valid pseudo-handle for this process.
    let Some(current) = token_user(unsafe { GetCurrentProcess() }) else {
        return false;
    };
    let Some(peer) = token_user(process.0) else {
        return false;
    };
    // SAFETY: both buffers were populated as TOKEN_USER and remain alive.
    let current = unsafe { &*current.as_ptr().cast::<TOKEN_USER>() };
    let peer = unsafe { &*peer.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: both SID pointers are owned by the live token-information buffers.
    unsafe { EqualSid(current.User.Sid, peer.User.Sid) != 0 }
}

/// PID-reuse-safe process lifetime marker, expressed as the opaque Windows
/// creation timestamp in 100-nanosecond ticks.
pub(super) fn process_start_marker(pid: u32) -> Option<String> {
    let process = open_process(pid)?;
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output pointers name initialized writable FILETIME values and
    // the process handle was opened for query-only access.
    if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return None;
    }
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    Some(format!("windows:{ticks}"))
}

#[derive(Clone, Debug)]
struct ProcessEntry {
    pid: u32,
    parent: u32,
    executable: String,
}

#[derive(Debug)]
struct ProcessSnapshot {
    names: HashMap<u32, String>,
    children: HashMap<u32, Vec<u32>>,
}

impl ProcessSnapshot {
    fn capture() -> Option<Self> {
        // SAFETY: ToolHelp owns the returned snapshot handle; the guard closes it.
        let snapshot =
            OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
        let mut raw = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut entries = Vec::new();
        // SAFETY: `raw` has the required size and remains writable for the loop.
        let mut available = unsafe { Process32FirstW(snapshot.0, &mut raw) } != 0;
        while available && entries.len() < MAX_PROCESS_ENTRIES {
            let end = raw
                .szExeFile
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(raw.szExeFile.len());
            let executable = String::from_utf16_lossy(&raw.szExeFile[..end]);
            if raw.th32ProcessID != 0 && !executable.is_empty() {
                entries.push(ProcessEntry {
                    pid: raw.th32ProcessID,
                    parent: raw.th32ParentProcessID,
                    executable,
                });
            }
            // SAFETY: same initialized ToolHelp snapshot and writable entry.
            available = unsafe { Process32NextW(snapshot.0, &mut raw) } != 0;
        }
        if entries.is_empty() {
            return None;
        }
        Some(Self::from_entries(entries))
    }

    fn from_entries(entries: Vec<ProcessEntry>) -> Self {
        let mut names = HashMap::with_capacity(entries.len());
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for entry in entries {
            names.insert(entry.pid, entry.executable);
            children.entry(entry.parent).or_default().push(entry.pid);
        }
        for child_ids in children.values_mut() {
            child_ids.sort_unstable();
        }
        Self { names, children }
    }

    fn descendants(&self, root: u32) -> Vec<(u32, u16, String)> {
        let mut output = Vec::new();
        let mut pending = vec![(root, 0_u16)];
        let mut visited = HashSet::new();
        while let Some((pid, depth)) = pending.pop() {
            if !visited.insert(pid) || output.len() >= MAX_DESCENDANTS_PER_ROOT {
                continue;
            }
            if let Some(executable) = self.names.get(&pid) {
                output.push((pid, depth, executable.clone()));
            }
            if let Some(children) = self.children.get(&pid) {
                pending.extend(
                    children
                        .iter()
                        .rev()
                        .copied()
                        .map(|child| (child, depth.saturating_add(1))),
                );
            }
        }
        output
    }
}

pub(super) fn descendant_commands(roots: &[u32]) -> Option<HashMap<u32, Vec<String>>> {
    let snapshot = ProcessSnapshot::capture()?;
    Some(
        roots
            .iter()
            .copied()
            .map(|root| {
                let commands = snapshot
                    .descendants(root)
                    .into_iter()
                    .map(|(_, _, command)| command)
                    .collect();
                (root, commands)
            })
            .collect(),
    )
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessBasicInformationBuf {
    reserved1: *mut core::ffi::c_void,
    peb_base_address: *mut core::ffi::c_void,
    reserved2: [*mut core::ffi::c_void; 2],
    unique_process_id: usize,
    reserved3: *mut core::ffi::c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

fn read_process_memory<T: Copy>(process: HANDLE, addr: *const core::ffi::c_void) -> Option<T> {
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    let mut read = 0_usize;
    // SAFETY: `out` is writable for `size_of::<T>()` and `addr` is a pointer
    // in the target process; failure is reported by the BOOL return.
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr,
            out.as_mut_ptr().cast(),
            size_of::<T>(),
            &mut read,
        )
    };
    (ok != 0 && read == size_of::<T>()).then(|| unsafe { out.assume_init() })
}

/// Another process's current directory via its PEB. Used so a workspace can
/// follow a pane whose agent `chdir`'d in a child (Pi on Windows).
#[cfg(target_pointer_width = "64")]
pub(super) fn process_cwd(pid: u32) -> Option<std::path::PathBuf> {
    const PEB_PROCESS_PARAMETERS: usize = 0x20;
    const RTL_CURRENT_DIRECTORY: usize = 0x38;
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
    })?;
    let mut info = ProcessBasicInformationBuf {
        reserved1: std::ptr::null_mut(),
        peb_base_address: std::ptr::null_mut(),
        reserved2: [std::ptr::null_mut(), std::ptr::null_mut()],
        unique_process_id: 0,
        reserved3: std::ptr::null_mut(),
    };
    let mut returned = 0_u32;
    // SAFETY: `info` is the ProcessBasicInformation buffer ntdll expects.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.0,
            ProcessBasicInformation,
            (&raw mut info).cast(),
            size_of::<ProcessBasicInformationBuf>() as u32,
            &mut returned,
        )
    };
    if status != 0 || info.peb_base_address.is_null() {
        return None;
    }
    let params: *mut core::ffi::c_void = read_process_memory(
        handle.0,
        (info.peb_base_address as usize + PEB_PROCESS_PARAMETERS) as *const _,
    )?;
    if params.is_null() {
        return None;
    }
    let dos: UnicodeString =
        read_process_memory(handle.0, (params as usize + RTL_CURRENT_DIRECTORY) as *const _)?;
    if dos.buffer.is_null() || dos.length < 2 {
        return None;
    }
    let wchar_len = (dos.length as usize) / 2;
    if wchar_len == 0 || wchar_len > 4096 {
        return None;
    }
    let mut buf = vec![0_u16; wchar_len];
    let mut read = 0_usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle.0,
            dos.buffer.cast(),
            buf.as_mut_ptr().cast(),
            dos.length as usize,
            &mut read,
        )
    };
    if ok == 0 || read < 2 {
        return None;
    }
    let n = (read / 2).min(wchar_len);
    let path = String::from_utf16_lossy(&buf[..n]);
    let path = path.trim_end_matches(['\\', '\0']);
    (!path.is_empty()).then(|| std::path::PathBuf::from(path))
}

#[cfg(not(target_pointer_width = "64"))]
pub(super) fn process_cwd(_pid: u32) -> Option<std::path::PathBuf> {
    None
}

pub(super) fn process_tree(root: u32) -> Vec<super::ProcInfo> {
    ProcessSnapshot::capture()
        .map(|snapshot| {
            snapshot
                .descendants(root)
                .into_iter()
                .map(|(pid, depth, command)| super::ProcInfo {
                    pid,
                    depth,
                    command,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descendant_walk_is_bounded_and_cycle_safe() {
        let mut entries = vec![ProcessEntry {
            pid: 1,
            parent: 65,
            executable: "root.exe".into(),
        }];
        entries.extend((2..=65).map(|pid| ProcessEntry {
            pid,
            parent: pid - 1,
            executable: format!("child-{pid}.exe"),
        }));
        let descendants = ProcessSnapshot::from_entries(entries).descendants(1);
        assert_eq!(descendants.len(), MAX_DESCENDANTS_PER_ROOT);
        assert_eq!(descendants[0], (1, 0, "root.exe".into()));
    }

    #[test]
    fn current_process_has_a_stable_identity_and_owner() {
        let pid = std::process::id();
        assert!(process_belongs_to_current_user(pid));
        let first = process_start_marker(pid).expect("Windows process creation time");
        assert_eq!(process_start_marker(pid).as_deref(), Some(first.as_str()));
        assert!(first.starts_with("windows:"));
    }

    #[test]
    fn process_snapshot_contains_the_current_process() {
        let pid = std::process::id();
        let snapshot = ProcessSnapshot::capture().expect("Windows ToolHelp snapshot");
        let root = snapshot.descendants(pid);
        assert_eq!(root.first().map(|entry| entry.0), Some(pid));
        assert!(root.first().is_some_and(|entry| !entry.2.is_empty()));
    }

    #[test]
    fn process_cwd_matches_this_process() {
        let pid = std::process::id();
        let cwd = process_cwd(pid).expect("Windows process cwd");
        let expected = std::env::current_dir().expect("current_dir");
        assert!(
            crate::platform::same_path(&cwd, &expected),
            "process_cwd={cwd:?} current_dir={expected:?}"
        );
        let tree = crate::platform::process_tree_cwd(pid).expect("tree cwd");
        assert!(
            crate::platform::same_path(&tree, &expected),
            "process_tree_cwd={tree:?} current_dir={expected:?}"
        );
    }
}
