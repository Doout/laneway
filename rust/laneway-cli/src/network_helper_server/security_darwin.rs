use std::{
    io, mem,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, ensure};
use nix::libc;

static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOPPING.store(true, Ordering::Relaxed);
}

pub(super) fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

pub(super) fn syscall(status: libc::c_int) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn require_single_thread() -> Result<()> {
    let mut task = mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: PROC_PIDTASKINFO writes exactly one proc_taskinfo on success.
    // We query this process and check the returned length before reading it.
    let copied = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            task.as_mut_ptr().cast(),
            size,
        )
    };
    ensure!(copied == size, "inspect Darwin helper thread count");
    let task = unsafe { task.assume_init() };
    ensure!(
        task.pti_threadnum == 1,
        "network helper requires one thread"
    );
    Ok(())
}

pub(super) fn isolate_process_group() -> Result<()> {
    // SAFETY: all process IDs are documented constants referring to our own
    // process. No pointers or shared process state cross these calls.
    if let Err(error) = syscall(unsafe { libc::setpgid(0, 0) }) {
        ensure!(
            unsafe { libc::getpgrp() == libc::getpid() },
            "isolate helper process group: {error}"
        );
    }
    // SAFETY: sigaction's mask is initialized by sigemptyset. The handler
    // only stores to a lock-free atomic; no libc calls occur in the handler.
    unsafe {
        let mut action: libc::sigaction = mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        syscall(libc::sigemptyset(&mut action.sa_mask))?;
        for signal in [libc::SIGTERM, libc::SIGINT] {
            syscall(libc::sigaction(signal, &action, std::ptr::null_mut()))
                .context("install helper cleanup signal handler")?;
        }
    }
    Ok(())
}

pub(super) fn harden_process() -> Result<()> {
    // macOS retains root for the scoped ifconfig and route operations.
    // The authenticated inherited socket is the only command channel.
    Ok(())
}
