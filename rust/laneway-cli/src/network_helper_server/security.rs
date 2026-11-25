use std::{fs, io};

use anyhow::{Context, Result, ensure};
use nix::libc;

use super::socket::syscall;

pub(super) fn isolate_process_group() -> Result<()> {
    let result = unsafe { libc::setpgid(0, 0) };
    if let Err(error) = syscall(result) {
        ensure!(
            unsafe { libc::getpgrp() == libc::getpid() },
            "isolate helper process group: {error}"
        );
    }
    Ok(())
}

fn prctl(option: libc::c_int, first: libc::c_ulong, second: libc::c_ulong) -> io::Result<()> {
    syscall(unsafe {
        libc::prctl(
            option,
            first,
            second,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    })
    .map(|_| ())
}

pub(super) fn require_single_thread() -> Result<()> {
    ensure!(
        fs::read_dir("/proc/self/task")?.count() == 1,
        "Linux helper capability reduction requires a dedicated single-threaded process"
    );
    Ok(())
}

pub(super) fn harden_process() -> Result<()> {
    require_single_thread()?;
    const NET_ADMIN: libc::c_ulong = 12;
    const VERSION_3: u32 = 0x2008_0522;
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as _, 0)
        .context("clear ambient helper capabilities")?;
    for capability in 0..=63 {
        if capability == NET_ADMIN {
            continue;
        }
        match prctl(libc::PR_CAPBSET_DROP, capability, 0) {
            Ok(()) => (),
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => (),
            Err(error) => return Err(error).context("reduce helper capability bounding set"),
        }
    }
    let header = CapabilityHeader {
        version: VERSION_3,
        pid: 0,
    };
    let mask = 1 << NET_ADMIN;
    let data = [
        CapabilityData {
            effective: mask,
            permitted: mask,
            inheritable: mask,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let outcome = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if outcome < 0 {
        return Err(io::Error::last_os_error()).context("restrict helper to CAP_NET_ADMIN");
    }
    prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_RAISE as _,
        NET_ADMIN,
    )
    .context("retain CAP_NET_ADMIN for helper subprocesses")?;
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0).context("prevent helper privilege gains")
}
