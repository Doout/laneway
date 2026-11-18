#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::TunDevice;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub(crate) use darwin::TunDevice;
