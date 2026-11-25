//! Private bridge from native user enrollment to the retained host dataplane.
use std::{
    ffi::OsString,
    future::Future,
    io::{self, Write},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Serialize, Serializer};
use tokio::{io::AsyncWriteExt, process::ChildStdin};
use zeroize::Zeroizing;

const MAX_FRAME_BYTES: usize = 512 << 10;

/// The payload is written once to an anonymous pipe. Neither the arguments nor
/// the environment of the compatibility runtime carries identity material.
#[derive(Serialize)]
pub(crate) struct Session<'a> {
    pub metadata: &'a serde_json::Value,
    #[serde(serialize_with = "encode_bytes")]
    pub ca_pem: &'a [u8],
    #[serde(serialize_with = "encode_bytes")]
    pub certificate_pem: &'a [u8],
    #[serde(serialize_with = "encode_bytes")]
    pub private_key_pem: &'a [u8],
    #[serde(serialize_with = "encode_bytes")]
    pub wireguard_private_key: &'a [u8],
    pub network_id: &'a str,
    pub node_id: &'a str,
    pub lease_expires_at: i64,
    pub saved_login: bool,
    pub routes: &'a [String],
    pub exit: &'a str,
    pub failure_mode: &'a str,
    pub dns: &'a [String],
    pub local_lan: &'a [String],
}

fn encode_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let encoded = Zeroizing::new(STANDARD.encode(bytes));
    serializer.serialize_str(&encoded)
}

#[cfg(target_os = "macos")]
pub(crate) fn preflight() -> Result<()> {
    crate::macos::verify_installation()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn preflight() -> Result<()> {
    let mut command = crate::compat::command(&[OsString::from("_connect-preflight")])?;
    #[cfg(target_os = "linux")]
    crate::compat::verify_linux_network_helper_bridge(std::path::Path::new(command.get_program()))?;
    let status = command
        .stdin(Stdio::null())
        .status()
        .context("check the installed connect dataplane")?;
    ensure!(
        status.success(),
        "installed connect dataplane preflight failed"
    );
    Ok(())
}

pub(crate) async fn run(session: &Session<'_>, shutdown: impl Future<Output = ()>) -> Result<()> {
    let mut frame = PrivateFrame(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut frame, session).context("encode private connect session")?;
    let command = crate::compat::command(&[OsString::from("_connect-session")])?;
    drive_session(command, frame, shutdown).await
}

struct PrivateFrame(Zeroizing<Vec<u8>>);

impl Write for PrivateFrame {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > MAX_FRAME_BYTES - self.0.len() {
            return Err(io::Error::other("connect session exceeds the frame limit"));
        }
        self.0.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn send_frame(pipe: &mut ChildStdin, frame: &PrivateFrame) -> io::Result<()> {
    pipe.write_all(&(frame.0.len() as u32).to_be_bytes())
        .await?;
    pipe.write_all(&frame.0).await
}

async fn drive_session(
    mut command: Command,
    frame: PrivateFrame,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    command.stdin(Stdio::piped());
    let mut child = tokio::process::Command::from(command)
        .spawn()
        .context("launch the installed connect dataplane")?;
    let mut pipe = child
        .stdin
        .take()
        .context("open private connect session pipe")?;
    tokio::pin!(shutdown);
    let send = tokio::select! {
        biased;
        _ = &mut shutdown => None,
        result = send_frame(&mut pipe, &frame) => Some(result),
    };
    drop(frame);
    if let Some(result) = send {
        if let Err(err) = result {
            drop(pipe);
            let _ = child.wait().await;
            return Err(err).context("send private connect session");
        }
    } else {
        drop(pipe);
        child
            .wait()
            .await
            .context("wait for cancelled connect setup")?;
        return Ok(());
    }
    let status = tokio::select! {
        biased;
        exit = child.wait() => exit,
        _ = &mut shutdown => {
            // The Go dataplane treats EOF as cancellation, closes the helper
            // and waits for route teardown. Avoid sending SIGKILL or leaving
            // the helper running while the frontend rotates credentials.
            drop(pipe);
            child.wait().await
        }
    }
    .context("wait for connect dataplane cleanup")?;
    ensure!(status.success(), "connect dataplane exited with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_bounded_before_allocation_or_launch() {
        let mut frame = PrivateFrame(Zeroizing::new(Vec::new()));
        frame.write_all(&vec![0; MAX_FRAME_BYTES]).unwrap();
        assert!(frame.write_all(&[1]).is_err());
        assert_eq!(frame.0.len(), MAX_FRAME_BYTES);
    }

    #[tokio::test]
    async fn only_the_framed_pipe_contains_session_data_and_eof_reaps_runtime() {
        let work = tempfile::tempdir().unwrap();
        let received = work.path().join("pipe");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "dd bs=1 count=27 > \"$1\" 2>/dev/null && cat > /dev/null",
                "connect-child",
            ])
            .arg(&received);
        let sent = async {
            while !std::fs::metadata(&received).is_ok_and(|info| info.len() == 27) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            drive_session(
                command,
                PrivateFrame(Zeroizing::new(b"test credential fixture".to_vec())),
                sent,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let packet = std::fs::read(received).unwrap();
        assert_eq!(&packet[..4], &23u32.to_be_bytes());
        assert_eq!(&packet[4..], b"test credential fixture");
    }
}
