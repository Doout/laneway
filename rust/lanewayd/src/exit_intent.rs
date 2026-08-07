use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};

use crate::config::{Config, ExitFailureMode};

const VERSION: u32 = 1;
const MAX_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_mode: Option<ExitFailureModeWire>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExitFailureModeWire {
    Open,
    Closed,
}

impl From<ExitFailureMode> for Option<ExitFailureModeWire> {
    fn from(value: ExitFailureMode) -> Self {
        match value {
            ExitFailureMode::Open => Some(ExitFailureModeWire::Open),
            ExitFailureMode::Closed => Some(ExitFailureModeWire::Closed),
            ExitFailureMode::Unspecified => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Store {
    path: PathBuf,
}

impl Store {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn load(&self, config: &mut Config) -> Result<bool> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("inspect exit intent"),
        };
        ensure!(metadata.is_file(), "exit intent is not a regular file");
        ensure!(
            metadata.len() <= MAX_BYTES,
            "exit intent exceeds size limit"
        );
        let file = File::open(&self.path).context("open exit intent")?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "exit intent exceeds size limit"
        );
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        let intent = Intent::deserialize(&mut decoder).context("decode exit intent")?;
        decoder.end().context("exit intent has trailing data")?;
        validate(&intent)?;
        apply(config, &intent)?;
        Ok(true)
    }

    pub(crate) fn save(&self, config: &Config) -> Result<()> {
        let exit = &config.forwarding.exit_client;
        let intent = Intent {
            version: VERSION,
            enabled: exit.enabled,
            selected_node_id: exit.enabled.then(|| exit.selected_node.clone()).flatten(),
            failure_mode: if exit.enabled {
                exit.failure_mode.into()
            } else {
                None
            },
        };
        validate(&intent)?;
        let bytes = serde_json::to_vec(&intent).context("encode exit intent")?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "exit intent exceeds size limit"
        );
        let parent = self
            .path
            .parent()
            .context("exit intent has no parent directory")?;
        ensure!(
            parent.is_dir(),
            "exit intent parent directory does not exist"
        );
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            ensure!(
                metadata.is_file(),
                "refusing to replace non-regular exit intent"
            );
        }
        let (temporary_path, mut temporary) = create_temporary(parent)?;
        let result = (|| -> Result<()> {
            temporary.write_all(&bytes).context("write exit intent")?;
            temporary
                .write_all(b"\n")
                .context("write exit intent newline")?;
            temporary.sync_all().context("sync exit intent")?;
            drop(temporary);
            fs::rename(&temporary_path, &self.path).context("replace exit intent")?;
            sync_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    pub(crate) fn remove(&self) -> Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => ensure!(
                metadata.is_file(),
                "refusing to remove non-regular exit intent"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("inspect exit intent"),
        }
        fs::remove_file(&self.path).context("remove exit intent")?;
        sync_directory(self.path.parent().context("exit intent has no parent")?)
    }
}

fn validate(intent: &Intent) -> Result<()> {
    ensure!(intent.version == VERSION, "unsupported exit intent version");
    if intent.enabled {
        let selected = intent
            .selected_node_id
            .as_deref()
            .context("enabled exit intent omitted selected_node_id")?;
        selected
            .parse::<Id>()
            .context("exit intent selected_node_id")?;
        ensure!(
            intent.failure_mode.is_some(),
            "enabled exit intent omitted failure_mode"
        );
    } else {
        ensure!(
            intent.selected_node_id.is_none() && intent.failure_mode.is_none(),
            "disabled exit intent must be neutral"
        );
    }
    Ok(())
}

fn apply(config: &mut Config, intent: &Intent) -> Result<()> {
    let exit = &mut config.forwarding.exit_client;
    exit.enabled = intent.enabled;
    exit.selected_node = intent.selected_node_id.clone();
    if let Some(mode) = intent.failure_mode {
        let configured = match mode {
            ExitFailureModeWire::Open => ExitFailureMode::Open,
            ExitFailureModeWire::Closed => ExitFailureMode::Closed,
        };
        ensure!(
            exit.failure_mode == configured,
            "persisted exit failure_mode differs from configuration"
        );
    }
    Ok(())
}

fn create_temporary(parent: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..32 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).context("generate exit intent temporary name")?;
        let path = parent.join(format!(
            ".exit-intent-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create exit intent temporary file"),
        }
    }
    bail!("could not allocate exit intent temporary file")
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .context("sync exit intent directory")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn config() -> Config {
        toml::from_str(include_str!(
            "../../../deploy/examples/node-rust-controller.toml"
        ))
        .unwrap()
    }

    #[test]
    fn round_trips_enabled_and_disabled_intent_securely() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("intent.json");
        let store = Store::new(path.clone());
        let mut value = config();
        value.forwarding.exit_client.authorized = true;
        value.forwarding.exit_client.failure_mode = ExitFailureMode::Closed;
        value.forwarding.exit_client.enabled = true;
        value.forwarding.exit_client.selected_node =
            Some("202122232425262728292a2b2c2d2e2f".into());
        store.save(&value).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut loaded = config();
        loaded.forwarding.exit_client.authorized = true;
        loaded.forwarding.exit_client.failure_mode = ExitFailureMode::Closed;
        assert!(store.load(&mut loaded).unwrap());
        assert!(loaded.forwarding.exit_client.enabled);
        assert_eq!(
            loaded.forwarding.exit_client.selected_node,
            value.forwarding.exit_client.selected_node
        );
        loaded.forwarding.exit_client.enabled = false;
        loaded.forwarding.exit_client.selected_node = None;
        store.save(&loaded).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert_eq!(body, "{\"version\":1,\"enabled\":false}\n");
        store.remove().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn rejects_symlink_and_mismatched_failure_mode() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"{}\n").unwrap();
        let link = directory.path().join("intent");
        symlink(&target, &link).unwrap();
        assert!(Store::new(link).load(&mut config()).is_err());

        let path = directory.path().join("mode.json");
        fs::write(&path, b"{\"version\":1,\"enabled\":true,\"selected_node_id\":\"202122232425262728292a2b2c2d2e2f\",\"failure_mode\":\"open\"}\n").unwrap();
        let mut value = config();
        value.forwarding.exit_client.failure_mode = ExitFailureMode::Closed;
        assert!(Store::new(path).load(&mut value).is_err());
    }
}
