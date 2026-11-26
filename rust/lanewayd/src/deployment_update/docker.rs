use std::{
    fmt, fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::Value;

use crate::fleet_update::connector::{is_standard_running, valid_name};

pub(super) const CONNECTOR_PREFIX: &str = "laneway-connector-";
const DOCKER_SOCKET: &str = "/run/docker.sock";
const LIST: &str =
    "/containers/json?filters=%7B%22name%22%3A%5B%22%5E%2Flaneway-connector-%22%5D%7D";
const MAX_RESPONSE: usize = 4 << 20;

#[derive(Debug)]
pub(super) struct Unavailable(pub(super) String);

impl fmt::Display for Unavailable {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "the local Docker Engine is unavailable: {}", self.0)
    }
}

impl std::error::Error for Unavailable {}

pub(super) async fn local_managed_connectors(name: Option<&str>) -> Result<Vec<String>> {
    let socket = match fs::symlink_metadata(DOCKER_SOCKET) {
        Ok(socket) => socket,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(Unavailable(err.to_string()).into()),
    };
    ensure!(
        socket.file_type().is_socket() && socket.uid() == 0,
        "unsafe local Docker socket {DOCKER_SOCKET}"
    );
    let client = Client::builder()
        .unix_socket(DOCKER_SOCKET)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()
        .context("initialize local Docker client")?;
    let names = if let Some(name) = name {
        ensure!(valid_name(name), "invalid standard Connector name");
        vec![name.to_owned()]
    } else {
        let listed = get_json(&client, LIST)
            .await?
            .context("local Docker Engine does not expose the container list")?;
        listed_names(&listed)?
    };
    let mut managed = Vec::new();
    for name in names {
        let path = format!("/containers/{name}/json");
        if let Some(row) = get_json(&client, &path).await?
            && is_standard_running(&row, &name)
        {
            managed.push(name);
        }
        if managed.len() == 2 {
            break;
        }
    }
    Ok(managed)
}

fn listed_names(listed: &Value) -> Result<Vec<String>> {
    let mut names = listed
        .as_array()
        .context("invalid local Docker container list")?
        .iter()
        .flat_map(|container| container["Names"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(|name| name.strip_prefix('/').unwrap_or(name))
        .filter(|name| valid_name(name))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

async fn get_json(client: &Client, path: &str) -> Result<Option<Value>> {
    let mut response = client
        .get(format!("http://docker{path}"))
        .send()
        .await
        .map_err(|err| Unavailable(err.to_string()))?;
    match response.status() {
        StatusCode::NOT_FOUND => Ok(None),
        StatusCode::OK => {
            let mut payload = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .context("read local Docker response")?
            {
                ensure!(
                    payload.len() + chunk.len() <= MAX_RESPONSE,
                    "local Docker response exceeds the size limit"
                );
                payload.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&payload)
                .map(Some)
                .context("decode local Docker response")
        }
        status => bail!("local Docker Engine returned HTTP {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_for_inspection_are_sorted_unique_and_safe() {
        let listed = json!([
            {"Names": ["/laneway-connector-two", "/laneway-connector-one"]},
            {"Names": ["/laneway-connector-one", "/ignored", "/laneway-connector-../escape"]},
        ]);
        assert_eq!(
            listed_names(&listed).unwrap(),
            ["laneway-connector-one", "laneway-connector-two"]
        );
        assert!(listed_names(&json!({})).is_err());
    }
}
