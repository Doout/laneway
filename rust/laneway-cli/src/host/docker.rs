use std::{
    fmt, fs,
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use serde_json::Value;

pub(super) const CONNECTOR_PREFIX: &str = "laneway-connector-";
const DOCKER_SOCKET: &str = "/run/docker.sock";
const LIST: &str =
    "/containers/json?filters=%7B%22name%22%3A%5B%22%5E%2Flaneway-connector-%22%5D%7D";
const MAX_RESPONSE: u64 = 4 << 20;

#[derive(Debug)]
pub(super) struct Unavailable(pub(super) String);

impl fmt::Display for Unavailable {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "the local Docker Engine is unavailable: {}", self.0)
    }
}

impl std::error::Error for Unavailable {}

pub(super) fn standard_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(CONNECTOR_PREFIX) else {
        return false;
    };
    suffix.len() <= 128
        && suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn managed_image(reference: &str) -> bool {
    let Some((tagged, digest)) = reference.split_once("@sha256:") else {
        return false;
    };
    let Some((image, version)) = tagged.split_once(':') else {
        return false;
    };
    matches!(
        image,
        "ghcr.io/doout/lane-edge"
            | "ghcr.io/doout/laneway-connector"
            | "ghcr.io/doout/laneway-exit-node"
    ) && version.split('.').count() == 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn local_managed_connectors(name: Option<&str>) -> Result<Vec<String>> {
    let socket = match fs::symlink_metadata(DOCKER_SOCKET) {
        Ok(socket) => socket,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(Unavailable(err.to_string()).into()),
    };
    ensure!(
        socket.file_type().is_socket() && socket.uid() == 0,
        "unsafe local Docker socket {DOCKER_SOCKET}"
    );
    // The host's Unix socket is the only Docker endpoint. Environment-based
    // contexts, proxies and remote Docker targets are never used.
    let client = Client::builder()
        .unix_socket(DOCKER_SOCKET)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()
        .context("initialize local Docker client")?;
    find_managed_connectors(name, |path| get_json(&client, path))
}

fn find_managed_connectors(
    name: Option<&str>,
    request: impl Fn(&str) -> Result<Option<Value>>,
) -> Result<Vec<String>> {
    let mut names = if let Some(name) = name {
        vec![name.to_owned()]
    } else {
        let listed =
            request(LIST)?.context("local Docker Engine does not expose the container list")?;
        listed
            .as_array()
            .context("invalid local Docker container list")?
            .iter()
            .flat_map(|container| container["Names"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .map(|name| name.strip_prefix('/').unwrap_or(name))
            .filter(|name| standard_name(name))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    names.sort_unstable();
    names.dedup();
    let mut managed = Vec::new();
    for name in names {
        ensure!(
            standard_name(&name),
            "invalid standard Connector name {name:?}"
        );
        let path = format!("/containers/{name}/json");
        if let Some(connector) = request(&path)?
            && is_managed(&connector, &name)
        {
            managed.push(name);
        }
    }
    Ok(managed)
}

fn get_json(client: &Client, path: &str) -> Result<Option<Value>> {
    let response = client
        .get(format!("http://docker{path}"))
        .send()
        .map_err(|err| Unavailable(err.to_string()))?;
    match response.status() {
        StatusCode::NOT_FOUND => Ok(None),
        StatusCode::OK => {
            let mut payload = Vec::new();
            response
                .take(MAX_RESPONSE + 1)
                .read_to_end(&mut payload)
                .context("read local Docker response")?;
            ensure!(
                payload.len() as u64 <= MAX_RESPONSE,
                "local Docker response exceeds the size limit"
            );
            serde_json::from_slice(&payload)
                .map(Some)
                .context("decode local Docker response")
        }
        status => bail!("local Docker Engine returned HTTP {status}"),
    }
}

fn is_managed(container: &Value, name: &str) -> bool {
    let config = &container["Config"];
    let host = &container["HostConfig"];
    let networks = &container["NetworkSettings"]["Networks"];
    if container["Name"] != format!("/{name}")
        || container["State"]["Running"] != true
        || !config["Image"].as_str().is_some_and(managed_image)
        || config["Hostname"] != name
        || config["User"] != "65532:65532"
        || !words(&config["Entrypoint"], &["/usr/local/bin/laneway"])
        || !words(&config["Cmd"], &["connector", "run"])
    {
        return false;
    }
    let standard_security = words(&host["SecurityOpt"], &["no-new-privileges:true"])
        || words(&host["SecurityOpt"], &["no-new-privileges"]);
    if !false_or_missing(&host["Privileged"])
        || host["ReadonlyRootfs"] != true
        || !false_or_missing(&host["PublishAllPorts"])
        || !words(&host["CapDrop"], &["ALL"])
        || !standard_security
        || host["RestartPolicy"]["Name"] != "unless-stopped"
        || ![
            "CapAdd",
            "PortBindings",
            "Devices",
            "DeviceRequests",
            "ExtraHosts",
        ]
        .iter()
        .all(|key| empty_options(&host[*key]))
        || !matches!(host["NetworkMode"].as_str(), Some("bridge" | "default"))
        || !networks
            .as_object()
            .is_some_and(|networks| networks.len() == 1 && networks.contains_key("bridge"))
    {
        return false;
    }
    if !valid_optional_keys(&config["Labels"], |label| {
        label == "io.laneway.update-transaction" || label.starts_with("org.opencontainers.image.")
    }) || !valid_optional_keys(&host["Tmpfs"], |path| {
        matches!(path, "/tmp" | "/run/laneway")
    }) || !valid_connector_environment(&config["Env"])
    {
        return false;
    }
    let Some(mounts) = container["Mounts"].as_array() else {
        return false;
    };
    let state_name = format!("{name}-state");
    let mut volumes = 0;
    for mount in mounts {
        match (mount["Type"].as_str(), mount["Destination"].as_str()) {
            (Some("volume"), Some("/var/lib/laneway"))
                if mount["Name"] == state_name
                    && mount["Driver"] == "local"
                    && mount["RW"] == true =>
            {
                volumes += 1
            }
            (Some("tmpfs"), Some("/tmp" | "/run/laneway")) => {}
            _ => return false,
        }
    }
    volumes == 1
}

fn valid_connector_environment(field: &Value) -> bool {
    field.is_null()
        || field.as_array().is_some_and(|values| {
            values.iter().all(|value| {
                value
                    .as_str()
                    .and_then(|variable| variable.split_once('='))
                    .is_some_and(|(key, _)| matches!(key, "PATH" | "SETUP_TOKEN"))
            })
        })
}

fn words(field: &Value, expected: &[&str]) -> bool {
    field.as_array().is_some_and(|words| {
        words.len() == expected.len()
            && words
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual == *expected)
    })
}

fn valid_optional_keys(field: &Value, validate: impl Fn(&str) -> bool) -> bool {
    field.is_null()
        || field
            .as_object()
            .is_some_and(|map| map.keys().all(|key| validate(key)))
}

fn false_or_missing(field: &Value) -> bool {
    field.is_null() || field == false
}

fn empty_options(field: &Value) -> bool {
    field.is_null()
        || field.as_array().is_some_and(Vec::is_empty)
        || field.as_object().is_some_and(|map| map.is_empty())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde_json::json;

    use super::*;

    const OFFICE: &str = "laneway-connector-office";

    fn connector(name: &str) -> Value {
        json!({
            "Name": format!("/{name}"),
            "Config": {
                "Image": format!("ghcr.io/doout/lane-edge:0.3.10@sha256:{}", "a".repeat(64)),
                "Entrypoint": ["/usr/local/bin/laneway"],
                "Cmd": ["connector", "run"],
                "User": "65532:65532",
                "Hostname": name,
                "Env": ["PATH=/usr/local/bin", "SETUP_TOKEN=fixture"],
            },
            "State": {"Running": true},
            "HostConfig": {
                "NetworkMode": "bridge",
                "ReadonlyRootfs": true,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "RestartPolicy": {"Name": "unless-stopped"},
                "Tmpfs": {"/tmp": "rw,noexec", "/run/laneway": "rw,noexec"},
            },
            "Mounts": [{"Type": "volume", "Driver": "local", "Name": format!("{name}-state"), "Destination": "/var/lib/laneway", "RW": true}],
            "NetworkSettings": {"Networks": {"bridge": {}}},
        })
    }

    #[test]
    fn recognizes_standard_production_metadata() {
        assert!(is_managed(&connector(OFFICE), OFFICE));
        for (path, substitute) in [
            (
                "/Config/Labels",
                json!({"com.docker.compose.project": "another-deployment"}),
            ),
            ("/Config/Env", json!(["OPERATOR_SETTING=value"])),
            (
                "/Config/Image",
                json!("registry.example.invalid/custom:1.0.0"),
            ),
            (
                "/HostConfig/SecurityOpt",
                json!(["no-new-privileges:true", "apparmor=unconfined"]),
            ),
            ("/HostConfig/PortBindings", json!({"443/tcp": [{}]})),
            ("/HostConfig/NetworkMode", json!("custom")),
            ("/Mounts/0/Driver", json!("third-party")),
            ("/Mounts/0/Name", json!("foreign-state")),
            ("/State/Running", json!(false)),
        ] {
            let mut object = connector(OFFICE);
            let (parent, leaf) = path.rsplit_once('/').unwrap();
            object.pointer_mut(parent).unwrap()[leaf] = substitute;
            assert!(!is_managed(&object, OFFICE), "{path}");
        }
    }

    #[test]
    fn discovery_selects_only_the_verified_container() {
        let paths = RefCell::new(Vec::new());
        let request = |path: &str| {
            paths.borrow_mut().push(path.to_owned());
            match path {
                LIST => Ok(Some(
                    json!([{"Names": ["/laneway-connector-other"]}, {"Names": ["/laneway-connector-office"]}, {"Names": ["/irrelevant"]}]),
                )),
                "/containers/laneway-connector-office/json" => Ok(Some(connector(OFFICE))),
                "/containers/laneway-connector-other/json" => Ok(Some(json!({}))),
                _ => bail!("unexpected request {path}"),
            }
        };
        assert_eq!(find_managed_connectors(None, request).unwrap(), [OFFICE]);
        assert_eq!(
            &*paths.borrow(),
            &[
                LIST,
                "/containers/laneway-connector-office/json",
                "/containers/laneway-connector-other/json"
            ]
        );
        paths.borrow_mut().clear();
        assert_eq!(
            find_managed_connectors(Some(OFFICE), request).unwrap(),
            [OFFICE]
        );
        assert_eq!(
            &*paths.borrow(),
            &["/containers/laneway-connector-office/json"]
        );
    }
}
