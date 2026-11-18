use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{
    Backend, Driver, Egress, Endpoint, Error, Network, Phase, Policy, Reply, Result, Store,
};

const GO_STATE: &[u8] = include_bytes!("../../../testvectors/docker-plugin/state-v1.json");
const GO_GRANT: &[u8] = include_bytes!("../../../testvectors/docker-plugin/authorization-v1.json");

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);

#[derive(Default)]
struct FakeState {
    operations: Vec<String>,
    fail_apply: bool,
    fail_remove: bool,
    fail_join: bool,
}

impl Fake {
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().operations.clone()
    }

    fn capture(&self, action: String, fails: impl FnOnce(&FakeState) -> bool) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.operations.push(action);
        if fails(&state) {
            return Err(Error::Backend("fixture operation failed".into()));
        }
        Ok(())
    }
}

impl Backend for Fake {
    fn apply(&self, network: &Network) -> Result<()> {
        self.capture(format!("apply:{}", network.id), |state| state.fail_apply)
    }
    fn remove(&self, network: &Network) -> Result<()> {
        self.capture(format!("remove:{}", network.id), |state| state.fail_remove)
    }
    fn join(&self, _: &Network, endpoint: &Endpoint) -> Result<()> {
        self.capture(format!("join:{}", endpoint.host_veth), |state| {
            state.fail_join
        })
    }
    fn leave(&self, _: &Network, endpoint: &Endpoint) -> Result<()> {
        self.capture(format!("leave:{}", endpoint.host_veth), |_| false)
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn clock() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn paths(directory: &Path) -> (PathBuf, PathBuf) {
    (
        directory.join("state-v1.json"),
        directory.join("authorization-v1.json"),
    )
}

fn driver(directory: &Path, backend: Fake) -> Driver<Fake> {
    let (state, authorization) = paths(directory);
    let mut driver = Driver::new(
        Store::open(state).unwrap(),
        backend,
        authorization,
        "test".into(),
    );
    driver.set_clock(clock);
    driver
}

fn post(driver: &Driver<Fake>, operation: &str, body: Value) -> Reply {
    driver.handle(
        "POST",
        &format!("/NetworkDriver.{operation}"),
        &serde_json::to_vec(&body).unwrap(),
    )
}

fn success(reply: Reply) -> Value {
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.get("Err").is_none(), "{}", reply.body);
    reply.body
}

fn denied(reply: Reply, reason: &str) {
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body["Err"]
            .as_str()
            .unwrap_or_default()
            .contains(reason),
        "{}",
        reply.body
    );
}

fn create(id: &str, options: Value) -> Value {
    json!({"NetworkID":id, "IPv4Data":[{"Pool":"172.30.60.0/24","Gateway":"172.30.60.1/24","AddressSpace":"LocalDefault"}], "IPv6Data":null,
        "Options":{"com.docker.network.generic":options}})
}

fn endpoint() -> Value {
    json!({"NetworkID":"net-fixture", "EndpointID":"endpoint-fixture", "SandboxKey":"/var/run/docker/netns/fixture",
        "Interface":{"Address":"172.30.60.2/24", "AddressIPv6":""}})
}

#[test]
fn docker_contract_and_idempotent_endpoint_lifecycle() {
    let temporary = tempfile::tempdir().unwrap();
    let backend = Fake::default();
    let driver = driver(temporary.path(), backend.clone());
    assert_eq!(
        success(driver.handle("POST", "/Plugin.Activate", b"{}")),
        json!({"Implements":["NetworkDriver"]})
    );
    assert_eq!(
        success(post(&driver, "GetCapabilities", json!({}))),
        json!({"Scope":"local","ConnectivityScope":"local"})
    );
    assert_eq!(driver.handle("GET", "/NetworkDriver.Join", b"").status, 405);
    assert_eq!(
        driver.handle("POST", "/NetworkDriver.Join", b"{").status,
        400
    );
    denied(post(&driver, "AllocateNetwork", json!({})), "Swarm");
    let req = create("net-fixture", json!({"laneway.dns":"172.30.60.100"}));
    success(post(&driver, "CreateNetwork", req.clone()));
    success(post(&driver, "CreateNetwork", req));
    denied(
        post(&driver, "CreateNetwork", create("overlap", json!({}))),
        "overlap",
    );
    success(post(&driver, "CreateEndpoint", endpoint()));
    let mut other_ip = endpoint();
    other_ip["Interface"]["Address"] = json!("172.30.60.3/24");
    denied(
        post(&driver, "CreateEndpoint", other_ip),
        "different address",
    );
    let joined = success(post(&driver, "Join", endpoint()));
    assert_eq!(
        joined["InterfaceName"],
        json!({"SrcName":"lwcb3d89ecb0d","DstPrefix":"eth"})
    );
    assert_eq!(joined["DNSNameserver"], json!(["172.30.60.100"]));
    assert_eq!(success(post(&driver, "Join", endpoint())), joined);
    let mut elsewhere = endpoint();
    elsewhere["SandboxKey"] = json!("other-sandbox");
    denied(post(&driver, "Join", elsewhere), "another sandbox");
    denied(
        post(&driver, "DeleteNetwork", json!({"NetworkID":"net-fixture"})),
        "endpoints",
    );
    success(post(&driver, "Leave", endpoint()));
    success(post(&driver, "DeleteEndpoint", endpoint()));
    success(post(
        &driver,
        "DeleteNetwork",
        json!({"NetworkID":"net-fixture"}),
    ));
    success(post(
        &driver,
        "DeleteNetwork",
        json!({"NetworkID":"net-fixture"}),
    ));
    assert_eq!(
        backend.calls(),
        [
            "apply:net-fixture",
            "join:lwhb3d89ecb0d",
            "join:lwhb3d89ecb0d",
            "leave:lwhb3d89ecb0d",
            "remove:net-fixture"
        ]
    );
    assert_eq!(success(driver.handle("GET", "/status", b""))["networks"], 0);
}

#[test]
fn go_v1_state_and_grants_survive_a_rust_restart_without_broadening_access() {
    let temporary = tempfile::tempdir().unwrap();
    let (state, authorization) = paths(temporary.path());
    write_private(&state, GO_STATE);
    write_private(&authorization, GO_GRANT);
    let backend = Fake::default();
    {
        let driver = driver(temporary.path(), backend.clone());
        driver.reconcile().unwrap();
        let status = success(driver.handle("GET", "/status", b""));
        assert_eq!(status["ready"], true);
        assert_eq!(status["policies"]["selective"], 1);
        assert_eq!(
            success(post(&driver, "EndpointOperInfo", endpoint()))["Value"]["joined"],
            true
        );
        success(post(&driver, "Leave", endpoint()));
    }
    let published: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(published["version"], 1);
    assert_eq!(published["networks"]["net-fixture"]["table"], 24434);
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    {
        let restarted = driver(temporary.path(), backend.clone());
        restarted.reconcile().unwrap();
        assert_eq!(
            success(post(&restarted, "EndpointOperInfo", endpoint()))["Value"]["joined"],
            false
        );
        let mut changed: Value = serde_json::from_slice(GO_GRANT).unwrap();
        changed["bypass_cidrs"] = json!(["192.0.2.0/24"]);
        write_private(&authorization, &serde_json::to_vec(&changed).unwrap());
        denied(post(&restarted, "Join", endpoint()), "bypasses changed");
        assert!(restarted.reconcile().is_err());
        assert_eq!(
            success(restarted.handle("GET", "/status", b""))["ready"],
            false
        );
    }
    assert_eq!(
        backend.calls(),
        [
            "apply:net-fixture",
            "leave:lwhb3d89ecb0d",
            "apply:net-fixture"
        ]
    );
}

#[test]
fn missing_invalid_and_expired_authorization_never_reaches_the_backend() {
    let temporary = tempfile::tempdir().unwrap();
    let (state, authorization) = paths(temporary.path());
    let backend = Fake::default();
    let driver = driver(temporary.path(), backend.clone());
    let option = json!({"laneway.policy":"selective","laneway.egress-cidrs":"10.60.0.0/16"});
    denied(
        post(
            &driver,
            "CreateNetwork",
            create("net-fixture", option.clone()),
        ),
        "controller-authorized",
    );
    let mut grant: Value = serde_json::from_slice(GO_GRANT).unwrap();
    grant["valid_until"] = json!("2020-01-01T00:00:00Z");
    write_private(&authorization, &serde_json::to_vec(&grant).unwrap());
    denied(
        post(
            &driver,
            "CreateNetwork",
            create("net-fixture", option.clone()),
        ),
        "expired",
    );
    write_private(&authorization, GO_GRANT);
    let mut more = option;
    more["laneway.egress-cidrs"] = json!("10.0.0.0/8");
    denied(
        post(&driver, "CreateNetwork", create("net-fixture", more)),
        "egress prefix was not granted",
    );
    assert!(!state.exists());
    assert!(backend.calls().is_empty());
}

#[test]
fn failed_creation_and_join_keep_recoverable_intent() {
    let temporary = tempfile::tempdir().unwrap();
    let (state_path, _) = paths(temporary.path());
    let backend = Fake::default();
    {
        let mut state = backend.0.lock().unwrap();
        state.fail_apply = true;
        state.fail_remove = true;
    }
    {
        let driver = driver(temporary.path(), backend.clone());
        denied(
            post(&driver, "CreateNetwork", create("net-fixture", json!({}))),
            "cleanup pending",
        );
        assert!(driver.reconcile().is_err());
    }
    let journal = Store::open(&state_path).unwrap();
    assert_eq!(journal.networks()["net-fixture"].phase, Phase::Creating);
    drop(journal);
    {
        let mut state = backend.0.lock().unwrap();
        state.fail_apply = false;
        state.fail_remove = false;
        state.fail_join = true;
    }
    {
        let driver = driver(temporary.path(), backend.clone());
        driver.reconcile().unwrap();
        success(post(
            &driver,
            "CreateNetwork",
            create("net-fixture", json!({})),
        ));
        success(post(&driver, "CreateEndpoint", endpoint()));
        denied(post(&driver, "Join", endpoint()), "backend");
        assert_eq!(
            success(post(&driver, "EndpointOperInfo", endpoint()))["Value"]["joined"],
            false
        );
    }
    let journal = Store::open(&state_path).unwrap();
    assert!(journal.networks()["net-fixture"].endpoints["endpoint-fixture"].join_pending);
    drop(journal);
    backend.0.lock().unwrap().fail_join = false;
    let restarted = driver(temporary.path(), backend.clone());
    restarted.reconcile().unwrap();
    success(post(&restarted, "Join", endpoint()));
    assert_eq!(
        success(post(&restarted, "EndpointOperInfo", endpoint()))["Value"]["joined"],
        true
    );
}

#[test]
fn protected_journal_rejects_concurrent_writers_symlinks_and_public_files() {
    let temporary = tempfile::tempdir().unwrap();
    let (state, _) = paths(temporary.path());
    let store = Store::open(&state).unwrap();
    assert!(Store::open(&state).is_err());
    drop(store);
    let target = temporary.path().join("target");
    write_private(&target, GO_STATE);
    symlink(&target, &state).unwrap();
    assert!(Store::open(&state).is_err());
    fs::remove_file(&state).unwrap();
    write_private(&state, GO_STATE);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(&state).is_err());
}

#[test]
fn policy_options_preserve_go_normalization_and_reject_ambiguity() {
    let parsed = Policy::from_options(Some(&json!({"com.docker.network.generic": {
        "laneway.policy":"selective", "laneway.egress-cidrs":"10.22.3.2/16,10.22.0.0/16, 10.100.0.0/16", "laneway.nat":"True"
    }}))).unwrap();
    assert_eq!(parsed.egress, Egress::Selective);
    assert_eq!(
        parsed
            .egress_cidrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.100.0.0/16", "10.22.0.0/16"]
    );
    assert!(parsed.nat);
    assert!(
        Policy::from_options(Some(
            &json!({"laneway.policy":"direct","generic":{"laneway.policy":"isolated"}})
        ))
        .is_err()
    );
    assert!(Policy::from_options(Some(&json!({"laneway.policy":"full-tunnel"}))).is_err());
}

#[tokio::test]
async fn docker_http_requests_run_over_the_unix_socket_and_close_cleanly() {
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        sync::oneshot,
        time::timeout,
    };

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("laneway.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap()); // stale after a crash
    let backend = Fake::default();
    let driver = Arc::new(driver(temporary.path(), backend.clone()));
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn({
        let path = path.clone();
        async move {
            crate::serve_until(&path, driver, async {
                let _ = stopped.await;
            })
            .await
        }
    });
    let mut socket = timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = UnixStream::connect(&path).await {
                break socket;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    socket.write_all(b"POST /Plugin.Activate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(2), socket.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({"Implements":["NetworkDriver"]}));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o660
    );

    let mut socket = UnixStream::connect(&path).await.unwrap();
    let payload = serde_json::to_string(&create("net-fixture", json!({}))).unwrap();
    let request = format!(
        "POST /NetworkDriver.CreateNetwork HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    response.clear();
    timeout(Duration::from_secs(2), socket.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, json!({}));
    assert_eq!(backend.calls(), ["apply:net-fixture"]);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(!path.exists());
}
