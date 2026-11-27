use super::*;
use laneway_protocol::policy::{CompiledPolicy, Packet};
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    database: std::path::PathBuf,
    spec: GatewaySpec,
    node: Id,
    other: Id,
}

impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let database = dir.path().join("controller.db");
        let spec = GatewaySpec {
            gateway: Id::new([3; 16])?,
            network: Id::new([1; 16])?,
            client: Id::new([4; 16])?,
            address: Ipv4Addr::new(192, 168, 2, 17),
            port: 8123,
        };
        crate::backup::initialize(
            &database,
            spec.network,
            Id::new([2; 16])?,
            "test",
            "100.80.0.0/24",
        )?;
        let node = Id::new([5; 16])?;
        let other = Id::new([6; 16])?;
        transaction(&database, |tx, now| {
            for (i, id) in [(1, spec.client), (2, node), (3, other)] {
                tx.execute("INSERT INTO nodes(id,network_id,name,enabled_capabilities,created_at) VALUES(?,?,?,?,?)",
                    params![id.as_bytes(),spec.network.as_bytes(),id.to_string(),ROUTER as i64,now])?;
                tx.execute("INSERT INTO overlay_addresses(id,network_id,node_id,address,prefix_length,created_at)
                    VALUES(randomblob(16),?,?,?,32,?)",params![spec.network.as_bytes(),id.as_bytes(),[100u8,80,0,i],now])?;
                tx.execute("INSERT INTO certificates(id,network_id,node_id,serial,der,not_before,not_after,created_at)
                    VALUES(randomblob(16),?,?,?,x'01',?-60,?+86400,?)",
                    params![spec.network.as_bytes(),id.as_bytes(),[i],now,now,now])?;
                tx.execute(
                    "INSERT INTO node_locations(node_id,observed_at) VALUES(?,?)",
                    (id.as_bytes(), now),
                )?;
            }
            Ok(())
        })?;
        Ok(Self {
            _dir: dir,
            database,
            spec,
            node,
            other,
        })
    }
    fn consume(&self) -> Result<()> {
        transaction(&self.database, |tx, now| {
            let (_, first) = issue_grant(tx, &self.spec, now)?;
            let (_, second) = issue_grant(tx, &self.spec, now)?;
            assert_ne!(*first, *second);
            let hash = |code: &str| -> Result<[u8; 32]> {
                Ok(Sha256::digest(URL_SAFE_NO_PAD.decode(code)?).into())
            };
            let stale: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM enrollment_tokens WHERE token_hash=?)",
                [hash(&first)?],
                |r| r.get(0),
            )?;
            assert!(!stale);
            assert_eq!(tx.execute("UPDATE enrollment_tokens SET consumed_by=?,consumed_at=? WHERE token_hash=? AND consumed_at IS NULL",
                params![self.node.as_bytes(),now,hash(&second)?])?,1);
            assert!(issue_grant(tx, &self.spec, now).is_err());
            Ok(())
        })
    }
    fn route(&self, id: Id, address: Ipv4Addr, length: u8) -> Result<()> {
        transaction(&self.database, |tx, now| {
            tx.execute("INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,created_at,approved_at)
                VALUES(?,?,?,?,?,'subnet','nat',100,'approved',?,?)",params![id.as_bytes(),self.spec.network.as_bytes(),self.other.as_bytes(),address.octets(),length,now,now])?;
            Ok(())
        })
    }
    fn policy(&self) -> Result<CompiledPolicy> {
        transaction(&self.database, |tx, _| {
            let mut snapshot = PolicySnapshot {
                network_id: self.spec.network.as_bytes().to_vec(),
                configuration_epoch: 1,
                default_action: PolicyAction::Deny as i32,
                // Exercise a pre-existing broad allow at the highest manual priority.
                rules: vec![PolicyRule {
                    rule_id: vec![0x17; 16],
                    priority: 0,
                    action: PolicyAction::Accept as i32,
                    selector: Some(TrafficSelector {
                        ip_protocol: IpProtocol::Any as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
            };
            apply_policy(tx, self.spec.network, &mut snapshot)?;
            Ok(CompiledPolicy::compile(snapshot, self.spec.network, 1)?)
        })
    }
}

#[test]
fn exact_gateway_policy_precedes_any_existing_allow_and_is_bound_to_consumed_node() -> Result<()> {
    let f = Fixture::new()?;
    assert!(!activate(&f.database, &f.spec)?);
    assert!(
        preflight(
            &f.database,
            &GatewaySpec {
                network: Id::new([8; 16])?,
                ..f.spec
            }
        )
        .is_err()
    );
    f.consume()?;
    assert!(activate(&f.database, &f.spec)?);
    assert!(activate(&f.database, &f.spec)?);
    let policy = f.policy()?;
    let ip = Ipv4Addr::new(100, 80, 0, 1);
    let remote = f.spec.address;
    let allows = |source: Id, dest: Id, src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, port: u16| {
        policy
            .evaluate(
                source,
                dest,
                Packet {
                    source: src.into(),
                    destination: dst.into(),
                    protocol,
                    destination_port: Some(port),
                },
                |_, _| {},
            )
            .0
    };
    assert!(allows(f.spec.client, f.node, ip, remote, 6, f.spec.port));
    assert!(!allows(f.other, f.node, ip, remote, 6, f.spec.port));
    assert!(!allows(
        f.spec.client,
        f.node,
        Ipv4Addr::new(100, 80, 0, 3),
        remote,
        6,
        f.spec.port
    ));
    assert!(!allows(f.spec.client, f.node, ip, remote, 6, 443));
    assert!(!allows(f.spec.client, f.node, ip, remote, 17, f.spec.port));
    assert!(!allows(
        f.spec.client,
        f.node,
        ip,
        Ipv4Addr::new(192, 168, 2, 18),
        6,
        f.spec.port
    ));
    assert!(allows(f.node, f.spec.client, remote, ip, 6, 49152));
    assert!(!allows(f.node, f.spec.client, remote, ip, 6, 22));
    assert!(!allows(f.node, f.other, remote, ip, 6, 49152));
    assert!(allows(f.spec.client, f.other, ip, remote, 6, 80));
    transaction(&f.database, |tx, now| {
        tx.execute(
            "UPDATE node_locations SET observed_at=? WHERE node_id=?",
            (now - 91, f.node.as_bytes()),
        )?;
        Ok(())
    })?;
    assert!(!activate(&f.database, &f.spec)?);
    let blocked = f.policy()?;
    assert!(
        !blocked
            .evaluate(
                f.spec.client,
                f.node,
                Packet {
                    source: ip.into(),
                    destination: remote.into(),
                    protocol: 6,
                    destination_port: Some(f.spec.port)
                },
                |_, _| {}
            )
            .0
    );
    Ok(())
}

#[test]
fn existing_host_can_be_staged_but_never_overwritten_and_cleanup_preserves_unrelated_state()
-> Result<()> {
    let f = Fixture::new()?;
    let prior = Id::new([7; 16])?;
    let unrelated = Id::new([8; 16])?;
    f.route(prior, f.spec.address, 32)?;
    f.route(unrelated, Ipv4Addr::new(192, 168, 7, 0), 24)?;
    assert_eq!(preflight(&f.database, &f.spec)?.unwrap().route_id, prior);
    f.consume()?;
    let error = activate(&f.database, &f.spec).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<GatewayRouteConflict>()
            .unwrap()
            .route_id,
        prior
    );
    transaction(&f.database, |tx, _| {
        assert_eq!(
            tx.execute(
                "UPDATE routes SET state='withdrawn' WHERE state='approved' AND id=?",
                [prior.as_bytes()]
            )?,
            1
        );
        Ok(())
    })?;
    assert!(activate(&f.database, &f.spec)?);
    let wrong = GatewaySpec {
        client: f.other,
        ..f.spec
    };
    cleanup(&f.database, &wrong)?;
    assert!(activate(&f.database, &f.spec)?);
    cleanup(&f.database, &f.spec)?;
    cleanup(&f.database, &f.spec)?;
    transaction(&f.database, |tx, _| {
        assert_eq!(
            tx.query_row(
                "SELECT state FROM routes WHERE id=?",
                [unrelated.as_bytes()],
                |r| r.get::<_, String>(0)
            )?,
            "approved"
        );
        assert_eq!(
            tx.query_row(
                "SELECT state FROM routes WHERE id=?",
                [prior.as_bytes()],
                |r| r.get::<_, String>(0)
            )?,
            "withdrawn"
        );
        let current: i64 = tx.query_row(
            "SELECT count(*) FROM certificates WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(current, 2);
        assert!(owned_node(tx, &f.spec)?.is_none());
        Ok(())
    })?;
    f.route(Id::new([9; 16])?, Ipv4Addr::new(192, 168, 2, 0), 24)?;
    assert!(preflight(&f.database, &f.spec).is_err());
    Ok(())
}

#[test]
fn changing_the_caller_preserves_enrollment_and_switches_the_grant_atomically() -> Result<()> {
    let f = Fixture::new()?;
    f.consume()?;
    assert!(activate(&f.database, &f.spec)?);
    let desired = GatewaySpec {
        client: f.other,
        ..f.spec
    };
    let check_caller = |granted: Id| -> Result<()> {
        let policy = f.policy()?;
        for (node, ip) in [
            (f.spec.client, Ipv4Addr::new(100, 80, 0, 1)),
            (f.other, Ipv4Addr::new(100, 80, 0, 3)),
        ] {
            let packet = Packet {
                source: ip.into(),
                destination: f.spec.address.into(),
                protocol: 6,
                destination_port: Some(f.spec.port),
            };
            assert_eq!(
                policy.evaluate(node, f.node, packet, |_, _| {}).0,
                node == granted
            );
        }
        Ok(())
    };
    check_caller(f.spec.client)?;
    assert!(change_client(&f.database, &f.spec, Id::new([9; 16])?).is_err());
    assert!(change_client(&f.database, &f.spec, f.node).is_err());
    change_client(&f.database, &f.spec, f.other)?;
    change_client(&f.database, &f.spec, f.other)?;
    cleanup(&f.database, &f.spec)?;
    check_caller(f.other)?;
    assert!(activate(&f.database, &desired)?);
    change_client(&f.database, &desired, f.spec.client)?;
    check_caller(f.spec.client)?;
    transaction(&f.database, |tx, _| {
        assert_eq!(owned_node(tx, &f.spec)?, Some(f.node));
        assert!(published(tx, &f.spec, f.node)?);
        let published: i64 = tx.query_row(
            "SELECT count(*) FROM audit_events WHERE action='twingate.gateway.publish'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(published, 1);
        Ok(())
    })
}

#[test]
fn only_the_certificate_issued_from_the_live_gateway_grant_can_publish() -> Result<()> {
    use crate::{SessionStore, enrollment::renewal::NodeCredential, node_pki::NodeIssuer};
    use laneway_protocol::v1::{EnrollmentClass, EnrollmentRequest};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let f = Fixture::new()?;
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let mut ca = CertificateParams::new(vec![])?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = ca.self_signed(&key)?;
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let issuer = NodeIssuer::new(std::slice::from_ref(cert.der()), &private_key, 3600)?;
    let mut store = SessionStore::open(&f.database)?;
    let unrelated_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let (old_name, old_code) = transaction(&f.database, |tx, now| issue_grant(tx, &f.spec, now))?;
    let (name, code) = transaction(&f.database, |tx, now| issue_grant(tx, &f.spec, now))?;
    let request = EnrollmentRequest {
        enrollment_token: code.to_string(),
        requested_name: name,
        expected_network_id: f.spec.network.as_bytes().to_vec(),
        expected_enrollment_class: EnrollmentClass::DurableNode as i32,
        pkcs10_csr_der: CertificateParams::new(vec![])?
            .serialize_request(&unrelated_key)?
            .der()
            .to_vec(),
        wireguard_public_key: x25519_dalek::x25519([13; 32], x25519_dalek::X25519_BASEPOINT_BYTES)
            .to_vec(),
    };
    let mut invalid = request.clone();
    invalid.enrollment_token = old_code.to_string();
    invalid.requested_name = old_name;
    assert!(store.redeem_enrollment(invalid, &issuer, || false).is_err());
    let mut invalid = request.clone();
    invalid.expected_network_id = vec![8; 16];
    assert!(store.redeem_enrollment(invalid, &issuer, || false).is_err());
    let enrolled = store.redeem_enrollment(request.clone(), &issuer, || false)?;
    let peer = NodeCredential::from_verified_peer(
        &enrolled.certificate_chain.unwrap().certificates_der[0],
    )?;
    assert!(!activate(&f.database, &f.spec)?);
    store.observe_node(&peer, Ipv4Addr::LOCALHOST.into(), None)?;
    assert!(activate(&f.database, &f.spec)?);
    let mut changed = request.clone();
    changed.pkcs10_csr_der = CertificateParams::new(vec![])?
        .serialize_request(&KeyPair::generate_for(&PKCS_ED25519)?)?
        .der()
        .to_vec();
    assert!(store.redeem_enrollment(changed, &issuer, || false).is_err());
    cleanup(&f.database, &f.spec)?;
    assert!(
        store
            .observe_node(&peer, Ipv4Addr::LOCALHOST.into(), None)
            .is_err()
    );
    assert!(store.redeem_enrollment(request, &issuer, || false).is_err());
    Ok(())
}

#[test]
fn configuration_service_withdraws_expired_publication_even_if_reconciliation_stops() -> Result<()>
{
    let f = Fixture::new()?;
    f.consume()?;
    assert!(activate(&f.database, &f.spec)?);
    transaction(&f.database, |tx, now| {
        let deadline = publication_deadline(tx, f.spec.network)?;
        assert!((now + 89..=now + 90).contains(&deadline));
        expire_publications(tx, f.spec.network, deadline - 1)?;
        assert!(published(tx, &f.spec, f.node)?);
        expire_publications(tx, f.spec.network, deadline)?;
        assert!(!published(tx, &f.spec, f.node)?);
        assert_eq!(publication_deadline(tx, f.spec.network)?, i64::MAX);
        Ok(())
    })?;
    assert!(activate(&f.database, &f.spec)?);
    Ok(())
}
