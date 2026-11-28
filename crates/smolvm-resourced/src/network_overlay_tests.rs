use super::*;
use crate::network::enter_private_namespace;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::thread;

fn namespace() -> File {
    thread::spawn(enter_private_namespace)
        .join()
        .unwrap()
        .unwrap()
}

fn inside<T: Send>(ns: BorrowedFd<'_>, action: impl FnOnce() -> T + Send) -> T {
    thread::scope(|threads| {
        threads
            .spawn(move || {
                assert_eq!(
                    unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) },
                    0
                );
                action()
            })
            .join()
            .unwrap()
    })
}

fn guest(
    router: &PrivateRouter,
    name: &str,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    published: bool,
) -> File {
    let ns = namespace();
    let target = namespace_path(ns.as_fd());
    ip(
        router.namespace(),
        &format!("link add {name} type veth peer name eth0 netns {target}\n"),
    )
    .unwrap();
    if published {
        publish_guest(router, name, address);
    }
    ip(
        ns.as_fd(),
        &format!(
            "link set lo up\nlink set eth0 up\naddr add {address}/32 dev eth0\n\
         route add default via {gateway} dev eth0 onlink\n",
        ),
    )
    .unwrap();
    ns
}

fn publish_guest(router: &PrivateRouter, name: &str, address: Ipv4Addr) {
    ip(
        router.namespace(),
        &format!("link set {name} up\nroute add {address}/32 dev {name} scope link\n",),
    )
    .unwrap();
}

fn keypair() -> (String, String) {
    let key = Command::new("wg").arg("genkey").output().unwrap();
    assert!(key.status.success());
    let mut public = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    public.stdin.take().unwrap().write_all(&key.stdout).unwrap();
    let public = public.wait_with_output().unwrap();
    assert!(public.status.success());
    (
        String::from_utf8(key.stdout).unwrap().trim_end().to_owned(),
        String::from_utf8(public.stdout)
            .unwrap()
            .trim_end()
            .to_owned(),
    )
}

fn config(namespace: File, worker: &str, allocation: &str, key: String, peer: Peer) -> Config {
    let parsed = parse_prefix(allocation).unwrap();
    let domain = parse_prefix("10.88.0.0/24").unwrap();
    Config {
        settings: Settings {
            version: 1,
            worker_id: worker.into(),
            worker_namespace: PathBuf::new(),
            network_id: "managed".into(),
            route_domain_id: "domain".into(),
            cidr: "10.88.0.0/24".into(),
            allocation_cidr: allocation.into(),
            listen_port: 51820,
            private_key_file: PathBuf::new(),
            peers: vec![peer],
        },
        allocation: Allocation {
            network_id: "managed".into(),
            route_domain_id: "domain".into(),
            cidr: "10.88.0.0/24".into(),
            first: parsed.first,
            last: parsed.last,
        },
        namespace,
        private_key: key,
        first: domain.first,
        last: domain.last,
    }
}

fn dns_query(peer: &UdpSocket, gateway: Ipv4Addr, name: &str) -> (u8, Vec<IpAddr>) {
    let mut request = vec![1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for part in name.split('.') {
        request.push(part.len() as u8);
        request.extend_from_slice(part.as_bytes());
    }
    request.extend_from_slice(&[0, 0, 1, 0, 1]);
    peer.send_to(&request, (gateway, 53)).unwrap();
    let mut response = [0; 512];
    let count = peer.recv(&mut response).unwrap();
    (
        response[3] & 0x0f,
        smolvm_network::dns::answer_ip_records(&response[..count])
            .into_iter()
            .map(|(address, _)| address)
            .collect(),
    )
}

#[test]
#[ignore = "requires isolated Linux Worker namespaces with iproute2, nft and WireGuard"]
fn cross_worker_wireguard_packets_dns_labels_and_withdrawal() {
    let outer = File::open("/proc/thread-self/ns/net").unwrap();
    let initial = File::open("/proc/1/ns/net").unwrap();
    assert_ne!(
        NamespaceIdentity::read(outer.as_fd()).unwrap(),
        NamespaceIdentity::read(initial.as_fd()).unwrap()
    );
    let worker_a = namespace();
    let worker_b = namespace();
    let right = namespace_path(worker_b.as_fd());
    ip(
        worker_a.as_fd(),
        &format!(
            "link add warder type veth peer name warder netns {right}\n\
         addr add 192.0.2.1/30 dev warder\nlink set warder up\n",
        ),
    )
    .unwrap();
    ip(
        worker_b.as_fd(),
        "addr add 192.0.2.2/30 dev warder\nlink set warder up\n",
    )
    .unwrap();

    let (a_key, a_pub) = keypair();
    let (b_key, b_pub) = keypair();
    let a_config = config(
        worker_a,
        "worker-a",
        "10.88.0.0/25",
        a_key,
        Peer {
            worker_id: "worker-b".into(),
            public_key: b_pub,
            endpoint: "192.0.2.2:51820".parse().unwrap(),
        },
    );
    let b_config = config(
        worker_b,
        "worker-b",
        "10.88.0.128/25",
        b_key,
        Peer {
            worker_id: "worker-a".into(),
            public_key: a_pub,
            endpoint: "192.0.2.1:51820".parse().unwrap(),
        },
    );
    let gateway = "10.88.0.1".parse().unwrap();
    let a = "10.88.0.2".parse().unwrap();
    let b = "10.88.0.130".parse().unwrap();
    let mut router_a = PrivateRouter::new(gateway, 24).unwrap();
    let router_b = PrivateRouter::new(gateway, 24).unwrap();
    let guest_a = guest(&router_a, "pfixturea", a, gateway, true);
    let guest_b = guest(&router_b, "pfixtureb", b, gateway, true);
    let mut a_link = Link::open(&a_config, &router_a).unwrap();
    let mut b_link = Link::open(&b_config, &router_b).unwrap();
    let a_remote = vec![("worker-b".to_owned(), b)];
    let b_remote = vec![("worker-a".to_owned(), a)];
    let deadline = || Instant::now() + Duration::from_secs(12);
    a_link
        .apply(
            &a_config,
            a_remote.clone(),
            vec![((a, b), (1, 2))],
            deadline(),
        )
        .unwrap();
    b_link
        .apply(
            &b_config,
            b_remote.clone(),
            vec![((b, a), (2, 1))],
            deadline(),
        )
        .unwrap();

    let udp_client = inside(guest_a.as_fd(), || UdpSocket::bind((a, 0)).unwrap());
    let udp_server = inside(guest_b.as_fd(), || UdpSocket::bind((b, 0)).unwrap());
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    udp_server
        .set_read_timeout(Some(Duration::from_millis(450)))
        .unwrap();
    let peer = udp_server.local_addr().unwrap();

    let work = tempfile::tempdir().unwrap();
    let db = work.path().join("catalog.sqlite");
    let _catalog = Catalog::open(&db, "boot", "session").unwrap();
    let dns = DnsView::default();
    dns.replace(Some(DnsEntries {
        deadline: deadline(),
        answers: BTreeMap::from([((a, "b.private".to_owned()), b)]),
    }));
    router_a.ensure_dns(&db, "managed", dns.clone()).unwrap();
    assert_eq!(
        dns_query(&udp_client, gateway, "b.private"),
        (0, vec![IpAddr::V4(b)])
    );

    let listener = inside(guest_b.as_fd(), || TcpListener::bind((b, 0)).unwrap());
    let service = listener.local_addr().unwrap();
    let connect = || {
        inside(guest_a.as_fd(), || {
            TcpStream::connect_timeout(&service, Duration::from_secs(2)).unwrap()
        })
    };
    let mut client = connect();
    let (mut backend, _) = listener.accept().unwrap();
    let mut stale_client = connect();
    let (_stale_backend, _) = listener.accept().unwrap();
    client.write_all(b"T").unwrap();
    let mut received = [0];
    backend.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"T");

    udp_client.send_to(b"first UDP datagram", peer).unwrap();
    let mut packet = [0; 64];
    let (count, origin) = udp_server.recv_from(&mut packet).unwrap();
    assert_eq!(origin.ip(), IpAddr::V4(a));
    assert_eq!(&packet[..count], b"first UDP datagram");
    udp_server.send_to(b"return datagram", origin).unwrap();
    let count = udp_client.recv(&mut packet).unwrap();
    assert_eq!(&packet[..count], b"return datagram");

    dns.replace(None);
    a_link
        .apply(&a_config, a_remote.clone(), vec![], deadline())
        .unwrap();
    b_link
        .apply(&b_config, b_remote.clone(), vec![], deadline())
        .unwrap();
    assert_eq!(
        dns_query(&udp_client, gateway, "b.private"),
        (3, Vec::new())
    );
    client.write_all(b"N").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        client.read(&mut received).unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    udp_client.send_to(b"blocked", peer).unwrap();
    assert!(udp_server.recv_from(&mut packet).is_err());

    a_link
        .apply(
            &a_config,
            a_remote.clone(),
            vec![((a, b), (1, 2))],
            deadline(),
        )
        .unwrap();
    b_link
        .apply(&b_config, b_remote, vec![((b, a), (2, 1))], deadline())
        .unwrap();
    stale_client.write_all(b"X").unwrap();
    stale_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        stale_client.read(&mut received).unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    let mut reopened = connect();
    let (mut new_backend, _) = listener.accept().unwrap();
    reopened.write_all(b"R").unwrap();
    new_backend.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"R");

    // Stage the new endpoint while the old Worker still owns the stable /32.
    let staged_guest = guest(&router_a, "pnewtarget", b, gateway, false);
    let staged = inside(staged_guest.as_fd(), || UdpSocket::bind(peer).unwrap());
    staged
        .set_read_timeout(Some(Duration::from_millis(450)))
        .unwrap();
    let observer = "10.88.0.131".parse().unwrap();
    let observer_guest = guest(&router_b, "pobserver", observer, gateway, true);
    let observer_socket = inside(observer_guest.as_fd(), || {
        UdpSocket::bind((observer, 0)).unwrap()
    });
    observer_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    udp_client
        .send_to(b"source still owns address", peer)
        .unwrap();
    let (count, _) = udp_server.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..count], b"source still owns address");
    assert!(staged.recv_from(&mut packet).is_err());

    // Close the old port and remove its WireGuard route before opening the new port.
    ip(router_b.namespace(), "link del pfixtureb\n").unwrap();
    b_link.revoke().unwrap();
    a_link.apply(&a_config, vec![], vec![], deadline()).unwrap();
    udp_client.send_to(b"withheld during cutover", peer).ok();
    assert!(udp_server.recv_from(&mut packet).is_err());
    assert!(staged.recv_from(&mut packet).is_err());

    // Publish the new endpoint. A separate Guest on the old Worker traverses
    // the now-reversed overlay to the same address and receives its reply.
    publish_guest(&router_a, "pnewtarget", b);
    a_link
        .apply(
            &a_config,
            vec![("worker-b".into(), observer)],
            vec![((b, observer), (3, 4))],
            deadline(),
        )
        .unwrap();
    b_link
        .apply(
            &b_config,
            vec![("worker-a".into(), b)],
            vec![((observer, b), (4, 3))],
            deadline(),
        )
        .unwrap();
    observer_socket
        .send_to(b"arrives at new owner", peer)
        .unwrap();
    let (count, origin) = staged.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..count], b"arrives at new owner");
    staged.send_to(b"new owner replied", origin).unwrap();
    let count = observer_socket.recv(&mut packet).unwrap();
    assert_eq!(&packet[..count], b"new owner replied");
    assert!(udp_server.recv_from(&mut packet).is_err());
}

#[test]
fn overlay_revision_survives_catalog_reopen() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("catalog.sqlite");
    let catalog = Catalog::open(&path, "boot", "initial").unwrap();
    catalog.db.execute_batch(
        "DROP TABLE network_overlay_revisions; DROP TABLE network_overlay_source_fences; PRAGMA user_version=33;",
    ).unwrap();
    drop(catalog);

    let configure = || {
        config(
            File::open("/proc/thread-self/ns/net").unwrap(),
            "worker-a",
            "10.88.0.0/25",
            "".into(),
            Peer {
                worker_id: "worker-b".into(),
                public_key: "".into(),
                endpoint: "192.0.2.2:51820".parse().unwrap(),
            },
        )
    };
    let catalog = Catalog::open(&path, "boot", "upgrade").unwrap();
    let mut overlay = Overlay {
        config: Some(configure()),
        ..Overlay::default()
    };
    overlay.configure_catalog(&catalog).unwrap();
    let expiry = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(10))
        .as_millis() as u64;
    let snapshot = |revision| Apply {
        route_domain_id: "domain".into(),
        revision,
        lease_seconds: 10,
        expires_at_unix_ms: expiry,
        routes: Vec::new(),
    };
    overlay.install(&catalog, snapshot(2)).unwrap();
    overlay.install(&catalog, snapshot(2)).unwrap();
    overlay.mark_reconciled(true);
    assert!(overlay.withdrawn("moved-machine", "10.88.0.130".parse().unwrap()));
    drop(catalog);

    let reopened = Catalog::open(&path, "boot", "reopen").unwrap();
    let mut recovered = Overlay {
        config: Some(configure()),
        ..Overlay::default()
    };
    assert!(!recovered.withdrawn("moved-machine", "10.88.0.130".parse().unwrap()));
    assert_eq!(
        recovered.install(&reopened, snapshot(1)).unwrap_err().code,
        "E_STALE_REVISION"
    );
    assert_eq!(
        recovered.install(&reopened, snapshot(2)).unwrap_err().code,
        "E_STALE_REVISION"
    );
    recovered.install(&reopened, snapshot(3)).unwrap();
    assert!(!recovered.withdrawn("moved-machine", "10.88.0.130".parse().unwrap()));
    recovered.mark_reconciled(true);
    assert!(recovered.withdrawn("moved-machine", "10.88.0.130".parse().unwrap()));
}

#[test]
#[ignore = "requires isolated Linux Worker namespaces, WireGuard and /dev/net/tun"]
fn overlay_commit_requires_real_source_tap_fence_and_withdrawal() {
    use crate::catalog::NewExecution;
    use crate::ipc::{Expected, Request, PROTOCOL};
    use crate::network_runtime::NetworkRuntime;
    use crate::network_transfer::{authorize_overlay_commit, fence_source, Transfer};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let work = tempfile::tempdir().unwrap();
    let source_ns = namespace();
    let target_ns = namespace();
    let (source_key, source_public) = keypair();
    let (target_key, target_public) = keypair();
    let runtime = |worker, ns: &File, key, peer, peer_key, endpoint, allocation| {
        let key_path = work.path().join(format!("{worker}.key"));
        let config_path = work.path().join(format!("{worker}.json"));
        let namespace_pins = work.path().join(format!("{worker}-pins"));
        fs::create_dir(&namespace_pins).unwrap();
        fs::write(&key_path, key).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &config_path,
            json!({
                "version":1, "worker_id":worker, "worker_namespace":namespace_path(ns.as_fd()),
                "network_id":"managed", "route_domain_id":"domain", "cidr":"10.88.0.0/24",
                "allocation_cidr":allocation, "listen_port":51820, "private_key_file":key_path,
                "peers":[{"worker_id":peer, "public_key":peer_key, "endpoint":endpoint}],
            })
            .to_string(),
        )
        .unwrap();
        inside(ns.as_fd(), || {
            NetworkRuntime::new(namespace_pins, None, Some(&config_path)).unwrap()
        })
    };
    let mut source_network = runtime(
        "source",
        &source_ns,
        source_key,
        "target",
        target_public,
        "192.0.2.2:51820",
        "10.88.0.0/25",
    );
    let mut target_network = runtime(
        "target",
        &target_ns,
        target_key,
        "source",
        source_public,
        "192.0.2.1:51820",
        "10.88.0.128/25",
    );

    let source_path = work.path().join("source.sqlite");
    let mut catalog = Catalog::open(&source_path, "boot", "source").unwrap();
    let target_catalog =
        Catalog::open(&work.path().join("target.sqlite"), "boot", "target").unwrap();
    source_network
        .overlay()
        .configure_catalog(&catalog)
        .unwrap();
    target_network
        .overlay()
        .configure_catalog(&target_catalog)
        .unwrap();
    let bundle = format!("sha256:{}", "a".repeat(64));
    catalog.register_bundle(&bundle, &"c".repeat(64)).unwrap();
    let mut request = Request {
        protocol: PROTOCOL.into(),
        request_id: "launch".into(),
        operation_id: Some("launch".into()),
        request_digest: Some(format!("sha256:{}", "b".repeat(64))),
        route_id: Some("deep".into()),
        bundle_digest: Some(bundle.clone()),
        expected: Some(Expected {
            instance_id: "source-instance".into(),
            incarnation_id: None,
            execution_epoch: 0,
        }),
        method: "ReserveNetworkAttachment".into(),
        fd_table: Vec::new(),
        payload: json!({"attachment_id":"source-attachment","network_id":"managed","device_id":"net0","mode":"native","dns_name":"moving.private"}),
    };
    let launch = catalog.begin(&request, "launch").unwrap();
    let reservation = catalog
        .reserve_network_with_overlay(
            &request,
            &request.payload().unwrap(),
            source_network.overlay(),
        )
        .unwrap();
    let prepared = source_network
        .prepare(
            &catalog,
            &request.derived(
                "PrepareNetworkAttachment",
                json!({"attachment_id":"source-attachment"}),
            ),
        )
        .unwrap();
    let expected = Expected {
        instance_id: "source-instance".into(),
        incarnation_id: Some("source-incarnation".into()),
        execution_epoch: 1,
    };
    let pid = std::process::id() as i32;
    let (start, _) = crate::worker::observe_pid(pid).unwrap();
    let execution = catalog
        .register_execution(
            &launch,
            NewExecution {
                route: "deep",
                bundle: &bundle,
                expected: &expected,
                boot: "boot",
                pid,
                start,
                uid: 0,
                permit_digest: &"d".repeat(64),
                kernel_import: None,
            },
        )
        .unwrap();
    let offered = catalog.offer_tap(&execution, "source-attachment").unwrap();
    let attached = catalog
        .acknowledge_tap(
            &execution,
            "source-attachment",
            &prepared.lease_id,
            offered.revision,
        )
        .unwrap();
    request.expected = Some(expected);
    let opened = source_network.publish_initial(&catalog, &request.derived(
        "PublishNetworkAttachment",
        json!({"attachment_id":"source-attachment","lease_id":attached.lease_id,"expected_revision":attached.revision}),
    ), &execution, || Ok(())).unwrap();
    assert_eq!(opened.gate, "open");
    catalog.finish(&request, false, 1).unwrap();
    let transfer = Transfer {
        machine_id: "machine".into(),
        source_worker_id: "source".into(),
        target_worker_id: "target".into(),
        expected_owner_epoch: 1,
        target_execution_epoch: 2,
        attachment_id: opened.attachment.attachment_id.clone(),
        attachment_revision: opened.revision,
        target_attachment_id: "target-attachment".into(),
        target_attachment_revision: 9,
        policy_revision: 1,
        migration_id: "migration".into(),
        network_mode: "native".into(),
        private_ipv4: opened.attachment.private_ipv4,
        guest_ipv4: opened.attachment.guest_ipv4,
        guest_gateway_ipv4: opened.attachment.gateway_ipv4,
        guest_prefix: opened.attachment.guest_prefix,
        guest_mac: opened.attachment.mac,
        route_domain_id: "domain".into(),
    };
    let expires_at_unix_ms = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        + Duration::from_secs(10))
    .as_millis() as u64;
    let route = Route {
        machine_id: transfer.machine_id.clone(),
        worker_id: transfer.source_worker_id.clone(),
        owner_epoch: 1,
        instance_id: execution.instance_id.clone(),
        incarnation_id: execution.incarnation_id.clone(),
        execution_epoch: 1,
        attachment_id: transfer.attachment_id.clone(),
        attachment_revision: opened.revision,
        policy_revision: 1,
        networks: Vec::new(),
        private_ipv4: transfer.private_ipv4,
        dns_name: "moving.private".into(),
    };
    let apply = |revision, routes| Apply {
        route_domain_id: "domain".into(),
        revision,
        lease_seconds: 10,
        expires_at_unix_ms,
        routes,
    };
    source_network
        .apply_overlay_routes(&catalog, apply(1, vec![route.clone()]))
        .unwrap();
    target_network
        .apply_overlay_routes(&target_catalog, apply(1, vec![route]))
        .unwrap();
    assert_eq!(
        authorize_overlay_commit(target_network.overlay(), &transfer, None)
            .unwrap_err()
            .code,
        "E_FENCE_UNPROVEN"
    );

    let fence_request = || serde_json::from_value(json!({"transfer":transfer})).unwrap();
    let fence = fence_source(&catalog, &execution, &mut source_network, fence_request()).unwrap();
    assert_eq!(
        catalog.tap_lease(&transfer.attachment_id).unwrap_err().code,
        "E_NOT_FOUND"
    );
    assert_eq!(
        authorize_overlay_commit(target_network.overlay(), &transfer, Some(&fence))
            .unwrap_err()
            .code,
        "E_FENCE_UNPROVEN"
    );

    target_network
        .apply_overlay_routes(&target_catalog, apply(2, Vec::new()))
        .unwrap();
    authorize_overlay_commit(target_network.overlay(), &transfer, Some(&fence)).unwrap();
    let mut mismatched = transfer.clone();
    mismatched.target_execution_epoch += 1;
    assert_eq!(
        authorize_overlay_commit(target_network.overlay(), &mismatched, Some(&fence))
            .unwrap_err()
            .code,
        "E_FENCE_UNPROVEN"
    );

    // Simulate release of the ordinary reservation after migration and verify
    // the source-slice hold and byte-exact receipt survive broker restart.
    catalog.db.execute("UPDATE network_attachments SET state='released' WHERE attachment_id='source-attachment'", []).unwrap();
    drop(catalog);
    let mut reopened = Catalog::open(&source_path, "boot", "reopened").unwrap();
    let execution = reopened.reconcile_execution("source-incarnation").unwrap();
    reopened.complete_recovery("reopened").unwrap();
    let recovered =
        fence_source(&reopened, &execution, &mut source_network, fence_request()).unwrap();
    assert_eq!(json!(fence), json!(recovered));
    let next = Request {
        operation_id: Some("next".into()),
        request_id: "next".into(),
        expected: Some(Expected {
            instance_id: "next-instance".into(),
            incarnation_id: None,
            execution_epoch: 0,
        }),
        payload: json!({"attachment_id":"next-attachment","network_id":"managed","device_id":"net0","mode":"native"}),
        ..request
    };
    reopened.begin(&next, "launch").unwrap();
    let next_reservation = reopened
        .reserve_network_with_overlay(&next, &next.payload().unwrap(), source_network.overlay())
        .unwrap();
    assert_eq!(
        reservation.private_ipv4,
        "10.88.0.2".parse::<Ipv4Addr>().unwrap()
    );
    assert_eq!(
        next_reservation.private_ipv4,
        "10.88.0.3".parse::<Ipv4Addr>().unwrap()
    );
}
