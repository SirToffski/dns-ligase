use super::*;
use tokio::task::JoinHandle;

struct Replies {
    addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Replies {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn reply(wire: &[u8]) -> Vec<u8> {
    let mut msg = DnsMessage::parse(wire).unwrap();
    msg.header.flags = match msg.questions[0].name.as_str() {
        "nxdomain.test" => 0x8183,
        "servfail.test" => 0x8182,
        _ => 0x8180,
    };
    if !matches!(
        msg.questions[0].name.as_str(),
        "nxdomain.test" | "servfail.test" | "plain.test"
    ) {
        msg.answers.push(crate::dns::DnsResourceRecord {
            name: msg.questions[0].name.clone(),
            rtype: 5,
            rclass: 1,
            ttl: 60,
            rdata: crate::dns::serialize_name("tracker.test").unwrap(),
            cname_target: Some("tracker.test".into()),
        });
        if msg.questions[0].name == "chain.test" {
            let mut next = msg.answers[0].clone();
            next.name = "tracker.test".into();
            next.cname_target = Some("last.test".into());
            msg.answers.push(next);
        }
    }
    msg.serialize().unwrap()
}
async fn replies() -> Replies {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&reply(&buf[..n]), peer).await.unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            tasks.spawn(async move {
                while let Ok(n) = stream.read_u16().await {
                    let mut wire = vec![0; n as usize];
                    if stream.read_exact(&mut wire).await.is_err() {
                        break;
                    }
                    let response = reply(&wire);
                    let mut frame = (response.len() as u16).to_be_bytes().to_vec();
                    frame.extend(response);
                    if stream.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Replies {
        addr,
        tasks: vec![udp_task, tcp_task],
    }
}
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn state(addr: SocketAddr, rules: Blocklist) -> QueryState {
    QueryState {
        upstream: Arc::new(Upstream::new(addr)),
        blocklist: Arc::new(rules),
        clients: Arc::default(),
        log_queries: true,
    }
}
async fn recorded(
    state: &QueryState,
    name: &str,
    transport: ClientTransport,
) -> (DnsMessage, Vec<(String, String, String)>) {
    recorded_from(state, name, transport, "127.0.0.1:10000").await
}
async fn recorded_from(
    state: &QueryState,
    name: &str,
    transport: ClientTransport,
    client: &str,
) -> (DnsMessage, Vec<(String, String, String)>) {
    let wire = DnsMessage::new_query(1, name, 1).serialize().unwrap();
    let output = std::sync::Mutex::new(None);
    let mut logs = Vec::new();
    handle_request(
        &wire,
        state,
        transport,
        client.parse().unwrap(),
        |wire| {
            std::future::ready({
                *output.lock().unwrap() = Some(wire);
                Ok(())
            })
        },
        |_, domain, _, action, rule| {
            logs.push((domain.to_owned(), action.to_owned(), rule.to_owned()))
        },
    )
    .await
    .unwrap();
    let response = output.into_inner().unwrap().unwrap();
    (DnsMessage::parse(&response).unwrap(), logs)
}

#[tokio::test]
async fn all_allow_rule_shapes_override_cname_blocks_on_both_transports() {
    let server = replies().await;
    let allow_regex = regex::Regex::new(r"^site\.test$").unwrap();
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        for kind in 0..5 {
            let mut rules = Blocklist::new();
            rules.block_domains.insert("tracker.test".into());
            let name = if kind == 1 {
                "sub.site.test"
            } else {
                "site.test"
            };
            match kind {
                0 => {
                    rules.allow_domains.insert(name.into());
                }
                1 => {
                    rules.parse_auto_mode("||site.test^", true).unwrap();
                }
                2 => {
                    rules
                        .allow_regex
                        .push(allow_regex.clone());
                }
                3 => {
                    crate::blocklist::parse_lines_into_allow(
                        &mut rules,
                        "site.test\n",
                        "allow-url",
                    );
                }
                _ => {
                    crate::blocklist::parse_lines_into_regex(
                        &mut rules,
                        r"^site\.test$",
                        true,
                        "regex-url",
                    );
                }
            }
            let state = state(server.addr, rules);
            let (response, logs) = recorded(&state, name, transport).await;
            assert_eq!(response.header.flags & 15, 0);
            assert_eq!(
                response.answers[0].cname_target.as_deref(),
                Some("tracker.test")
            );
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].1, "allowed");
            let (response, logs) = recorded(&state, "tracker.test", transport).await;
            assert_eq!(response.header.flags & 15, 3);
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].1, "blocked");
        }
    }
}

#[tokio::test]
async fn unmatched_cnames_block_and_plain_queries_forward_with_one_log() {
    let server = replies().await;
    let mut rules = Blocklist::new();
    rules.block_domains.insert("tracker.test".into());
    let state = state(server.addr, rules);
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        let (response, logs) = recorded(&state, "site.test", transport).await;
        assert_eq!(response.header.flags & 15, 3);
        assert_eq!(
            logs,
            vec![(
                "site.test".into(),
                "blocked".into(),
                "cname:tracker.test block:tracker.test".into()
            )]
        );
        let (response, logs) = recorded(&state, "plain.test", transport).await;
        assert_eq!(response.header.flags & 15, 0);
        assert_eq!(
            logs,
            vec![("plain.test".into(), "forwarded".into(), "".into())]
        );
    }
}

fn client_state(addr: SocketAddr) -> QueryState {
    let mut rules = Blocklist::new();
    rules
        .block_domains
        .extend(["tracker.test".into(), "site.test".into()]);
    let clients = crate::config::ClientsConfig {
        unfiltered: vec!["192.0.2.53".into(), "198.51.100.0/24".into()],
        allow: vec![crate::config::ClientAllowConfig {
            sources: vec!["192.0.2.60".into()],
            domains: vec!["site.test".into()],
            regex: vec![],
        }],
    };
    QueryState {
        clients: Arc::new(crate::clients::ClientPolicy::from_config(&clients).unwrap()),
        ..state(addr, rules)
    }
}

#[tokio::test]
async fn unfiltered_clients_skip_name_and_cname_blocks() {
    let server = replies().await;
    let state = client_state(server.addr);
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        for (client, entry) in [
            ("192.0.2.53:5000", "192.0.2.53"),
            ("198.51.100.7:5000", "198.51.100.0/24"),
            ("[::ffff:192.0.2.53]:5000", "192.0.2.53"),
        ] {
            // Directly blocked name, and a name whose CNAME target is blocked.
            for name in ["tracker.test", "other.test"] {
                let (response, logs) = recorded_from(&state, name, transport, client).await;
                assert_eq!(response.header.flags & 15, 0, "{client} {name}");
                assert_eq!(
                    logs,
                    vec![(name.into(), "bypassed".into(), format!("client_bypass:{entry}"))]
                );
            }
        }
        // Everyone else is still filtered.
        let (response, logs) = recorded_from(&state, "tracker.test", transport, "192.0.2.99:5000").await;
        assert_eq!(response.header.flags & 15, 3);
        assert_eq!(logs[0].1, "blocked");
    }
}

#[tokio::test]
async fn per_client_allow_overrides_global_block_only_for_that_client() {
    let server = replies().await;
    let state = client_state(server.addr);
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        // site.test is globally blocked and CNAMEs to a blocked tracker; the
        // per-client allow exempts both, like a global allow rule would.
        let (response, logs) = recorded_from(&state, "site.test", transport, "192.0.2.60:5000").await;
        assert_eq!(response.header.flags & 15, 0);
        assert_eq!(response.answers[0].cname_target.as_deref(), Some("tracker.test"));
        assert_eq!(
            logs,
            vec![("site.test".into(), "allowed".into(), "client_allow:site.test".into())]
        );
        // The allowed client keeps normal filtering for other names.
        let (response, logs) = recorded_from(&state, "tracker.test", transport, "192.0.2.60:5000").await;
        assert_eq!(response.header.flags & 15, 3);
        assert_eq!(logs[0].1, "blocked");
        // Other clients are still blocked for the allowed name.
        let (response, logs) = recorded_from(&state, "site.test", transport, "192.0.2.61:5000").await;
        assert_eq!(response.header.flags & 15, 3);
        assert_eq!(logs[0].2, "block:site.test");
    }
}

#[tokio::test]
async fn client_exception_applies_to_each_cname_target_individually() {
    let server = replies().await;
    let mut rules = Blocklist::new();
    rules
        .block_domains
        .extend(["tracker.test".into(), "last.test".into()]);
    let mut state = state(server.addr, rules);
    let clients = crate::config::ClientsConfig {
        allow: vec![crate::config::ClientAllowConfig {
            sources: vec!["192.0.2.60".into()],
            domains: vec!["tracker.test".into()],
            regex: vec![],
        }],
        ..Default::default()
    };
    state.clients = Arc::new(ClientPolicy::from_config(&clients).unwrap());
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        for (source, name, rcode) in [
            ("192.0.2.60:5000", "alias.test", 0),
            ("192.0.2.61:5000", "alias.test", 3),
            ("192.0.2.60:5000", "chain.test", 3),
        ] {
            let (response, logs) = recorded_from(&state, name, transport, source).await;
            assert_eq!(response.header.flags & 15, rcode);
            if name == "chain.test" {
                assert!(logs[0].2.contains("cname:last.test"));
            }
        }
    }
}

#[tokio::test]
async fn typed_blocks_use_the_question_or_cname_record_type() {
    let server = replies().await;
    let mut rules = Blocklist::new();
    rules.parse_auto("||plain.test^$dnstype=AAAA").unwrap();
    rules.parse_auto("||tracker.test^$dnstype=CNAME").unwrap();
    let state = state(server.addr, rules);
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        for (name, qtype, blocked) in [
            ("plain.test", 1, false),
            ("plain.test", 28, true),
            ("alias.test", 1, true),
        ] {
            let wire = DnsMessage::new_query(17, name, qtype).serialize().unwrap();
            let result = process_query(&wire, &state, transport, LOCAL)
                .await
                .unwrap();
            let msg = DnsMessage::parse(&result.wire).unwrap();
            assert_eq!(msg.header.flags & 15, 0);
            assert_eq!(!matches!(result.outcome, MatchOutcome::Forwarded), blocked);
            if blocked {
                assert!(msg.answers.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn allowed_names_preserve_upstream_errors() {
    let server = replies().await;
    let mut rules = Blocklist::new();
    rules
        .allow_domains
        .extend(["nxdomain.test".into(), "servfail.test".into()]);
    let state = state(server.addr, rules);
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        for (name, rcode) in [("nxdomain.test", 3), ("servfail.test", 2)] {
            let (response, logs) = recorded(&state, name, transport).await;
            assert_eq!(response.header.flags & 15, rcode);
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].1, "allowed");
        }
    }
}

#[tokio::test]
async fn delivery_failure_and_disabled_logging_emit_no_query_entry() {
    let server = replies().await;
    for transport in [ClientTransport::Udp, ClientTransport::Tcp] {
        let mut state = state(server.addr, Blocklist::new());
        let packet = DnsMessage::new_query(1, "plain.test", 1)
            .serialize()
            .unwrap();
        let mut logs = 0;
        let result = handle_request(
            &packet,
            &state,
            transport,
            "127.0.0.1:1000".parse().unwrap(),
            |_| std::future::ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            |_, _, _, _, _| logs += 1,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(logs, 0);
        state.log_queries = false;
        let (_, logs) = recorded(&state, "plain.test", transport).await;
        assert!(logs.is_empty());
    }
}

#[tokio::test]
async fn ambiguous_or_response_shaped_requests_are_rejected_before_filtering() {
    let server = replies().await;
    let state = state(server.addr, Blocklist::new());
    let mut query = DnsMessage::new_query(1, "plain.test", 1);
    query.questions.push(query.questions[0].clone());
    assert!(
        process_query(&query.serialize().unwrap(), &state, ClientTransport::Udp, LOCAL)
            .await
            .is_err()
    );
    query.questions.pop();
    query.header.flags |= 0x8000;
    assert!(
        process_query(&query.serialize().unwrap(), &state, ClientTransport::Tcp, LOCAL)
            .await
            .is_err()
    );
}

#[test]
fn hosts_aliases_and_invalid_rules_do_not_poison_the_remaining_list() {
    let mut rules = Blocklist::new();
    crate::blocklist::parse_lines_into(&mut rules,"0.0.0.0 FIRST.test second.test. # comment\n::1 localhost third.test\n/\n//\n@@/\nfourth.test\nthis is prose\nexample.com##.ad\n","test-source");
    for name in ["first.test", "second.test", "third.test", "fourth.test"] {
        assert!(rules.matches(name), "{name}");
    }
    for name in ["localhost", "prose", "example.com"] {
        assert!(!rules.matches(name), "{name}");
    }
    crate::blocklist::parse_lines_into_allow(
        &mut rules,
        "0.0.0.0 first.test second.test\n",
        "allow-source",
    );
    assert!(!rules.matches("first.test"));
    assert!(!rules.matches("second.test"));
    for line in ["/", "//", "@@/", "@@//", "@@@@/"] {
        assert!(rules.parse_auto(line).is_err());
    }
}

#[test]
fn unsupported_regexes_are_counted_without_broadening_the_rules() {
    let mut rules = Blocklist::new();
    let counts = crate::blocklist::parse_lines_into_regex(
        &mut rules,
        "# comment\n^safe\\.test$ -- allowed\n^(?!bad)skip$\n[invalid\n/\n//\n",
        true,
        "https://list.test/regex",
    );
    assert_eq!(counts.compiled, 1);
    assert_eq!(counts.skipped, 4);
    assert_eq!(rules.allow_regex.len(), 1);
    assert!(matches!(rules.check("safe.test"), MatchOutcome::Allowed(_)));
    assert_eq!(rules.check("skip"), MatchOutcome::Forwarded);
}
