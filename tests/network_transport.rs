use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use upspa_unified_benchmark::network::common::{self, Config, Metrics};

fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut payload).unwrap();
    payload
}

fn send_frame(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(&(payload.len() as u32).to_be_bytes()).unwrap();
    stream.write_all(payload).unwrap();
}

#[test]
fn socket_measurements_count_exact_framed_bytes_and_fragmented_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let raw = br#"{"action":"probe"}"#.to_vec();
    let response = serde_json::to_vec(&json!({"body":{"ok":true},"handler_ns":123})).unwrap();
    let sent_len = raw.len() + 4;
    let received_len = response.len() + 4;
    let expected_request = raw.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read_frame(&mut stream), expected_request);
        let frame = [&(response.len() as u32).to_be_bytes()[..], &response].concat();
        for chunk in frame.chunks(3) {
            stream.write_all(chunk).unwrap();
        }
    });
    let mut measured = Metrics::default();
    let reply = common::request(&address, &raw, 1000, &mut measured).unwrap();
    server.join().unwrap();
    assert_eq!(reply, json!({"ok":true}));
    assert_eq!(measured.sent_bytes, sent_len as u64);
    assert_eq!(measured.received_bytes, received_len as u64);
    assert_eq!(measured.sent_messages, 1);
    assert_eq!(measured.received_messages, 1);
    assert_eq!(measured.handler_ns, 123);
    assert!(measured.events.iter().all(|event| event.error.is_none()));
    assert_eq!(
        measured.events.iter().map(|event| event.bytes).sum::<u64>(),
        (sent_len + received_len) as u64
    );
}

#[test]
fn truncated_response_counts_received_prefix_without_completed_message() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_frame(&mut stream);
        stream.write_all(&10_u32.to_be_bytes()).unwrap();
        stream.write_all(b"xy").unwrap();
    });
    let mut measured = Metrics::default();
    assert!(common::request(&address, b"{}", 1000, &mut measured).is_err());
    server.join().unwrap();
    assert_eq!(measured.sent_bytes, 6);
    assert_eq!(measured.received_bytes, 6);
    assert_eq!(measured.sent_messages, 1);
    assert_eq!(measured.received_messages, 0);
    assert!(measured.events.last().unwrap().error.is_some());
}

#[test]
fn oversized_response_header_is_measured_and_rejected_before_allocation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_frame(&mut stream);
        stream
            .write_all(&(16_u32 * 1024 * 1024 + 1).to_be_bytes())
            .unwrap();
    });
    let mut measured = Metrics::default();
    let error = common::request(&address, b"{}", 1000, &mut measured).unwrap_err();
    server.join().unwrap();
    assert!(error.contains("frame exceeds limit"));
    assert_eq!(measured.received_bytes, 4);
    assert_eq!(measured.received_messages, 0);
}

#[test]
fn completed_error_reply_is_counted_as_actual_network_traffic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let reply = serde_json::to_vec(&json!({"error":"rejected","handler_ns":9})).unwrap();
    let reply_len = reply.len() + 4;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_frame(&mut stream);
        send_frame(&mut stream, &reply);
    });
    let mut measured = Metrics::default();
    assert_eq!(
        common::request(&address, b"{}", 1000, &mut measured),
        Err("rejected".into())
    );
    server.join().unwrap();
    assert_eq!(measured.received_bytes, reply_len as u64);
    assert_eq!(measured.received_messages, 1);
    assert_eq!(measured.handler_ns, 9);
}

#[test]
fn one_way_send_does_not_wait_for_or_count_an_application_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read_frame(&mut stream), b"terminal");
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    let mut measured = Metrics::default();
    common::one_way(&address, b"terminal", 1000, &mut measured).unwrap();
    server.join().unwrap();
    assert_eq!(measured.sent_bytes, 12);
    assert_eq!(measured.sent_messages, 1);
    assert_eq!(measured.received_bytes, 0);
    assert_eq!(measured.received_messages, 0);
}

struct LoginProcess {
    child: Child,
    root: PathBuf,
    address: String,
}
impl Drop for LoginProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn login_process() -> LoginProcess {
    login_process_with_fault(None)
}
fn login_process_with_fault(fault: Option<(&str, &str)>) -> LoginProcess {
    let root = std::env::temp_dir().join(format!(
        "upspa-transport-test-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let config_path = root.join("config.json");
    fs::write(&config_path, serde_json::to_vec(&Config::default()).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_bench_network"));
    command
        .args([
            "service", "--scheme", "roupspa", "--role", "login", "--id", "0", "--listen", &address,
        ])
        .arg("--config")
        .arg(&config_path)
        .arg("--state")
        .arg(root.join("login"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some((variable, stage)) = fault {
        command.env(variable, stage);
    }
    let child = command.spawn().unwrap();
    let mut service = LoginProcess { child, root, address };
    let start = Instant::now();
    while !service.root.join("login/ready").exists() {
        assert!(
            service.child.try_wait().unwrap().is_none(),
            "login service failed to start"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "login service readiness deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    service
}

#[test]
fn rejected_terminal_stays_one_way_and_has_independent_failure_evidence() {
    let service = login_process();
    let terminal = json!({
        "action":"ls_store", "session":"aa".repeat(32), "uid":b"user123",
        "old_vinfo":null, "new_vinfo":vec![4_u8;32]
    });
    let mut stream = TcpStream::connect(&service.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send_frame(&mut stream, &serde_json::to_vec(&terminal).unwrap());
    let mut byte = [0; 1];
    assert_eq!(
        stream.read(&mut byte).unwrap(),
        0,
        "terminal rejection must not add a reply"
    );
    let lines = fs::read_to_string(service.root.join("login/endpoint.jsonl")).unwrap();
    let evidence = lines
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    assert!(evidence.iter().any(|event| event["processed"] == false
        && (event["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Prepare"))
            || event["error"]
                .as_str()
                .is_some_and(|reason| reason.contains("Prepare")))));
    assert!(
        !service.root.join("login/roupspa-events.json").exists(),
        "rejected Store must not become durable state"
    );
}

#[test]
fn malformed_terminal_has_no_error_response() {
    let service = login_process();
    let terminal = json!({"action":"ls_store", "session":"aa".repeat(32)});
    let mut stream = TcpStream::connect(&service.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send_frame(&mut stream, &serde_json::to_vec(&terminal).unwrap());
    let mut byte = [0; 1];
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    assert!(!service.root.join("login/roupspa-events.json").exists());
}

#[test]
fn suppressing_a_whole_action_does_not_durably_run_its_handler() {
    let service = login_process_with_fault(Some(("BENCH_SUPPRESS_STAGE", "ls_prepare")));
    let prepare = json!({
        "action":"ls_prepare", "session":"bb".repeat(32), "uid":b"user123",
        "old_vinfo":null, "new_vinfo":vec![5_u8;32]
    });
    let mut measured = Metrics::default();
    assert!(common::request(
        &service.address,
        &serde_json::to_vec(&prepare).unwrap(),
        1000,
        &mut measured
    )
    .is_err());
    assert_eq!(measured.sent_messages, 1);
    assert_eq!(measured.received_messages, 0);
    assert!(!service.root.join("login/roupspa-events.json").exists());
    let lines = fs::read_to_string(service.root.join("login/endpoint.jsonl")).unwrap();
    assert!(lines
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|event| event["transport"] == true
            && event["suppressed"] == true
            && event["stage"] == "ls_prepare"
            && event["metrics"]["received_messages"] == 1
            && event["metrics"]["sent_messages"] == 0));
}

#[test]
fn endpoint_transport_log_includes_its_actual_reply_bytes() {
    let service = login_process();
    let prepare = json!({
        "action":"ls_prepare", "session":"cc".repeat(32), "uid":b"user123",
        "old_vinfo":null, "new_vinfo":vec![6_u8;32]
    });
    let mut measured = Metrics::default();
    let reply = common::request(
        &service.address,
        &serde_json::to_vec(&prepare).unwrap(),
        1000,
        &mut measured,
    )
    .unwrap();
    assert_eq!(reply["ok"], true);
    let deadline = Instant::now() + Duration::from_secs(2);
    let transport = loop {
        let lines = fs::read_to_string(service.root.join("login/endpoint.jsonl")).unwrap();
        if let Some(value) = lines
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|event| event["transport"] == true && event["stage"] == "ls_prepare")
        {
            break value;
        }
        assert!(Instant::now() < deadline, "endpoint transport row missing");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(transport["metrics"]["sent_bytes"], measured.received_bytes);
    assert_eq!(transport["metrics"]["received_bytes"], measured.sent_bytes);
    assert_eq!(transport["metrics"]["sent_messages"], 1);
    assert_eq!(transport["metrics"]["received_messages"], 1);
}
