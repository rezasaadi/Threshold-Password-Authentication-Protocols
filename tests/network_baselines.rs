//! Each endpoint and every client invocation is a separate operating-system process.
use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use upspa_unified_benchmark::network::{
    baselines,
    common::{self, Config, Metrics, RunResult},
};

struct Processes(Vec<Child>);
impl Drop for Processes {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn free_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn spawn(scheme: &str, role: &str, id: usize, address: &str, state: &Path, config: &Path) -> Child {
    let ready = state.join("ready");
    if ready.exists() {
        fs::remove_file(&ready).unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_bench_network"))
        .args([
            "service",
            "--scheme",
            scheme,
            "--role",
            role,
            "--id",
            &id.to_string(),
            "--listen",
            address,
            "--state",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "service exited before readiness"
        );
        assert!(Instant::now() < deadline, "service readiness timeout");
        thread::sleep(Duration::from_millis(10));
    }
    child
}
fn client(scheme: &str, phase: &str, state: &Path, config: &Path) -> RunResult {
    let out = state.join("last-result.json");
    let status = Command::new(env!("CARGO_BIN_EXE_bench_network"))
        .args([
            "client",
            "--scheme",
            scheme,
            "--phase",
            phase,
            "--state",
            state.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    serde_json::from_slice(&fs::read(out).unwrap()).unwrap()
}
fn node(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("baseline.json")).unwrap()).unwrap()
}
fn settled_record(path: &Path, old: Option<&Value>) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = node(path);
        if state["record"].as_array().is_some_and(|x| !x.is_empty())
            && old.map_or(true, |old| old != &state["record"])
        {
            return state["record"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "one-way submission was not durably processed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn exercise(scheme: &str) {
    let root = std::env::temp_dir().join(format!(
        "upspa-baseline-{scheme}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let mut cfg = Config::default();
    cfg.n_sp = 3;
    cfg.t_sp = 2;
    cfg.q_sp = 3;
    cfg.providers = (0..3).map(|_| free_address()).collect();
    cfg.login_server = free_address();
    cfg.timeout_ms = 1500;
    let config = root.join("config.json");
    common::atomic_write(&config, &serde_json::to_vec(&cfg).unwrap()).unwrap();
    baselines::provision(scheme, &cfg, &root).unwrap();
    let mut group = Processes(Vec::new());
    for id in 1..=3 {
        group.0.push(spawn(
            scheme,
            "provider",
            id,
            &cfg.providers[id - 1],
            &root.join(format!("provider-{id}")),
            &config,
        ));
    }
    group.0.push(spawn(
        scheme,
        "login",
        0,
        &cfg.login_server,
        &root.join("login"),
        &config,
    ));
    let registration = client(scheme, "registration", &root.join("client"), &config);
    assert_eq!(registration.outcome, "completed", "{:?}", registration.reason);
    assert_eq!(registration.metrics.sent_messages, 3);
    assert_eq!(registration.metrics.received_messages, 0);
    let old: Vec<Value> = (1..=3)
        .map(|id| settled_record(&root.join(format!("provider-{id}")), None))
        .collect();
    // Every provider persists just one global share, and its own account share.
    assert_ne!(
        node(&root.join("provider-1"))["first_share"],
        node(&root.join("provider-2"))["first_share"]
    );
    group.0[0].kill().unwrap();
    group.0[0].wait().unwrap();
    group.0[0] = spawn(
        scheme,
        "provider",
        1,
        &cfg.providers[0],
        &root.join("provider-1"),
        &config,
    );
    let authentication = client(scheme, "authentication", &root.join("client"), &config);
    assert_eq!(authentication.outcome, "completed", "{:?}", authentication.reason);
    assert!(authentication.metrics.sent_bytes > 0 && authentication.metrics.received_bytes > 0);
    assert!(authentication.metrics.end_to_end_ns > authentication.metrics.client_ns);
    let update = client(scheme, "password_update", &root.join("client"), &config);
    assert_eq!(update.outcome, "completed", "{:?}", update.reason);
    for id in 1..=3 {
        settled_record(&root.join(format!("provider-{id}")), Some(&old[id - 1]));
    }
    // Kill providers and verifier after the update, then reload the durable files.
    for index in [0, 3] {
        group.0[index].kill().unwrap();
        group.0[index].wait().unwrap();
    }
    group.0[0] = spawn(
        scheme,
        "provider",
        1,
        &cfg.providers[0],
        &root.join("provider-1"),
        &config,
    );
    group.0[3] = spawn(
        scheme,
        "login",
        0,
        &cfg.login_server,
        &root.join("login"),
        &config,
    );
    let after = client(scheme, "authentication", &root.join("client"), &config);
    assert_eq!(after.outcome, "completed", "{:?}", after.reason);
    // Replaying a cached request after restart must reproduce its exact reply;
    // changed bytes under that same session/stage are rejected.
    let provider = node(&root.join("provider-1"));
    let cache = provider["cache"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, _)| key.ends_with(if scheme == "pastau" { ":token" } else { ":update2" }))
        .unwrap()
        .1;
    let exact: Vec<u8> = serde_json::from_value(cache["request"].clone()).unwrap();
    let mut metrics = Metrics::default();
    let replay = common::request(&cfg.providers[0], &exact, cfg.timeout_ms, &mut metrics).unwrap();
    assert_eq!(replay, cache["reply"]);
    let mut conflict: Value = serde_json::from_slice(&exact).unwrap();
    conflict["data"][0] = json!(conflict["data"][0].as_u64().unwrap() ^ 1);
    let error = common::request(
        &cfg.providers[0],
        &serde_json::to_vec(&conflict).unwrap(),
        cfg.timeout_ms,
        &mut metrics,
    )
    .unwrap_err();
    assert!(error.contains("conflicting reuse"));
    // A separate client process using an incorrect password cannot produce a token.
    let client_path = root.join("client/baseline.json");
    let correct = fs::read(&client_path).unwrap();
    let mut wrong: Value = serde_json::from_slice(&correct).unwrap();
    wrong["password"] = json!(b"wrong password".to_vec());
    common::atomic_write(&client_path, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    let rejected = client(scheme, "authentication", &root.join("client"), &config);
    assert_ne!(rejected.outcome, "completed");
    assert!(rejected.reason.is_some());
    common::atomic_write(&client_path, &correct).unwrap();
    drop(group);
    // Leave process test state as auditable evidence until the caller removes it.
    eprintln!("{scheme} process state: {}", root.display());
}
#[test]
fn pastau_independent_processes_and_restart() {
    exercise("pastau");
}
#[test]
fn augsso_independent_processes_and_restart() {
    exercise("augsso");
}

#[test]
fn preserved_modern_tcp_label_connects_to_external_addresses() {
    let addresses: Vec<String> = (0..3).map(|_| free_address()).collect();
    let mut group = Processes(Vec::new());
    for (index, address) in addresses.iter().enumerate() {
        group.0.push(
            Command::new(env!("CARGO_BIN_EXE_bench_modern_tcp"))
                .args([
                    "--server",
                    "--n",
                    "3",
                    "--t",
                    "2",
                    "--id",
                    &(index + 1).to_string(),
                    "--listen",
                    address,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
    }
    let output = std::env::temp_dir().join(format!("upspa-modern-external-{}.txt", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_bench_modern_tcp"))
        .args([
            "--n",
            "3",
            "--t",
            "2",
            "--providers",
            &addresses.join(","),
            "--warmup",
            "0",
            "--samples",
            "1",
            "--out",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let raw = fs::read_to_string(&output).unwrap();
    assert!(raw.contains("modern exp2 token_generation_tcp"));
    assert!(raw.contains("modern exp2 password_update_tcp"));
}
