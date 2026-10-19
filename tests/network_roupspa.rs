//! Process-level socket tests. These do not claim netem or namespace timings.
use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use upspa_unified_benchmark::network::common::{self, Config, Metrics, RunResult};

struct Deployment {
    root: PathBuf,
    config: Config,
    path: PathBuf,
    providers: Vec<Option<Child>>,
    login: Option<Child>,
    counter: usize,
}
impl Deployment {
    fn new(n: usize, t: usize, q: usize) -> Self {
        Self::with_suppression(n, t, q, &[])
    }
    fn with_suppression(n: usize, t: usize, q: usize, ids: &[usize]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "roupspa-process-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let listeners = (0..=n)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let addresses = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().to_string())
            .collect::<Vec<_>>();
        let mut config = Config::default();
        config.n_sp = n;
        config.t_sp = t;
        config.q_sp = q;
        config.providers = addresses[..n].to_vec();
        config.login_server = addresses[n].clone();
        config.schemes = vec!["roupspa".into()];
        config.delta_ms = 10;
        // Process startup and durable writes are slower under concurrent Windows tests.
        config.timeout_ms = if cfg!(windows) { 2000 } else { 300 };
        config.retry_ms = 5;
        config.warmups = 0;
        config.samples = 1;
        let path = root.join("config.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        drop(listeners);
        let mut d = Self {
            root,
            config,
            path,
            providers: (0..n).map(|_| None).collect(),
            login: None,
            counter: 0,
        };
        for i in 0..n {
            d.start_provider(
                i,
                if ids.contains(&i) {
                    Some(("BENCH_SUPPRESS_STAGE", "id_write"))
                } else {
                    None
                },
            );
        }
        d.start_login(None);
        d
    }
    fn spawn(&self, role: &str, id: usize, address: &str, env: Option<(&str, &str)>) -> Child {
        let state = self.root.join(if role == "login" {
            "login".into()
        } else {
            format!("provider-{}", id)
        });
        fs::create_dir_all(&state).unwrap();
        let ready = state.join("ready");
        let _ = fs::remove_file(&ready);
        let mut c = Command::new(env!("CARGO_BIN_EXE_bench_network"));
        c.args([
            "service",
            "--scheme",
            "roupspa",
            "--role",
            role,
            "--id",
            &id.to_string(),
            "--listen",
            address,
        ]);
        c.arg("--state")
            .arg(&state)
            .arg("--config")
            .arg(&self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(fs::File::create(state.join("stderr.log")).unwrap()));
        if let Some((k, v)) = env {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "service exited during start: {}",
                fs::read_to_string(state.join("stderr.log")).unwrap_or_default()
            );
            assert!(Instant::now() < end, "service start timed out");
            thread::sleep(Duration::from_millis(5));
        }
        child
    }
    fn start_provider(&mut self, i: usize, env: Option<(&str, &str)>) {
        self.providers[i] = Some(self.spawn("provider", i + 1, &self.config.providers[i], env));
    }
    fn start_login(&mut self, env: Option<(&str, &str)>) {
        self.login = Some(self.spawn("login", 0, &self.config.login_server, env));
    }
    fn stop_provider(&mut self, i: usize) {
        if let Some(mut p) = self.providers[i].take() {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
    fn stop_login(&mut self) {
        if let Some(mut p) = self.login.take() {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
    fn client(&mut self, phase: &str) -> RunResult {
        self.client_env(phase, None).expect("client emitted no result")
    }
    fn client_env(&mut self, phase: &str, env: Option<(&str, &str)>) -> Option<RunResult> {
        self.counter += 1;
        let output = self.root.join(format!("result-{}.json", self.counter));
        let mut c = Command::new(env!("CARGO_BIN_EXE_bench_network"));
        c.args(["client", "--scheme", "roupspa", "--phase", phase]);
        c.arg("--state")
            .arg(self.root.join("client"))
            .arg("--config")
            .arg(&self.path)
            .arg("--output")
            .arg(&output);
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        if let Some((k, v)) = env {
            c.env(k, v);
        }
        let status = c.status().unwrap();
        if !status.success() {
            return None;
        }
        let r: RunResult = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert!(matches!(
            r.outcome.as_str(),
            "completed" | "cleanly_aborted" | "unresolved" | "failed"
        ));
        Some(r)
    }
    fn set_config(&mut self, change: impl FnOnce(&mut Config)) {
        change(&mut self.config);
        fs::write(&self.path, serde_json::to_vec(&self.config).unwrap()).unwrap();
    }
    fn complete(&mut self, phase: &str) {
        let r = self.client(phase);
        assert_eq!(r.outcome, "completed", "{phase}: {:?}", r.reason);
    }
    fn journal(&self, i: usize) -> Vec<Value> {
        serde_json::from_slice(
            &fs::read(self.root.join(format!("provider-{}/roupspa-events.json", i + 1))).unwrap(),
        )
        .unwrap()
    }
    fn client_state(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("client/roupspa-client.json")).unwrap()).unwrap()
    }
    fn repair(&self, i: usize) -> Result<Value, String> {
        let raw =
            serde_json::to_vec(&json!({"action":"synchronize","uid":b"user123","scope":"identification"}))
                .unwrap();
        common::request(
            &self.config.providers[i],
            &raw,
            self.config.timeout_ms * 4,
            &mut Metrics::default(),
        )
    }
    fn wait_dead_provider(&mut self, i: usize) {
        let end = Instant::now() + Duration::from_secs(3);
        while self.providers[i].as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait_dead_login(&mut self) {
        let end = Instant::now() + Duration::from_secs(3);
        while self.login.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Deployment {
    fn drop(&mut self) {
        for i in 0..self.providers.len() {
            self.stop_provider(i);
        }
        self.stop_login();
    }
}

#[test]
fn healthy_real_processes_persistence_restart_and_threshold() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    d.complete("registration");
    assert_eq!(
        (0..4)
            .filter(|&i| d.journal(i).iter().any(|v| v["action"] == "registration_write"))
            .count(),
        4,
        "q+1 actual providers received the concurrent direct write"
    );
    let auth = d.client("authentication");
    assert_eq!(auth.outcome, "completed");
    assert!(auth.metrics.sent_bytes > 0 && auth.metrics.received_bytes > 0 && auth.metrics.handler_ns > 0);
    assert!(auth.metrics.client_ns < auth.metrics.end_to_end_ns);
    d.complete("secret_update");
    d.complete("password_update");
    d.complete("authentication");
    assert!(d.client_state()["pending"].is_null());
    d.stop_login();
    d.start_login(None);
    d.complete("authentication");
    // Only the acknowledgement set receives Store. Choose an endpoint with
    // locally processed terminal evidence for this successful restart case.
    let last: Value =
        serde_json::from_slice(&fs::read(d.root.join("client/roupspa-last-session.json")).unwrap()).unwrap();
    let restarted = last["acknowledged"][0].as_u64().unwrap() as usize;
    let share = d.journal(restarted)[0]["share"].clone();
    d.stop_provider(restarted);
    d.start_provider(restarted, None);
    let repair = d.repair(restarted).unwrap();
    assert_eq!(repair["ok"], true);
    assert_eq!(share, d.journal(restarted)[0]["share"]);
    // The restarted provider's account remains stale: no justified account
    // completion proof is available. Reads wait for r = n - q + t = 3 replies,
    // so keep the three providers that never restarted.
    d.stop_provider(restarted);
    d.complete("authentication");
    d.stop_provider((restarted + 1) % 4);
    let r = d.client("authentication");
    assert_eq!(r.outcome, "failed");
    assert!(r.reason.unwrap().contains("required 3"));
}

#[test]
fn reads_wait_for_r_and_tolerate_invalid_toprf_contributions() {
    // (n,t,q) = (5,2,4): r = n - q + t = 3.
    let mut d = Deployment::new(5, 2, 4);
    // Allow concurrent process tests time to finish cryptography on Windows.
    d.set_config(|c| c.timeout_ms = 1500);
    d.complete("setup");
    d.complete("registration");
    let auth = d.client("authentication");
    assert_eq!(auth.outcome, "completed", "{:?}", auth.reason);
    assert_eq!(auth.metrics.read_replies_required, 3);
    assert_eq!(auth.metrics.toprf_subsets_tried, 1);
    // Minimal fan-out contacts providers 1..r first, so provider 1 is always
    // among the responders below (deterministic test).
    d.set_config(|c| c.fanout = "minimal".into());
    d.complete("authentication");
    // One corrupted provider (t - 1 = 1) returns a wrong TOPRF contribution.
    d.stop_provider(0);
    d.start_provider(0, Some(("BENCH_CORRUPT_PARTIAL", "*")));
    d.repair(0).unwrap();
    // Responders 1-3 are contacted; the first two replies (arrival order) are
    // combined first, so provider 1 is among them in about 2 of 3 runs.
    let mut retried = false;
    for _ in 0..8 {
        let auth = d.client("authentication");
        assert_eq!(auth.outcome, "completed", "{:?}", auth.reason);
        retried |= auth.metrics.toprf_subsets_tried > 1;
    }
    assert!(retried, "subset retry was never exercised");
    // The new-password evaluation has nothing to decrypt; the batch check
    // detects the bad contribution and stops the update before any write.
    let pu = d.client("password_update");
    assert_eq!(pu.outcome, "cleanly_aborted", "{:?}", pu.reason);
    assert!(pu.reason.unwrap().contains("inconsistent"));
    assert_eq!(pu.metrics.toprf_consistency_checks, 1);
    assert!(d.client_state()["pending"].is_null());
    assert!((0..5).all(|i| d.journal(i).iter().all(|v| v["action"] != "id_write")));
    d.complete("authentication");
    // Three stopped providers leave 2 < r responders: reads fail before writing.
    d.stop_provider(2);
    d.stop_provider(3);
    d.stop_provider(4);
    let r = d.client("authentication");
    assert_eq!(r.outcome, "failed");
    assert!(r.metrics.fanout_extensions >= 1);
}

#[test]
fn password_update_quorum_failure_is_discarded_and_counter_reused() {
    // (n,t,q) = (5,2,4), r = 3. Providers 4 and 5 never acknowledge id_write
    // (3 < q). After they restart, their account replicas stay stale (account
    // synchronization gap), and the three others still serve r = 3 reads.
    let mut d = Deployment::with_suppression(5, 2, 4, &[3, 4]);
    d.complete("setup");
    d.complete("registration");
    let pu = d.client("password_update");
    assert_eq!(pu.outcome, "cleanly_aborted", "{:?}", pu.reason);
    assert_eq!(pu.metrics.discards, 1);
    assert!(d.client_state()["pending"].is_null());
    for i in 0..3 {
        let j = d.journal(i);
        assert!(j
            .iter()
            .any(|v| v["action"] == "id_write" && v["session"] == pu.session.as_str()));
        assert!(j
            .iter()
            .any(|v| v["action"] == "id_discard" && v["session"] == pu.session.as_str()));
    }
    // The old password still works.
    d.complete("authentication");
    // Explicit Discard after transmission is allowed for Password Update only.
    assert_eq!(d.client("password_update_write_once").outcome, "unresolved");
    assert_eq!(d.client("discard").outcome, "cleanly_aborted");
    d.complete("authentication");
    // With all providers acknowledging, the same counter is reused.
    for i in [3, 4] {
        d.stop_provider(i);
        d.start_provider(i, None);
        d.repair(i).unwrap();
    }
    d.complete("password_update");
    d.complete("authentication");
}

#[test]
fn password_update_discard_decision_survives_client_crash() {
    // Exercise both automatic quorum-failure Discard and an explicit Discard
    // after all tentative writes. Resuming must not change that decision even
    // after providers that previously suppressed writes become available.
    for automatic in [true, false] {
        for point in ["BEFORE", "AFTER"] {
            let mut d = if automatic {
                Deployment::with_suppression(5, 2, 4, &[3, 4])
            } else {
                Deployment::new(5, 2, 4)
            };
            d.complete("setup");
            d.complete("registration");
            let old_password = d.client_state()["password"].clone();
            let phase = if automatic {
                "password_update"
            } else {
                assert_eq!(d.client("password_update_write_once").outcome, "unresolved");
                "discard"
            };
            let variable = format!("BENCH_CLIENT_CRASH_{point}_STAGE");
            assert!(d.client_env(phase, Some((&variable, "discard"))).is_none());
            let pending = d.client_state()["pending"].clone();
            assert_eq!(pending["discard_decided"], true);
            assert_eq!(pending["terminal_started"], true);
            let sid = pending["id"].as_str().unwrap().to_owned();
            let holders = (0..5)
                .filter(|&i| {
                    d.journal(i)
                        .iter()
                        .any(|v| v["action"] == "id_write" && v["session"] == sid)
                })
                .collect::<Vec<_>>();
            assert!(!holders.is_empty());
            if point == "AFTER" {
                for &i in &holders {
                    assert!(d
                        .journal(i)
                        .iter()
                        .any(|v| v["action"] == "id_discard" && v["session"] == sid));
                }
            }
            if automatic {
                for i in [3, 4] {
                    d.stop_provider(i);
                    d.start_provider(i, None);
                    d.repair(i).unwrap();
                }
            }
            let resumed = d.client("resume");
            assert_eq!(resumed.outcome, "cleanly_aborted", "{:?}", resumed.reason);
            assert_eq!(resumed.session, sid);
            assert_eq!(resumed.metrics.discards, 1);
            assert!(d.client_state()["pending"].is_null());
            assert_eq!(d.client_state()["password"], old_password);
            for i in 0..5 {
                let events = d.journal(i);
                assert!(!events
                    .iter()
                    .any(|v| v["action"] == "id_store" && v["session"] == sid));
                if holders.contains(&i) {
                    assert!(events
                        .iter()
                        .any(|v| v["action"] == "id_discard" && v["session"] == sid));
                }
            }
            d.complete("authentication");
            // Discard also releases the counter for a fresh session.
            d.complete("password_update");
            d.complete("authentication");
        }
    }
}

#[test]
fn login_server_discard_decision_survives_client_crash() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    assert_eq!(d.client("registration_prepare_only").outcome, "unresolved");
    assert!(d
        .client_env("discard", Some(("BENCH_CLIENT_CRASH_AFTER_STAGE", "discard")))
        .is_none());
    let pending = d.client_state()["pending"].clone();
    assert_eq!(pending["discard_decided"], true);
    let sid = pending["id"].as_str().unwrap();
    let resumed = d.client("resume");
    assert_eq!(resumed.outcome, "cleanly_aborted", "{:?}", resumed.reason);
    let events: Vec<Value> =
        serde_json::from_slice(&fs::read(d.root.join("login/roupspa-events.json")).unwrap()).unwrap();
    assert!(events
        .iter()
        .any(|v| v["action"] == "ls_discard" && v["session"] == sid));
    assert!(!events
        .iter()
        .any(|v| v["action"] == "ls_store" && v["session"] == sid));
    for i in 0..4 {
        assert!(!d
            .journal(i)
            .iter()
            .any(|v| v["action"] == "registration_write" && v["session"] == sid));
    }
    d.complete("registration");
    d.complete("authentication");
}

#[test]
fn clean_prewrite_discard_and_exact_resume_at_quorum_boundary() {
    // (n,t,q) = (5,2,4), r = 3. Providers 4 and 5 do not acknowledge id_write
    // until restarted, so the Password Update below stops with 3 < q
    // acknowledgements while reads still succeed. After their restart their
    // account replicas stay stale, and providers 1-3 still serve r = 3 reads.
    let mut d = Deployment::with_suppression(5, 2, 4, &[3, 4]);
    d.complete("setup");
    assert_eq!(d.client("registration_prepare_only").outcome, "unresolved");
    for i in 0..5 {
        assert!(!d.journal(i).iter().any(|v| v["action"] == "registration_write"));
    }
    assert_eq!(d.client("discard").outcome, "cleanly_aborted");
    d.complete("registration");
    assert_eq!(d.client("secret_update_prepare_only").outcome, "unresolved");
    assert_eq!(d.client("discard").outcome, "cleanly_aborted");
    d.complete("authentication");
    let r = d.client("password_update_write_once");
    assert_eq!(r.outcome, "unresolved");
    let old = d.client_state();
    let raw = old["pending"]["write"][0].clone();
    let sid = old["pending"]["id"].clone();
    // (A Password Update may also be discarded here; see
    // password_update_quorum_failure_is_discarded_and_counter_reused.)
    for i in [3, 4] {
        d.stop_provider(i);
        d.start_provider(i, None);
        d.repair(i).unwrap();
    }
    let resumed = d.client("resume");
    assert_eq!(resumed.outcome, "completed", "{:?}", resumed.reason);
    assert_eq!(resumed.session, sid.as_str().unwrap());
    let exact: Vec<u8> = serde_json::from_value(raw).unwrap();
    let request: Value = serde_json::from_slice(&exact).unwrap();
    for i in 0..5 {
        for e in d
            .journal(i)
            .iter()
            .filter(|e| e["action"] == "id_write" && e["session"] == sid)
        {
            assert_eq!(e, &request);
        }
    }
    let mut metrics = Metrics::default();
    assert_eq!(
        common::request(&d.config.providers[0], &exact, 300, &mut metrics).unwrap()["ok"],
        true
    );
    let mut conflict = request.clone();
    conflict["record"]["ctrid"] = json!(2);
    assert!(common::request(
        &d.config.providers[0],
        &serde_json::to_vec(&conflict).unwrap(),
        300,
        &mut metrics
    )
    .is_err());
    let mut replay = request;
    replay["session"] = json!("55".repeat(32));
    assert!(common::request(
        &d.config.providers[0],
        &serde_json::to_vec(&replay).unwrap(),
        300,
        &mut metrics
    )
    .is_err());
    replay["session"] = json!("66".repeat(32));
    replay["record"]["ctrid"] = json!(2);
    assert!(common::request(
        &d.config.providers[0],
        &serde_json::to_vec(&replay).unwrap(),
        300,
        &mut metrics
    )
    .unwrap_err()
    .contains("InvalidSignature"));
    d.complete("authentication");
    let last: Value =
        serde_json::from_slice(&fs::read(d.root.join("client/roupspa-last-session.json")).unwrap()).unwrap();
    let retried = d.client("retry_terminal");
    assert_eq!(retried.outcome, "completed");
    assert_eq!(retried.session, last["id"].as_str().unwrap());
    d.complete("authentication");
}

#[test]
fn provider_and_login_crashes_before_and_after_durable_transition() {
    for point in ["BEFORE", "AFTER"] {
        let mut d = Deployment::new(4, 2, 3);
        d.complete("setup");
        d.stop_login();
        let variable = format!("BENCH_CRASH_{point}_STAGE");
        d.start_login(Some((&variable, "ls_prepare")));
        let r = d.client("registration");
        assert_eq!(r.outcome, "unresolved");
        d.wait_dead_login();
        let journal = d.root.join("login/roupspa-events.json");
        assert_eq!(journal.exists(), point == "AFTER");
        let raw = d.client_state()["pending"]["prepare"].clone();
        d.stop_login();
        d.start_login(None);
        d.complete("resume");
        let events: Vec<Value> = serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
        let prep: Vec<u8> = serde_json::from_value(raw).unwrap();
        let prep: Value = serde_json::from_slice(&prep).unwrap();
        assert_eq!(events[0], prep);
        d.complete("authentication");
        d.stop_provider(0);
        d.start_provider(0, Some((&variable, "id_write")));
        d.repair(0).unwrap();
        d.complete("password_update");
        d.wait_dead_provider(0);
        let wrote = d.journal(0).iter().any(|v| v["action"] == "id_write");
        assert_eq!(wrote, point == "AFTER");
        d.stop_provider(0);
        d.start_provider(0, None);
        let error = d.repair(0).unwrap_err();
        assert!(error.contains("lacks locally processed Store"), "{error}");
        d.complete("authentication");
    }
}

#[test]
fn client_crashes_preserve_exact_unfinished_session() {
    for (point, stage) in ["BEFORE", "AFTER"].into_iter().flat_map(|p| {
        ["ls_prepare", "provider_write", "terminal"]
            .into_iter()
            .map(move |s| (p, s))
    }) {
        let mut d = Deployment::new(4, 2, 3);
        d.complete("setup");
        let variable = format!("BENCH_CLIENT_CRASH_{point}_STAGE");
        assert!(d.client_env("registration", Some((&variable, stage))).is_none());
        let pending = d.client_state()["pending"].clone();
        assert!(!pending.is_null());
        let result = d.client("resume");
        assert_eq!(result.outcome, "completed", "{stage}: {:?}", result.reason);
        assert_eq!(result.session, pending["id"].as_str().unwrap());
        d.complete("authentication");
    }
}

#[test]
fn terminal_endpoint_crashes_and_identical_redelivery() {
    for point in ["BEFORE", "AFTER"] {
        let variable = format!("BENCH_CRASH_{point}_STAGE");
        let mut d = Deployment::new(4, 2, 3);
        d.complete("setup");
        d.stop_login();
        d.start_login(Some((&variable, "ls_store")));
        let _attempt = d.client("registration");
        d.wait_dead_login();
        let events: Vec<Value> =
            serde_json::from_slice(&fs::read(d.root.join("login/roupspa-events.json")).unwrap()).unwrap();
        assert_eq!(events.iter().any(|v| v["action"] == "ls_store"), point == "AFTER");
        d.stop_login();
        d.start_login(None);
        d.complete("retry_terminal");
        d.complete("authentication");

        assert_eq!(d.client("password_update_write_once").outcome, "unresolved");
        let pending = d.client_state()["pending"].clone();
        let target = pending["acknowledged"][0].as_u64().unwrap() as usize;
        let share = d.journal(target)[0]["share"].clone();
        d.stop_provider(target);
        d.start_provider(target, Some((&variable, "id_store")));
        let _attempt = d.client("resume");
        d.wait_dead_provider(target);
        assert_eq!(
            d.journal(target).iter().any(|v| v["action"] == "id_store"),
            point == "AFTER"
        );
        d.stop_provider(target);
        d.start_provider(target, None);
        d.complete("retry_terminal");
        assert_eq!(share, d.journal(target)[0]["share"]);
        d.complete("authentication");
    }
}

#[test]
fn synchronization_requires_q_other_responses_and_does_not_assert_account_completion() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    d.complete("registration");
    d.stop_provider(0);
    d.start_provider(0, None);
    d.stop_provider(3);
    let repair_error = d.repair(0).unwrap_err();
    assert!(repair_error.contains("required 3"), "{repair_error}");
    d.start_provider(3, None);
    d.repair(0).unwrap();
    let account = d
        .journal(1)
        .into_iter()
        .find(|v| v["action"] == "registration_write")
        .unwrap();
    let raw = serde_json::to_vec(
        &json!({"action":"synchronize","uid":b"user123","suid":account["record"]["suid"]}),
    )
    .unwrap();
    let error = common::request(&d.config.providers[0], &raw, 300, &mut Metrics::default()).unwrap_err();
    assert!(error.contains("do not prove login-server Store"), "{error}");
    let generic = d.client("synchronization");
    assert_eq!(generic.outcome, "unresolved", "{:?}", generic.reason);
    assert!(generic.reason.unwrap().contains("PROTOCOL GAP"));
    let injected = serde_json::to_vec(&json!({"action":"restart_stale"})).unwrap();
    assert!(
        common::request(&d.config.providers[0], &injected, 300, &mut Metrics::default())
            .unwrap_err()
            .contains("not permitted")
    );
}

#[test]
fn missed_whole_message_old_password_gap_needs_threshold_reads() {
    // A t-only read need not intersect the write quorum; r = n - q + t does.
    for policy in ["threshold", "quorum"] {
        let mut d = Deployment::with_suppression(7, 2, 5, &[5, 6]);
        d.complete("setup");
        d.complete("registration");
        let old_state = d.client_state();
        d.complete("password_update");
        // Use the selected policy only for the read: a new Password Update
        // now refuses an uncheckable threshold-only new-password evaluation.
        d.set_config(|c| c.read_policy = policy.into());
        for i in 0..5 {
            d.stop_provider(i);
        }
        fs::write(
            d.root.join("client/roupspa-client.json"),
            serde_json::to_vec(&old_state).unwrap(),
        )
        .unwrap();
        let r = d.client("authentication");
        if policy == "threshold" {
            assert_eq!(
                r.outcome, "completed",
                "legacy t-reads expose the old-password gap: {:?}",
                r.reason
            );
        } else {
            // r = 4 replies cannot be collected from the two stale providers.
            assert_eq!(r.outcome, "failed", "{:?}", r.reason);
        }
        assert!(d.journal(5).iter().all(|e| e["action"] != "id_write"));
        assert!(d.journal(6).iter().all(|e| e["action"] != "id_write"));
    }
}

#[test]
fn signed_direct_write_is_not_a_completed_account_and_all_provider_quorum_cannot_repair() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    let before = d.client("registration_write_once");
    assert_eq!(before.outcome, "unresolved");
    let account = d
        .journal(0)
        .into_iter()
        .find(|v| v["action"] == "registration_write")
        .unwrap();
    let events: Vec<Value> =
        serde_json::from_slice(&fs::read(d.root.join("login/roupspa-events.json")).unwrap()).unwrap();
    assert!(events.iter().any(|v| v["action"] == "ls_prepare"));
    assert!(!events.iter().any(|v| v["action"] == "ls_store"));
    // A recovering endpoint can verify q signatures even before Store. The
    // diagnostic path must not turn that evidence into an active account.
    d.stop_provider(0);
    d.start_provider(0, None);
    let evidence = serde_json::to_vec(&json!({"action":"account_sync_evidence","uid":b"user123",
        "suid":account["record"]["suid"]}))
    .unwrap();
    let evidence = common::request(&d.config.providers[0], &evidence, 300, &mut Metrics::default()).unwrap();
    assert_eq!(evidence["proves_completion"], false);
    assert_eq!(evidence["active"], false);
    assert_eq!(evidence["record"], account["record"]);
    let read = serde_json::to_vec(&json!({"action":"account_read","uid":b"user123",
        "suid":account["record"]["suid"]}))
    .unwrap();
    assert!(
        common::request(&d.config.providers[0], &read, 300, &mut Metrics::default())
            .unwrap_err()
            .contains("Stale")
    );
    let raw = serde_json::to_vec(
        &json!({"action":"synchronize","uid":b"user123","suid":account["record"]["suid"]}),
    )
    .unwrap();
    assert!(
        common::request(&d.config.providers[0], &raw, 300, &mut Metrics::default())
            .unwrap_err()
            .contains("PROTOCOL GAP")
    );
    d.complete("resume");
    d.complete("authentication");

    let mut all = Deployment::new(3, 1, 3);
    all.complete("setup");
    all.stop_provider(0);
    all.start_provider(0, None);
    assert!(all.repair(0).unwrap_err().contains("required 3"));
    assert!(all.journal(0).iter().all(|v| v["action"] != "sync_id_install"));
}

#[test]
fn password_update_aborts_when_consistency_has_too_few_honest_constraints() {
    for (n, t, q, policy) in [(3, 2, 3, "quorum"), (4, 2, 3, "threshold")] {
        let mut d = Deployment::new(n, t, q);
        d.set_config(|c| c.read_policy = policy.into());
        d.complete("setup");
        d.complete("registration");
        let before = d.client_state();
        let result = d.client("password_update");
        assert_eq!(result.outcome, "cleanly_aborted", "{:?}", result.reason);
        assert!(result.reason.unwrap().contains("2*t_sp-1=3"));
        assert_eq!(result.metrics.toprf_consistency_checks, 0);
        assert_eq!(d.client_state(), before);
        assert!((0..n).all(|i| d.journal(i).iter().all(|e| e["action"] != "id_write")));
        d.complete("authentication");
    }
}

#[test]
fn repeated_fixed_password_update_is_a_no_write_abort() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    d.complete("registration");
    d.complete("password_update");
    let before = d.client_state();
    let journals = (0..4).map(|i| d.journal(i)).collect::<Vec<_>>();
    let repeated = d.client("password_update");
    assert_eq!(repeated.outcome, "cleanly_aborted", "{:?}", repeated.reason);
    assert!(repeated.reason.unwrap().contains("equals the current password"));
    assert_eq!(d.client_state(), before);
    for (i, previous) in journals.iter().enumerate() {
        assert_eq!(&d.journal(i), previous);
    }
    d.complete("authentication");
}

#[test]
fn synchronization_does_not_bypass_an_unfinished_client_session() {
    let mut d = Deployment::new(4, 2, 3);
    d.complete("setup");
    assert_eq!(d.client("registration_write_once").outcome, "unresolved");
    let pending = d.client_state();
    let sync = d.client("synchronization");
    assert_eq!(sync.outcome, "unresolved");
    assert!(sync
        .reason
        .unwrap()
        .contains("unresolved session blocks synchronization"));
    assert_eq!(d.client_state(), pending);
    d.complete("resume");
    d.complete("authentication");
}
