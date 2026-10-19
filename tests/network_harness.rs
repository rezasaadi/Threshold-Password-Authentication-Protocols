use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use upspa_unified_benchmark::network::{
    common::{self, Config, Fault, Profile},
    harness::Record,
};

fn free_address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn config(label: &str) -> (Config, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "upspa-harness-{label}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let mut c = Config::default();
    c.n_sp = 4;
    c.t_sp = 2;
    c.q_sp = 3;
    c.providers = (0..4).map(|_| free_address()).collect();
    c.login_server = free_address();
    c.profiles = vec![Profile {
        name: "socket-correctness".into(),
        delay_ms: 0.0,
        jitter_ms: 0.0,
        bandwidth_mbps: 100.0,
        loss_percent: 0.0,
    }];
    c.samples = 1;
    c.warmups = 0;
    c.repetitions = 1;
    c.delta_ms = 20;
    c.timeout_ms = 800;
    c.output_dir = root.join("results");
    (c, root)
}
fn run(c: &Config, root: &std::path::Path, command: &str) -> (PathBuf, Vec<Record>, Value) {
    let path = root.join("config.json");
    common::atomic_write(&path, &serde_json::to_vec(c).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bench_network"))
        .args([command, "--config", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let folder = PathBuf::from(text.lines().last().unwrap());
    let raw = fs::read_to_string(folder.join("raw.jsonl")).unwrap();
    let rows = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary = serde_json::from_slice(&fs::read(folder.join("summary.json")).unwrap()).unwrap();
    (folder, rows, summary)
}

#[test]
fn healthy_harness_executes_actual_password_update_for_all_schemes() {
    let (mut c, root) = config("healthy");
    c.phase = "password_update".into();
    let (folder, rows, summary) = run(&c, &root, "local-smoke");
    let measured: Vec<_> = rows.iter().filter(|r| !r.fixture && !r.warmup).collect();
    assert_eq!(measured.len(), 3);
    for row in measured {
        assert_eq!(
            row.result.outcome, "completed",
            "{}: {:?}",
            row.result.scheme, row.result.reason
        );
        assert!(row.result.metrics.sent_bytes > 0 && row.result.metrics.sent_messages > 0);
        assert!(
            row.provider_handler_ns > 0,
            "missing actual endpoint processing measurement"
        );
        assert!(row.process_wall_ns >= row.result.metrics.end_to_end_ns);
    }
    for group in summary.as_object().unwrap().values() {
        assert_eq!(group["attempts"], 1);
        assert_eq!(group["outcomes"]["completed"], 1);
    }
    eprintln!("healthy harness raw evidence: {}", folder.display());
}

#[test]
fn suppressed_terminal_is_unresolved_and_in_denominator() {
    let (mut c, root) = config("terminal-suppression");
    c.schemes = vec!["roupspa".into()];
    c.phase = "registration".into();
    c.faults = vec![Fault {
        role: "login".into(),
        provider_id: 1,
        action: "suppress".into(),
        stage: "ls_store".into(),
    }];
    let (folder, rows, summary) = run(&c, &root, "local-fault");
    let measured: Vec<_> = rows.iter().filter(|r| !r.fixture && !r.warmup).collect();
    assert_eq!(measured.len(), 1);
    let row = measured[0];
    assert_eq!(row.result.outcome, "unresolved");
    assert_eq!(row.result.terminal_processing_observed, Some(false));
    assert!(row
        .result
        .reason
        .as_deref()
        .unwrap()
        .contains("terminal processing"));
    assert!(row.result.metrics.terminal_ns >= c.delta_ms * 1_000_000);
    let summary = summary.as_object().unwrap().values().next().unwrap();
    assert_eq!(summary["attempts"], 1);
    assert_eq!(summary["outcomes"]["unresolved"], 1);
    assert!(summary["completed_p50_ns"].is_null());
    let endpoint = folder
        .join(&c.state_dir)
        .join(&row.run_id)
        .join("login/endpoint.jsonl");
    let records = fs::read_to_string(endpoint).unwrap();
    assert!(records
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|v| v["stage"] == "ls_store" && v["suppressed"] == true));
    eprintln!("terminal suppression raw evidence: {}", folder.display());
}
