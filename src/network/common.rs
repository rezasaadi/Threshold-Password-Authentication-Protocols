use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    borrow::Borrow,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, String>;
pub fn ns(t: Instant) -> u64 {
    t.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub bandwidth_mbps: f64,
    pub loss_percent: f64,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "smoke".into(),
            delay_ms: 0.25,
            jitter_ms: 0.0,
            bandwidth_mbps: 100.0,
            loss_percent: 0.0,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fault {
    pub role: String,
    pub provider_id: usize,
    pub action: String,
    pub stage: String,
}
impl Default for Fault {
    fn default() -> Self {
        Self {
            role: "provider".into(),
            provider_id: 1,
            action: "suppress".into(),
            stage: "".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub n_sp: usize,
    pub t_sp: usize,
    pub q_sp: usize,
    pub phase: String,
    pub schemes: Vec<String>,
    pub providers: Vec<String>,
    pub login_server: String,
    pub profiles: Vec<Profile>,
    pub loss_levels: Vec<f64>,
    pub delta_ms: u64,
    pub timeout_ms: u64,
    pub retry_ms: u64,
    pub warmups: usize,
    pub samples: usize,
    pub repetitions: usize,
    pub connection_policy: String,
    pub state_dir: PathBuf,
    pub output_dir: PathBuf,
    pub faults: Vec<Fault>,
    /// RoUpSPA provider fan-out: "all" contacts every provider and uses the
    /// first replies; "minimal" contacts only as many providers as a stage
    /// needs and widens only on failure (the baselines always contact exactly
    /// the providers they need).
    pub fanout: String,
    /// RoUpSPA read size: "quorum" waits for r = n - q + t replies (paper);
    /// "threshold" waits for t (legacy reads, ablation only).
    pub read_policy: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            n_sp: 4,
            t_sp: 2,
            q_sp: 3,
            phase: "authentication".into(),
            schemes: vec!["roupspa".into(), "pastau".into(), "augsso".into()],
            providers: (1..=4).map(|i| format!("127.0.0.1:{}", 19000 + i)).collect(),
            login_server: "127.0.0.1:19100".into(),
            profiles: vec![Profile::default()],
            loss_levels: vec![0.0],
            delta_ms: 20,
            timeout_ms: 1000,
            retry_ms: 5,
            warmups: 1,
            samples: 2,
            repetitions: 1,
            connection_policy: "fresh_per_request".into(),
            state_dir: "network-state".into(),
            output_dir: "network-results".into(),
            faults: vec![],
            fanout: "all".into(),
            read_policy: "quorum".into(),
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        if self.t_sp == 0 || self.t_sp > self.q_sp || self.q_sp > self.n_sp {
            return Err("require 1 <= t_sp <= q_sp <= n_sp".into());
        }
        if self.q_sp <= self.n_sp.saturating_sub(self.q_sp).saturating_add(self.t_sp - 1) {
            return Err("require 2*q_sp - n_sp > t_sp - 1 (strict quorum intersection)".into());
        }
        if self.providers.len() != self.n_sp {
            return Err("providers length must equal n_sp".into());
        }
        let mut addresses = std::collections::HashSet::new();
        for a in self.providers.iter().chain(std::iter::once(&self.login_server)) {
            a.parse::<std::net::SocketAddr>()
                .map_err(|_| format!("invalid socket address: {a}"))?;
            if !addresses.insert(a) {
                return Err(format!("duplicate endpoint {a}"));
            }
        }
        if ![
            "setup",
            "registration",
            "authentication",
            "password_update",
            "secret_update",
            "synchronization",
        ]
        .contains(&self.phase.as_str())
        {
            return Err("unknown phase".into());
        }
        if self.schemes.is_empty()
            || self
                .schemes
                .iter()
                .any(|s| !["roupspa", "pastau", "augsso"].contains(&s.as_str()))
        {
            return Err("schemes must contain roupspa/pastau/augsso".into());
        }
        // "setup" is common to all schemes: RoUpSPA Setup (TOPRF shares and the
        // identification record to all n providers) corresponds to the baseline
        // registration (per-server key material to all n servers).
        if self.schemes.iter().any(|s| s != "roupspa")
            && ["secret_update", "synchronization"].contains(&self.phase.as_str())
        {
            return Err("secret_update/synchronization must select only roupspa".into());
        }
        if !["all", "minimal"].contains(&self.fanout.as_str()) {
            return Err("fanout must be all or minimal".into());
        }
        if !["quorum", "threshold"].contains(&self.read_policy.as_str()) {
            return Err("read_policy must be quorum or threshold".into());
        }
        if self.samples == 0
            || self.repetitions == 0
            || self.timeout_ms == 0
            || self.delta_ms == 0
            || self.retry_ms == 0
        {
            return Err("samples, repetitions, timeouts, Delta, retry must be positive".into());
        }
        if self.connection_policy != "fresh_per_request" {
            return Err("supported connection_policy is fresh_per_request".into());
        }
        if self.profiles.is_empty() || self.loss_levels.is_empty() {
            return Err("provide at least one profile and loss level".into());
        }
        for p in &self.profiles {
            if p.name.is_empty()
                || !p.delay_ms.is_finite()
                || p.delay_ms < 0.0
                || !p.jitter_ms.is_finite()
                || p.jitter_ms < 0.0
                || !p.bandwidth_mbps.is_finite()
                || p.bandwidth_mbps <= 0.0
                || !p.loss_percent.is_finite()
                || !(0.0..=100.0).contains(&p.loss_percent)
            {
                return Err("invalid profile delay/jitter/bandwidth/loss".into());
            }
        }
        if self
            .loss_levels
            .iter()
            .any(|x| !x.is_finite() || !(0.0..=100.0).contains(x))
        {
            return Err("loss_levels must be 0..100 percent".into());
        }
        for f in &self.faults {
            if !["provider", "login", "client"].contains(&f.role.as_str())
                || ![
                    "suppress",
                    "crash_before",
                    "crash_after",
                    "stop",
                    "restart",
                    "corrupt_partial",
                ]
                .contains(&f.action.as_str())
                || f.provider_id > self.n_sp
                || (f.role == "provider" && f.provider_id == 0)
            {
                return Err("invalid fault role/action/provider_id".into());
            }
            if f.action == "corrupt_partial" && f.role != "provider" {
                return Err("corrupt_partial applies to providers only".into());
            }
            if f.role == "client" && !["crash_before", "crash_after"].contains(&f.action.as_str()) {
                return Err(
                    "client faults support crash_before/crash_after followed by automatic restart/resume"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransportEvent {
    pub endpoint: String,
    pub direction: String,
    pub bytes: u64,
    pub elapsed_ns: u64,
    pub timestamp_unix_ns: u64,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub sent_messages: u64,
    pub received_messages: u64,
    pub send_ns: u64,
    pub receive_ns: u64,
    pub handler_ns: u64,
    pub quorum_ns: u64,
    pub terminal_ns: u64,
    pub retries: u64,
    pub timeouts: u64,
    pub client_ns: u64,
    pub end_to_end_ns: u64,
    pub repair_ns: u64,
    #[serde(default)]
    pub terminal_handler_ns: u64,
    /// Client time spent draining outstanding concurrent requests after the
    /// operation decided (stragglers beyond the required replies). Included in
    /// end_to_end_ns; reported separately so latency can be shown without it.
    #[serde(default)]
    pub drain_ns: u64,
    /// Largest number of provider replies a read stage waited for (r or t).
    #[serde(default)]
    pub read_replies_required: u64,
    /// TOPRF t-subsets combined before an identification candidate opened.
    #[serde(default)]
    pub toprf_subsets_tried: u64,
    /// Batch consistency checks on new-password TOPRF contributions.
    #[serde(default)]
    pub toprf_consistency_checks: u64,
    /// Client time for TOPRF combination, subset retries and consistency checks.
    #[serde(default)]
    pub toprf_combine_ns: u64,
    /// Distinct identification candidates returned by a read.
    #[serde(default)]
    pub id_candidates: u64,
    /// Password Update tentative tuples resolved by Discard.
    #[serde(default)]
    pub discards: u64,
    /// Providers a Discard could not be delivered to within Delta.
    #[serde(default)]
    pub discard_undelivered: u64,
    /// Stages that needed a second wave under fanout = "minimal".
    #[serde(default)]
    pub fanout_extensions: u64,
    pub events: Vec<TransportEvent>,
}
impl Metrics {
    pub fn merge<T: Borrow<Self>>(&mut self, other: T) {
        let o = other.borrow();
        macro_rules! sum {($($f:ident),*)=>{$(self.$f=self.$f.saturating_add(o.$f);)*};}
        sum!(
            sent_bytes,
            received_bytes,
            sent_messages,
            received_messages,
            send_ns,
            receive_ns,
            handler_ns,
            quorum_ns,
            terminal_ns,
            retries,
            timeouts,
            client_ns,
            end_to_end_ns,
            repair_ns,
            terminal_handler_ns,
            drain_ns,
            toprf_subsets_tried,
            toprf_consistency_checks,
            toprf_combine_ns,
            id_candidates,
            discards,
            discard_undelivered,
            fanout_extensions
        );
        self.read_replies_required = self.read_replies_required.max(o.read_replies_required);
        self.events.extend(o.events.clone());
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunResult {
    pub scheme: String,
    pub phase: String,
    pub session: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub metrics: Metrics,
    #[serde(default)]
    pub terminal_processing_observed: Option<bool>,
    #[serde(default)]
    pub client_measurement_unavailable: bool,
    #[serde(default)]
    pub measurement_source: String,
}
impl RunResult {
    pub fn new(scheme: &str, phase: &str, session: &str) -> Self {
        Self {
            scheme: scheme.into(),
            phase: phase.into(),
            session: session.into(),
            outcome: "unresolved".into(),
            reason: None,
            metrics: Metrics::default(),
            terminal_processing_observed: None,
            client_measurement_unavailable: false,
            measurement_source: "client sockets and independent endpoint handlers".into(),
        }
    }
}

// fsync the temporary file, replace, and fsync the directory on Linux. The
// caller must not send a durable acknowledgement before this returns.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    drop(f);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let source: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // REPLACE_EXISTING | WRITE_THROUGH; never delete the previous state first.
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    #[cfg(not(windows))]
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if let Some(p) = path.parent() {
        File::open(p)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn append_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if let Some(p) = path.parent() {
        File::open(p)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
const MAX_FRAME: usize = 16 * 1024 * 1024;
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
fn counted_write(stream: &mut TcpStream, data: &[u8], address: &str, m: &mut Metrics) -> Result<()> {
    if data.len() > MAX_FRAME {
        return Err("frame exceeds limit".into());
    }
    let start = Instant::now();
    let framed = [&(data.len() as u32).to_be_bytes()[..], data].concat();
    let mut count = 0;
    let result: Result<()> = (|| {
        while count < framed.len() {
            let n = stream.write(&framed[count..]).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("zero-byte socket write".into());
            }
            count += n;
        }
        stream.flush().map_err(|e| e.to_string())
    })();
    m.sent_bytes += count as u64;
    if result.is_ok() {
        m.sent_messages += 1;
    }
    let elapsed = ns(start);
    m.send_ns += elapsed;
    m.events.push(TransportEvent {
        endpoint: address.into(),
        direction: "send".into(),
        bytes: count as u64,
        elapsed_ns: elapsed,
        timestamp_unix_ns: timestamp(),
        error: result.as_ref().err().cloned(),
    });
    result
}
fn counted_read(stream: &mut TcpStream, address: &str, m: &mut Metrics) -> Result<Vec<u8>> {
    let start = Instant::now();
    let mut count = 0u64;
    fn fill(s: &mut TcpStream, b: &mut [u8], count: &mut u64) -> Result<()> {
        let mut off = 0;
        while off < b.len() {
            let n = s.read(&mut b[off..]).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("socket closed during frame".into());
            }
            off += n;
            *count += n as u64;
        }
        Ok(())
    }
    let result = (|| {
        let mut header = [0; 4];
        fill(stream, &mut header, &mut count)?;
        let n = u32::from_be_bytes(header) as usize;
        if n > MAX_FRAME {
            return Err("frame exceeds limit".into());
        }
        let mut body = vec![0; n];
        fill(stream, &mut body, &mut count)?;
        Ok(body)
    })();
    m.received_bytes += count;
    if result.is_ok() {
        m.received_messages += 1;
    }
    let elapsed = ns(start);
    m.receive_ns += elapsed;
    m.events.push(TransportEvent {
        endpoint: address.into(),
        direction: "receive".into(),
        bytes: count,
        elapsed_ns: elapsed,
        timestamp_unix_ns: timestamp(),
        error: result.as_ref().err().cloned(),
    });
    result
}
fn connect(addr: &str, timeout_ms: u64) -> Result<TcpStream> {
    let address = addr
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("empty address")?;
    let stream =
        TcpStream::connect_timeout(&address, Duration::from_millis(timeout_ms)).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}
pub fn request(addr: &str, bytes: &[u8], timeout_ms: u64, metrics: &mut Metrics) -> Result<Value> {
    let result = (|| {
        let mut s = connect(addr, timeout_ms)?;
        counted_write(&mut s, bytes, addr, metrics)?;
        let response = counted_read(&mut s, addr, metrics)?;
        let v: Value = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
        metrics.handler_ns += v["handler_ns"].as_u64().unwrap_or(0);
        if let Some(e) = v["error"].as_str() {
            return Err(e.into());
        }
        Ok(v["body"].clone())
    })();
    if result
        .as_ref()
        .err()
        .is_some_and(|e: &String| e.contains("timed out") || e.contains("temporarily unavailable"))
    {
        metrics.timeouts += 1;
    }
    result
}
pub fn one_way(addr: &str, bytes: &[u8], timeout_ms: u64, metrics: &mut Metrics) -> Result<()> {
    let mut s = connect(addr, timeout_ms)?;
    counted_write(&mut s, bytes, addr, metrics)
}

// Endpoint handling is serial to keep transitions atomic. Each endpoint runs in
// its own process; concurrent stage requests execute at different providers.
pub fn serve(
    listen: &str,
    state: &Path,
    mut handler: impl FnMut(&Value) -> Result<(Value, bool)>,
) -> Result<()> {
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    atomic_write(&state.join("ready"), listen.as_bytes())?;
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let peer = stream.peer_addr().map(|x| x.to_string()).unwrap_or_default();
        let mut m = Metrics::default();
        let bytes = match counted_read(&mut stream, &peer, &mut m) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let stage = value
            .get("action")
            .or_else(|| value.get("kind"))
            .or_else(|| value.get("stage"))
            .or_else(|| value.get("op"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let suppression = std::env::var("BENCH_SUPPRESS_STAGE")
            .ok()
            .is_some_and(|v| v == stage || v == "*");
        if std::env::var("BENCH_CRASH_BEFORE_STAGE")
            .ok()
            .is_some_and(|v| v == stage || v == "*")
        {
            std::process::exit(72);
        }
        if suppression {
            append_durable(&state.join("endpoint.jsonl"),format!("{}\n",json!({"transport":true,"stage":stage,"session":value["session"],"suppressed":true,"metrics":m})).as_bytes())?;
            continue;
        }
        let start = Instant::now();
        let result = handler(&value);
        let elapsed = ns(start);
        let error = result.as_ref().err().cloned();
        if std::env::var("BENCH_CRASH_AFTER_STAGE")
            .ok()
            .is_some_and(|v| v == stage || v == "*")
        {
            std::process::exit(73);
        }
        let terminal = matches!(
            stage,
            "ls_store" | "ls_discard" | "id_store" | "id_discard" | "register" | "update"
        );
        match result {
            Ok((body, oneway)) => {
                if !oneway && !terminal {
                    let reply = serde_json::to_vec(&json!({"body":body,"handler_ns":elapsed}))
                        .map_err(|e| e.to_string())?;
                    let _ = counted_write(&mut stream, &reply, &peer, &mut m);
                }
            }
            Err(e) => {
                if !terminal {
                    let reply = serde_json::to_vec(&json!({"error":e,"handler_ns":elapsed}))
                        .map_err(|e| e.to_string())?;
                    let _ = counted_write(&mut stream, &reply, &peer, &mut m);
                }
            }
        }
        append_durable(&state.join("endpoint.jsonl"),format!("{}\n",json!({"transport":true,"stage":stage,"session":value["session"],"handler_ns":elapsed,"processed":error.is_none(),"error":error,"metrics":m,"timestamp_unix_ns":timestamp()})).as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intersection_boundary() {
        let mut c = Config::default();
        c.n_sp = 7;
        c.t_sp = 2;
        c.q_sp = 4;
        c.providers = (1..=7).map(|i| format!("127.0.0.1:{}", 19000 + i)).collect();
        assert!(c.validate().is_err());
        c.q_sp = 5;
        assert!(c.validate().is_ok());
        c.t_sp = 0;
        assert!(c.validate().is_err());
    }
    #[test]
    fn malformed_network_is_rejected() {
        let mut c = Config::default();
        c.profiles[0].loss_percent = 101.0;
        assert!(c.validate().is_err());
        c.profiles[0].loss_percent = 0.0;
        c.providers[1] = c.providers[0].clone();
        assert!(c.validate().is_err());
    }
}
