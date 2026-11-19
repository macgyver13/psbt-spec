//! The adapter subprocess (docs/adapter.md): JSON lines over stdio, one
//! response per request, a timeout, and a restart after a failure.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

pub const PROTOCOL: &str = "psbt-spec.adapter/1";
pub const TASKS: [&str; 5] = ["deserialize", "sign", "finalize", "extract", "combine"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub project: [String; 3],
    pub adapter: [String; 2],
    pub tasks: Vec<String>,
    pub bips: Vec<u64>,
}

#[derive(Debug)]
pub enum Reply {
    Accept { psbt: Option<Vec<u8>> },
    Reject { rule: Option<String> },
    NotApplicable,
    AdapterError,
}

#[derive(Debug)]
pub struct Answer {
    pub reply: Reply,
    pub reason: Option<String>,
}

/// Why a request got no usable answer (the report's error kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Timeout,
    Crashed,
    Protocol,
}

impl Failure {
    pub fn name(self) -> &'static str {
        match self {
            Failure::Timeout => "timeout",
            Failure::Crashed => "crashed",
            Failure::Protocol => "protocol",
        }
    }
}

pub struct Adapter {
    argv: Vec<String>,
    timeout: Duration,
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

fn spawn(argv: &[String]) -> Result<(Child, ChildStdin, Receiver<String>), String> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cannot start adapter {}: {e}", argv[0]))?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    Ok((child, stdin, rx))
}

fn valid_rule_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    let upper = |s: &str, digits: bool| !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase() || (digits && c.is_ascii_digit()));
    parts.len() >= 2
        && upper(parts[0], false)
        && parts[1..parts.len() - 1].iter().all(|p| upper(p, true))
        && parts.last().is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

fn text(v: &Value, key: &str) -> Result<String, String> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned).ok_or_else(|| format!("{key} must be a non-empty string"))
}

/// Checks a hello response line against the schema.
pub fn parse_hello(line: &str) -> Result<Hello, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("hello is not JSON: {e}"))?;
    if v.get("id") != Some(&json!(0)) {
        return Err("hello must echo id 0".into());
    }
    if v.get("protocol").and_then(Value::as_str) != Some(PROTOCOL) {
        return Err(format!("adapter does not speak {PROTOCOL}"));
    }
    let named = |key: &str| -> Result<(String, String, Option<String>), String> {
        let o = v.get(key).ok_or(format!("{key} is required"))?;
        Ok((text(o, "name")?, text(o, "version")?, o.get("revision").map(|_| text(o, "revision")).transpose()?))
    };
    let (pn, pv, pr) = named("project")?;
    let (an, av, _) = named("adapter")?;
    let tasks: Vec<String> = v.get("tasks").and_then(Value::as_array).ok_or("tasks is required")?
        .iter().map(|t| t.as_str().filter(|t| TASKS.contains(t)).map(str::to_owned).ok_or("unknown task in tasks")).collect::<Result<_, _>>()?;
    let bips: Vec<u64> = v.get("bips").and_then(Value::as_array).ok_or("bips is required")?
        .iter().map(|b| b.as_u64().filter(|&b| b >= 1).ok_or("bips must be positive integers")).collect::<Result<_, _>>()?;
    if tasks.is_empty() || bips.is_empty() {
        return Err("tasks and bips must not be empty".into());
    }
    Ok(Hello { project: [pn, pv, pr.ok_or("project.revision is required")?], adapter: [an, av], tasks, bips })
}

/// Checks a response line against the schema and the task.
fn parse_reply(line: &str, id: u64, task: &str) -> Result<Answer, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("response is not JSON: {e}"))?;
    if v.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(format!("response id is not {id}"));
    }
    let reason = match v.get("reason") {
        None => None,
        Some(r) => Some(r.as_str().ok_or("reason must be a string")?.to_owned()),
    };
    let verdict = v.get("verdict").and_then(Value::as_str).ok_or("verdict is required")?;
    let has = |key: &str| v.get(key).is_some();
    let reply = match verdict {
        "accept" => {
            if has("rule") {
                return Err("rule is for reject only".into());
            }
            let psbt = match v.get("psbt") {
                None => None,
                Some(p) => Some(STANDARD.decode(p.as_str().ok_or("psbt must be a string")?).map_err(|e| format!("psbt is not base64: {e}"))?),
            };
            if psbt.is_none() && matches!(task, "finalize" | "combine") {
                return Err(format!("accept for {task} needs psbt"));
            }
            Reply::Accept { psbt }
        }
        "reject" => {
            if has("psbt") {
                return Err("psbt is for accept only".into());
            }
            let rule = match v.get("rule") {
                None => None,
                Some(r) => Some(r.as_str().filter(|r| valid_rule_id(r)).ok_or("rule is not a rule ID")?.to_owned()),
            };
            Reply::Reject { rule }
        }
        "n/a" | "error" => {
            if has("rule") || has("psbt") {
                return Err(format!("{verdict} carries neither rule nor psbt"));
            }
            if reason.is_none() {
                return Err(format!("{verdict} needs a reason"));
            }
            if verdict == "n/a" { Reply::NotApplicable } else { Reply::AdapterError }
        }
        other => return Err(format!("unknown verdict {other}")),
    };
    Ok(Answer { reply, reason })
}

impl Adapter {
    /// Starts the adapter and runs the hello.
    pub fn start(argv: &[String], timeout: Duration) -> Result<(Adapter, Hello), String> {
        let (child, stdin, lines) = spawn(argv)?;
        let mut adapter = Adapter { argv: argv.to_vec(), timeout, child, stdin: Some(stdin), lines };
        let hello = adapter.hello()?;
        Ok((adapter, hello))
    }

    fn send(&mut self, request: &Value) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("adapter stdin is closed")?;
        writeln!(stdin, "{request}").and_then(|_| stdin.flush()).map_err(|e| format!("cannot write to adapter: {e}"))
    }

    fn hello(&mut self) -> Result<Hello, String> {
        self.send(&json!({"id": 0, "task": "hello", "protocol": PROTOCOL}))?;
        let line = self.lines.recv_timeout(self.timeout).map_err(|e| match e {
            RecvTimeoutError::Timeout => "adapter did not answer hello in time".to_owned(),
            RecvTimeoutError::Disconnected => "adapter exited before answering hello".to_owned(),
        })?;
        parse_hello(&line)
    }

    fn kill(&mut self) {
        self.stdin = None;
        // The adapter leads its own process group; take the whole group down.
        let _ = Command::new("kill").arg("-KILL").arg(format!("-{}", self.child.id())).stderr(Stdio::null()).status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Kills the process group, starts the adapter again and repeats the hello.
    pub fn restart(&mut self) -> Result<Hello, String> {
        self.kill();
        let (child, stdin, lines) = spawn(&self.argv)?;
        self.child = child;
        self.stdin = Some(stdin);
        self.lines = lines;
        self.hello()
    }

    /// Sends one request and waits for its response. On a failure the reason
    /// says why; the caller restarts the adapter.
    pub fn ask(&mut self, request: &Value) -> Result<Answer, (Failure, String)> {
        let id = request["id"].as_u64().unwrap();
        let task = request["task"].as_str().unwrap().to_owned();
        if self.send(request).is_err() {
            return Err((Failure::Crashed, self.exit_reason()));
        }
        match self.lines.recv_timeout(self.timeout) {
            Ok(line) => parse_reply(&line, id, &task).map_err(|e| (Failure::Protocol, e)),
            Err(RecvTimeoutError::Timeout) => Err((Failure::Timeout, format!("no response within {} s", self.timeout.as_secs()))),
            Err(RecvTimeoutError::Disconnected) => Err((Failure::Crashed, self.exit_reason())),
        }
    }

    fn exit_reason(&mut self) -> String {
        std::thread::sleep(Duration::from_millis(50));
        match self.child.try_wait() {
            Ok(Some(status)) => match status.code() {
                Some(code) => format!("adapter exited with status {code}"),
                None => format!("adapter was killed ({status})"),
            },
            _ => "adapter closed stdout".to_owned(),
        }
    }

    /// Closes stdin; after 5 seconds the adapter is killed.
    pub fn finish(mut self) {
        self.stdin = None;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.kill();
    }
}
