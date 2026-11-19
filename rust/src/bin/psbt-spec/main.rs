//! psbt-spec: evaluate a project's PSBT behavior against the rulebook.
//!
//!   psbt-spec evaluate --out DIR [--timeout SECONDS] --corpus FILE [--corpus FILE ...] -- ADAPTER [ARGS ...]
//!   psbt-spec vectors FILE [FILE ...]
//!   psbt-spec attribute        (JSON lines on stdin, see docs/attribute.md)

mod adapter;
mod evaluate;
mod markdown;
mod pins;
mod vectors;

use std::io::{BufRead, Write};
use std::time::Duration;

use psbt_spec::attribution::{attribute, parse_request};
use serde_json::{json, Value};

const ATTRIBUTE_PROTOCOL: &str = "psbt-spec.attribute/1";

/// One result line for one request line.
fn attribute_line(line: &str, pins: &Result<pins::Pins, String>) -> Value {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return json!({"error": format!("not JSON: {e}")}),
    };
    let tag = |mut v: Value| {
        if let Some(id) = request.get("id").filter(|id| id.is_string() || id.is_i64() || id.is_u64()) {
            v["id"] = id.clone();
        }
        v
    };
    if request.get("task").and_then(Value::as_str) == Some("hello") {
        return tag(match pins {
            Ok(p) => json!({"protocol": ATTRIBUTE_PROTOCOL, "spec": {"revision": p.revision, "dirty": p.dirty, "status": p.status}}),
            Err(e) => json!({"error": format!("cannot determine the psbt-spec revision: {e}")}),
        });
    }
    tag(match parse_request(&request) {
        Ok((task, req)) => {
            let failures = attribute(task, &req);
            json!({"failed": failures.failed, "incomplete": failures.incomplete})
        }
        Err(e) => json!({"error": e}),
    })
}

fn attribute_command() -> i32 {
    let pins = pins::read();
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let _ = writeln!(out, "{}", attribute_line(&line, &pins));
        let _ = out.flush();
    }
    0
}

fn usage() -> i32 {
    eprintln!("usage: psbt-spec evaluate --out DIR [--timeout SECONDS] --corpus FILE [--corpus FILE ...] -- ADAPTER [ARGS ...]");
    eprintln!("       psbt-spec vectors FILE [FILE ...]");
    eprintln!("       psbt-spec attribute");
    2
}

fn evaluate_command(args: &[String]) -> Result<(), String> {
    let (mut out, mut timeout, mut corpora) = (None, 180u64, Vec::new());
    let mut it = args.iter();
    let mut adapter: Vec<String> = Vec::new();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--out" => out = Some(value("--out")?),
            "--timeout" => timeout = value("--timeout")?.parse().map_err(|_| "--timeout needs a number of seconds".to_owned())?,
            "--corpus" => corpora.push(value("--corpus")?),
            "--" => {
                adapter = it.by_ref().cloned().collect();
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let out = out.ok_or("--out is required")?;
    if corpora.is_empty() || adapter.is_empty() {
        return Err("--corpus and an adapter after -- are required".into());
    }
    let corpora = corpora.iter().map(|path| evaluate::load(path)).collect::<Result<Vec<_>, _>>()?;
    let pins = pins::read()?;
    let report = evaluate::run(&corpora, &adapter, Duration::from_secs(timeout), &pins)?;
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {out}: {e}"))?;
    let write = |name: &str, text: String| std::fs::write(format!("{out}/{name}"), text).map_err(|e| format!("cannot write {out}/{name}: {e}"));
    write("report.json", serde_json::to_string_pretty(&report).unwrap() + "\n")?;
    write("report.md", markdown::render(&report))?;
    eprintln!("wrote {out}/report.json and {out}/report.md");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("attribute") if args.len() == 1 => attribute_command(),
        Some("vectors") if args.len() > 1 => vectors::run(&args[1..]),
        Some("evaluate") => match evaluate_command(&args[1..]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("psbt-spec evaluate: {e}");
                2
            }
        },
        _ => usage(),
    };
    std::process::exit(code);
}
