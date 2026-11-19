//! `psbt-spec attribute` reproduces the responses of
//! docs/examples/attribute-session.jsonl for its requests.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

fn session() -> Vec<(String, Value)> {
    let path = format!("{}/../docs/examples/attribute-session.jsonl", env!("CARGO_MANIFEST_DIR"));
    let lines: Vec<String> = std::fs::read_to_string(path).unwrap().lines().map(str::to_owned).collect();
    lines.chunks(2).map(|pair| (pair[0].clone(), serde_json::from_str(&pair[1]).unwrap())).collect()
}

#[test]
fn attribute_reproduces_the_example_session() {
    let session = session();
    let mut child = Command::new(env!("CARGO_BIN_EXE_psbt-spec"))
        .arg("attribute")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for (request, _) in &session {
        writeln!(stdin, "{request}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let responses: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(responses.len(), session.len());
    for ((request, expected), actual) in session.iter().zip(&responses) {
        if request.contains("\"hello\"") {
            // The example records the revision it was computed at; compare the shape.
            assert_eq!(actual["id"], expected["id"]);
            assert_eq!(actual["protocol"], expected["protocol"]);
            assert_eq!(actual["spec"]["status"], expected["spec"]["status"]);
            assert_eq!(actual["spec"]["revision"].as_str().unwrap().len(), 40);
            assert!(actual["spec"]["dirty"].is_boolean());
        } else {
            assert_eq!(actual, expected, "request {request:.80}");
        }
    }
}

#[test]
fn attribute_reports_errors_without_stopping() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_psbt-spec"))
        .arg("attribute")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "not json").unwrap();
    writeln!(stdin, r#"{{"id": "a", "task": "deserialize", "bips": [999], "psbt": ""}}"#).unwrap();
    writeln!(stdin, r#"{{"id": 3, "task": "deserialize", "bips": [174], "psbt": "", "returned": ""}}"#).unwrap();
    // Valid base64 that is not a PSBT fails GEN-F-1; it is not an error.
    writeln!(stdin, r#"{{"id": 4, "task": "deserialize", "bips": [174], "psbt": "AAAA"}}"#).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let lines: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(lines[0]["error"].as_str().unwrap().starts_with("not JSON"));
    assert_eq!((&lines[1]["id"], lines[1]["error"].as_str().unwrap()), (&Value::from("a"), "unknown BIP 999"));
    assert_eq!(lines[2]["error"], "returned is not allowed for deserialize");
    assert_eq!(lines[3]["failed"][0], "GEN-F-1");
}
