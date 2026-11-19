//! What a report or attribution records about psbt-spec itself (principle 24).

use std::process::Command;

use bitcoin_hashes::{sha256, Hash};

pub struct Pins {
    pub revision: String,
    /// Tracked files differ from the revision.
    pub dirty: bool,
    pub status: String,
}

fn git(args: &[&str]) -> Result<String, String> {
    let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let out = Command::new("git").arg("-C").arg(repo).args(args).output().map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn read() -> Result<Pins, String> {
    Ok(Pins {
        revision: git(&["rev-parse", "HEAD"])?,
        dirty: !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        status: psbt_spec::spec::specification().status.to_owned(),
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_byte_array().iter().map(|b| format!("{b:02x}")).collect()
}
