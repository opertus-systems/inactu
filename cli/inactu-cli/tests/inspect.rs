mod common;

use common::vectors_root;
use std::process::Command;

#[test]
fn inspect_outputs_deterministic_fields() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let output = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["inspect", "--bundle"])
        .arg(&bundle)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let expected = [
        "name=echo.minimal",
        "version=0.1.0",
        "entrypoint=run",
        "manifest_artifact=sha256:93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476",
        "signatures_artifact=sha256:93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476",
        "signatures_manifest_hash=sha256:5608b234a450b93faa080969141fb123a69abd2e5563d0e21d47fc03862856a2",
        "capabilities=0",
        "signers=1",
        "signer[0]=alice.dev",
        "signature_count=1",
        "signature_signer[0]=alice.dev",
    ]
    .join("\n")
        + "\n";

    assert_eq!(stdout, expected);
}

#[test]
fn inspect_succeeds_for_non_verifying_bundle() {
    let root = vectors_root();
    let bundle = root.join("bad/hash-mismatch");
    let output = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["inspect", "--bundle"])
        .arg(&bundle)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);
}
