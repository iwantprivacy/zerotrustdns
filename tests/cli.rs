use std::process::Command;

#[test]
fn unknown_cli_arguments_fail_without_cloudflare_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_zerotrustdns"))
        .current_dir("/")
        .env_clear()
        .arg("--unsupported")
        .output()
        .expect("binary should start");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown option: --unsupported"));
}
