//! CLI-level regression tests: the compressed-input limit must be identical for
//! a named file and for standard input, and the growth of the CLI's own surface
//! (argument handling, exit statuses) stays observable.
use std::io::Write;
use std::process::{Command, Stdio};

const INPUT_LIMIT_MEMBER: &[u8] = include_bytes!("fixtures/input_limit.gz");

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sifr-inflate")
}

fn write_fixture(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("sifr-inflate-{}-{name}", std::process::id()));
    std::fs::write(&path, INPUT_LIMIT_MEMBER).unwrap();
    path
}

fn run_stdin(limit: &str) -> std::process::Output {
    let mut child = Command::new(binary())
        .args(["--max-input", limit, "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(INPUT_LIMIT_MEMBER)
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn compressed_input_limit_matches_for_file_and_stdin() {
    let path = write_fixture("limits");
    let size = INPUT_LIMIT_MEMBER.len().to_string();
    let under = (INPUT_LIMIT_MEMBER.len() - 1).to_string();

    // Exactly at the limit: both paths decode.
    let file = Command::new(binary())
        .args(["--max-input", &size])
        .arg(&path)
        .output()
        .unwrap();
    let stdin = run_stdin(&size);
    assert_eq!(file.status.code(), Some(0), "{:?}", file.stderr);
    assert_eq!(stdin.status.code(), Some(0), "{:?}", stdin.stderr);
    assert_eq!(file.stdout.len(), 4096);
    assert_eq!(file.stdout, stdin.stdout);

    // One byte under: both paths refuse with the same message and no output.
    let file = Command::new(binary())
        .args(["--max-input", &under])
        .arg(&path)
        .output()
        .unwrap();
    let stdin = run_stdin(&under);
    let expected = format!("compressed input exceeds limit of {under} bytes");
    assert_eq!(file.status.code(), Some(1));
    assert_eq!(stdin.status.code(), Some(1));
    assert!(file.stdout.is_empty() && stdin.stdout.is_empty());
    assert!(file
        .stderr
        .windows(expected.len())
        .any(|w| w == expected.as_bytes()));
    assert_eq!(file.stderr, stdin.stderr);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn unreadable_input_exits_with_io_status() {
    let output = Command::new(binary())
        .arg("/nonexistent/sifr-inflate/member.gz")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    // A directory is an I/O-level rejection, not a format error.
    let output = Command::new(binary())
        .arg(std::env::temp_dir())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    let output = Command::new(binary()).arg("--max-input").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn help_advertises_both_limits() {
    let output = Command::new(binary()).arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("--max-output"), "{text}");
    assert!(text.contains("--max-input"), "{text}");
}
