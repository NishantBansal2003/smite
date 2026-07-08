//! Thin wrapper around the tmux CLI for managing campaign sessions.

use std::io;
use std::process::{Command, Stdio};

/// Returns `true` if `tmux` is installed and runnable.
pub fn is_available() -> bool {
    Command::new("tmux")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Returns `true` if a tmux session with the given exact name exists.
pub fn session_exists(name: &str) -> bool {
    let target = format!("={name}");
    Command::new("tmux")
        .args(["has-session", "-t", &target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Creates a new detached tmux session with one window running `shell_cmd`.
///
/// Sets `remain-on-exit` atomically so dead windows preserve error output
/// even if the command exits immediately.
pub fn create_session(name: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    run_tmux(&[
        "new-session",
        "-d",
        "-s",
        name,
        "-n",
        window_name,
        shell_cmd,
        ";",
        "set-option",
        "-t",
        name,
        "remain-on-exit",
        "on",
    ])
}

/// Adds a new window running `shell_cmd` to an existing tmux session.
///
/// Sets `remain-on-exit` on the new window because session-level
/// `remain-on-exit` does not propagate to windows created after the fact.
pub fn add_window(session: &str, window_name: &str, shell_cmd: &str) -> io::Result<()> {
    let target = format!("={session}");
    run_tmux(&[
        "new-window",
        "-t",
        &target,
        "-n",
        window_name,
        shell_cmd,
        ";",
        "set-option",
        "-w",
        "remain-on-exit",
        "on",
    ])
}

/// Returns the names of windows in `session` whose command has exited.
///
/// Used during startup verification to tell a runner that failed to launch
/// (its pane is dead) apart from one still calibrating (pane alive). Relies on
/// `remain-on-exit`, which keeps dead windows queryable instead of destroying
/// them. Window names are assumed free of spaces (they are `runner-<id>`).
pub fn dead_windows(session: &str) -> io::Result<Vec<String>> {
    let target = format!("={session}");
    let output = Command::new("tmux")
        .args([
            "list-panes",
            "-s",
            "-t",
            &target,
            "-F",
            "#{pane_dead} #{window_name}",
        ])
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tmux list-panes failed for session {session}: {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("1 "))
        .map(str::to_owned)
        .collect())
}

/// Attaches to a session, using `switch-client` when already inside tmux.
pub fn attach(session: &str) -> io::Result<()> {
    let target = format!("={session}");
    let cmd = if std::env::var_os("TMUX").is_some() {
        "switch-client"
    } else {
        "attach-session"
    };
    run_tmux(&[cmd, "-t", &target])
}

fn run_tmux(args: &[&str]) -> io::Result<()> {
    let status = Command::new("tmux").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tmux {} failed: {status}",
            args[0]
        )))
    }
}
