use std::{path::Path, process::Command};

// Get the afl coverage map size of the given binary
fn get_map_size(binary: &Path) -> Option<String> {
    let output = String::from_utf8_lossy(
        &Command::new(binary)
            .env("AFL_DUMP_MAP_SIZE", "1")
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute {}", binary.display()))
            .stdout,
    )
    .trim()
    .to_string();

    (!output.is_empty()).then_some(output)
}

fn main() {
    // Build static library for Rust FFI
    let mut build = cc::Build::new();
    build.file("src/nyx-agent.c").define("NO_PT_NYX", None);

    let map_size = std::env::var("TARGET_PATH")
        .ok()
        .and_then(|path| get_map_size(Path::new(&path)));

    if let Some(ref size) = map_size {
        build.define("TARGET_MAP_SIZE", size.as_str());
    }

    build.compile("nyx_agent");

    // Build shared library for Go CGO bindings
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let profile = std::env::var("PROFILE").unwrap();

    // Find the target directory (e.g., target/release or target/debug)
    let out_path = Path::new(&out_dir);
    let target_dir = out_path
        .ancestors()
        .find(|p| p.ends_with(&profile))
        .expect("Failed to find target profile directory");

    let so_path = target_dir.join("libnyx_agent.so");

    // Build the shared library with gcc
    let mut gcc_cmd = Command::new("gcc");
    gcc_cmd
        .arg("-shared")
        .arg("-fPIC")
        .arg("-DNO_PT_NYX")
        .arg("src/nyx-agent.c")
        .arg("-o")
        .arg(&so_path);

    if let Some(ref size) = map_size {
        gcc_cmd.arg(format!("-DTARGET_MAP_SIZE={size}"));
    }

    let output = gcc_cmd
        .output()
        .expect("Failed to execute gcc for shared library");

    assert!(
        output.status.success(),
        "Failed to build shared library:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    println!("cargo:rerun-if-changed=src/nyx-agent.c");
    println!("cargo:rerun-if-env-changed=TARGET_PATH");
}
